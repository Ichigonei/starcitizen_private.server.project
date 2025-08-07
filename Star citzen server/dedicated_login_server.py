#!/usr/bin/env python3
"""
Star Citizen Dedicated Login Server
Handles all authentication before the game starts.
The game will only check for existing authentication status.

This server:
1. Provides a web interface for user login
2. Authenticates credentials against a user database
3. Generates and stores JWT tokens in loginData.json
4. Provides an authentication verification endpoint for the game
"""

import json
import time
import os
import logging
import uuid
import base64
import hashlib
import struct
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import threading
import ssl

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('dedicated_login_server.log', encoding='utf-8'),
    ]
)

# Login Configuration Identifiers (from login_identifiers_categorized.csv)
class LoginConfig:
    """Login configuration constants and identifiers"""
    
    # Settings / Config Keys - Default Home Location (multiple naming conventions)
    CLIENT_LOGIN_DEFAULTHOMELOCATION = "Stanton_ArcCorp_Area18"  # UPPER_SNAKE_CASE
    client_login_defaulthomelocation = "Stanton_ArcCorp_Area18"  # kebab-case equivalent
    
    # Engine Configuration
    SEngineConfigLogin = {
        "default_home_location": "Stanton_ArcCorp_Area18",
        "login_timeout": 30,  # seconds
        "session_timeout": 86400,  # 24 hours
        "max_login_attempts": 3,
        "eos_integration": True
    }
    
    # Debug / Log Messages
    LOGIN_TIMEOUT_MESSAGE = "Login Timeout"
    
    # Epic Online Services (EOS) Integration
    EOS_CONNECT_NOTIFICATIONS = {
        "login_status_changed": "EOS_Connect_RemoveNotifyLoginStatusChanged",
        "enabled": True
    }
    
    # Configuration variants for different systems
    CONFIG_VARIANTS = {
        "dot_notation": "client.login.defaulthomelocation",
        "kebab_case": "client-login-defaulthomelocation", 
        "upper_snake": "CLIENT_LOGIN_DEFAULTHOMELOCATION",
        "pascal_case": "SEngineConfigLogin"
    }

class LoginServer:
    def __init__(self, port=9000):
        self.port = port
        self.base_path = r"G:\scdebugging\PTU\StarCitizenGameclient"
        self.logindata_path = os.path.join(self.base_path, "loginData.json")
        
        # Apply login configuration from CSV identifiers
        self.config = LoginConfig()
        self.login_timeout = self.config.SEngineConfigLogin["login_timeout"]
        self.session_timeout = self.config.SEngineConfigLogin["session_timeout"]
        self.max_login_attempts = self.config.SEngineConfigLogin["max_login_attempts"]
        self.default_home_location = self.config.CLIENT_LOGIN_DEFAULTHOMELOCATION
        self.eos_enabled = self.config.EOS_CONNECT_NOTIFICATIONS["enabled"]
        
        # Track login attempts for timeout handling
        self.login_attempts = {}
        
        # User database (in production, this would be a proper database)
        self.users_db = {
            'test.pilot@robertsspaceindustries.com': {
                'password_hash': self.hash_password('test_password_123'),
                'displayname': 'TestPilot',
                'nickname': 'TestPilot',
                'citizen_id': '2001462951',
                'account_id': '1000001',
                'active': True
            },
            'admin@robertsspaceindustries.com': {
                'password_hash': self.hash_password('admin_password'),
                'displayname': 'Administrator',
                'nickname': 'Admin',
                'citizen_id': '1000000001',
                'account_id': '1000001',
                'active': True
            }
        }
        
        # Store active sessions
        self.active_sessions = {}
        
    def hash_password(self, password):
        """Simple password hashing (use proper bcrypt in production)"""
        return hashlib.sha256((password + "star_citizen_salt").encode()).hexdigest()
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        return self.hash_password(password) == password_hash
    
    def generate_jwt_token(self, user_data):
        """Generate a realistic JWT token structure"""
        # JWT Header
        header = {
            "typ": "JWT",
            "alg": "RS256"
        }
        
        # JWT Payload
        iat = int(time.time())
        exp = iat + (24 * 60 * 60)  # Expires in 24 hours
        
        payload = {
            "iss": "https://robertsspaceindustries.com",
            "iat": iat,
            "exp": exp,
            "nbf": iat,
            "jti": f"rsi_jwt_{uuid.uuid4().hex[:16]}",
            "sub": f"game/SC/geid_{user_data['citizen_id']}_account_{user_data['account_id']}",
            "aud": ["rsi/game/bearer", "star-citizen"],
            "account_id": user_data['account_id'],
            "citizen_id": user_data['citizen_id'],
            "displayname": user_data['displayname'],
            "nickname": user_data['nickname'],
            "email": user_data['email'],
            "ipAddress": "127.0.0.1",
            "user_agent": "StarCitizen/4.1.149.3486",
            "game_version": "4.1.149.3486",
            "region": "us-east-1",
            "shard": "PU",
            "game_mode": "persistent_universe",
            "server_id": "server_001",
            "session_id": f"sess_{int(time.time() * 1000)}",
            "scope": ["game:access", "game:play", "game:chat", "game:files", "game:analytics"],
            "roles": ["citizen", "backer", "player"],
            "authenticated": True,
            "login_time": iat
        }
        
        # Encode JWT parts (base64url)
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Test signature (for testing only)
        signature = "LoginServerSignatureForStarCitizenAuthenticationSystemTestingPurposesThisEnsuresCompatibilityWithGameClientExpectationsForJWTTokenStructure"
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def authenticate_user(self, email, password, client_ip="127.0.0.1"):
        """Authenticate user credentials with enhanced login tracking"""
        # Check for too many failed attempts (login timeout handling)
        if self.is_login_timeout(client_ip):
            logging.warning(f"❌ {self.config.LOGIN_TIMEOUT_MESSAGE}: Too many failed attempts from {client_ip}")
            return None, "login_timeout"
        
        user = self.users_db.get(email)
        if not user:
            logging.warning(f"❌ Authentication failed: User not found - {email}")
            self.record_failed_attempt(client_ip)
            return None, "user_not_found"
            
        if not user['active']:
            logging.warning(f"❌ Authentication failed: Account disabled - {email}")
            self.record_failed_attempt(client_ip)
            return None, "account_disabled"
            
        if not self.verify_password(password, user['password_hash']):
            logging.warning(f"❌ Authentication failed: Invalid password - {email}")
            self.record_failed_attempt(client_ip)
            return None, "invalid_password"
            
        # Clear failed attempts on successful login
        if client_ip in self.login_attempts:
            del self.login_attempts[client_ip]
            
        logging.info(f"✅ Authentication successful - {email}")
        return user, "success"
    
    def is_login_timeout(self, client_ip):
        """Check if client is in login timeout due to failed attempts"""
        if client_ip not in self.login_attempts:
            return False
            
        attempts = self.login_attempts[client_ip]
        if attempts['count'] >= self.max_login_attempts:
            # Check if timeout period has passed
            if time.time() - attempts['last_attempt'] < self.login_timeout:
                return True
            else:
                # Reset attempts after timeout period
                del self.login_attempts[client_ip]
                return False
        return False
    
    def record_failed_attempt(self, client_ip):
        """Record a failed login attempt"""
        if client_ip not in self.login_attempts:
            self.login_attempts[client_ip] = {'count': 0, 'first_attempt': time.time()}
        
        self.login_attempts[client_ip]['count'] += 1
        self.login_attempts[client_ip]['last_attempt'] = time.time()
        
        logging.info(f"🔍 Failed login attempt {self.login_attempts[client_ip]['count']}/{self.max_login_attempts} from {client_ip}")
    
    def get_login_config_info(self):
        """Get configuration information for status display"""
        return {
            "default_home_location": self.default_home_location,
            "login_timeout": self.login_timeout,
            "session_timeout": self.session_timeout,
            "max_login_attempts": self.max_login_attempts,
            "eos_enabled": self.eos_enabled,
            "config_variants": self.config.CONFIG_VARIANTS,
            "eos_notifications": self.config.EOS_CONNECT_NOTIFICATIONS
        }
    
    def create_session(self, email, user_data):
        """Create authenticated session and login data"""
        session_id = f"sess_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        
        # Create user data with email
        user_with_email = user_data.copy()
        user_with_email['email'] = email
        
        # Generate JWT token
        jwt_token = self.generate_jwt_token(user_with_email)
        
        # Create comprehensive login data
        login_data = {
            "username": email,
            "email": email,
            "displayname": user_data['displayname'],
            "nickname": user_data['nickname'],
            "citizen_id": user_data['citizen_id'],
            "account_id": user_data['account_id'],
            "session_id": session_id,
            "token": f"rsi_token_{uuid.uuid4().hex}",
            "refresh_token": f"rsi_refresh_{uuid.uuid4().hex}",
            "access_token": f"rsi_access_{uuid.uuid4().hex}",
            "auth_token": jwt_token,
            "bearer_token": f"Bearer {jwt_token}",
            "star_network": {
                "services_endpoint": "https://127.0.0.1:8000",
                "hostname": "127.0.0.1",
                "port": 8000
            },
            "game_config": {
                "version": "4.1.149.3486",
                "region": "us-east-1",
                "shard": "PU",
                "game_mode": "persistent_universe",
                "server_id": "server_001"
            },
            "character": {
                "geid": f"{user_data['citizen_id']}96",
                "name": user_data['displayname'],
                "state": "STATE_CURRENT",
                "created_at": int(time.time() * 1000),
                "updated_at": int(time.time() * 1000),
                "account_id": user_data['account_id'],
                "location": self.default_home_location,  # Use config default home location
                "credits": 125000,
                "reputation": {
                    "crusader": 0,
                    "microtech": 0,
                    "arccorp": 0,
                    "hurston": 0
                }
            },
            "universe": {
                "region": "us-east-1",
                "shard": "PU",
                "server_id": "server_001",
                "instance_id": f"instance_{uuid.uuid4().hex[:8]}"
            },
            "permissions": {
                "game_access": True,
                "chat_access": True,
                "analytics_access": True,
                "file_access": True,
                "character_access": True,
                "universe_access": True
            },
            "launcher_session": {
                "authenticated": True,
                "auth_time": int(time.time()),
                "expires_at": int(time.time()) + self.session_timeout,  # Use config session timeout
                "launcher_version": "2.0.3.756",
                "client_id": "rsi_launcher_client"
            },
            "login_server": {
                "server": "dedicated_login_server",
                "version": "1.0",
                "authenticated_at": int(time.time()),
                "session_id": session_id,
                "status": "authenticated",
                "config": {
                    "default_home_location": self.default_home_location,
                    "eos_enabled": self.eos_enabled,
                    "session_timeout": self.session_timeout
                }
            },
            # EOS Integration status (from CSV identifiers)
            "eos_integration": {
                "enabled": self.eos_enabled,
                "notifications": self.config.EOS_CONNECT_NOTIFICATIONS,
                "status": "active" if self.eos_enabled else "disabled"
            }
        }
        
        # Store session
        self.active_sessions[session_id] = {
            'email': email,
            'login_data': login_data,
            'created_at': time.time(),
            'last_accessed': time.time()
        }
        
        # Ensure base directory exists
        os.makedirs(self.base_path, exist_ok=True)
        
        # Write login data to file
        try:
            with open(self.logindata_path, 'w', encoding='utf-8') as f:
                json.dump(login_data, f, indent=2, ensure_ascii=False)
            
            logging.info(f"✅ Session created for {email}")
            logging.info(f"🎫 JWT Token generated and stored in loginData.json")
            logging.info(f"🔑 Session ID: {session_id}")
            logging.info(f"👤 Character: {login_data['character']['name']} (GEID: {login_data['character']['geid']})")
            
            return session_id, login_data
            
        except Exception as e:
            logging.error(f"❌ Failed to write login data: {e}")
            return None, None
    
    def verify_session(self, session_id=None):
        """Verify if there's an active authenticated session"""
        if session_id and session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session['last_accessed'] = time.time()
            return session['login_data']
        
        # Check if loginData.json exists and is valid
        try:
            if os.path.exists(self.logindata_path):
                with open(self.logindata_path, 'r', encoding='utf-8') as f:
                    login_data = json.load(f)
                
                # Check if authentication is still valid
                launcher_session = login_data.get('launcher_session', {})
                if launcher_session.get('authenticated') and launcher_session.get('expires_at', 0) > time.time():
                    logging.info(f"✅ Valid authentication found in loginData.json")
                    return login_data
                else:
                    logging.warning(f"⚠️ Authentication expired in loginData.json")
                    return None
            else:
                logging.warning(f"⚠️ No loginData.json found")
                return None
                
        except Exception as e:
            logging.error(f"❌ Failed to verify session: {e}")
            return None

class LoginRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, login_server=None, **kwargs):
        self.login_server = login_server
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logging system"""
        logging.info(f"HTTP {self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            self.serve_login_page()
        elif self.path == '/status':
            self.serve_status_page()
        elif self.path.startswith('/verify'):
            self.handle_verify_request()
        elif self.path == '/test-diffusion':
            self.handle_test_diffusion_request()
        elif self.path == '/test':
            self.serve_test_page()
        else:
            self.send_error(404, "Page not found")
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/login':
            self.handle_login_request()
        elif self.path == '/logout':
            self.handle_logout_request()
        else:
            self.send_error(404, "Endpoint not found")
    
    def serve_login_page(self):
        """Serve the login page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Star Citizen Login Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
        .header { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="email"], input[type="password"] { 
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; 
        }
        .btn { 
            background: #007bff; color: white; padding: 12px 30px; 
            border: none; border-radius: 5px; cursor: pointer; font-size: 16px; 
        }
        .btn:hover { background: #0056b3; }
        .status { margin-top: 20px; padding: 10px; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .users { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Star Citizen Login Server</h1>
            <p>Authenticate to access the Star Citizen universe</p>
        </div>
        
        <form id="loginForm" method="post" action="/login">
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" value="test.pilot@robertsspaceindustries.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" value="test_password_123" required>
            </div>
            
            <button type="submit" class="btn">🔑 Authenticate</button>
        </form>
        
        <div class="users">
            <h3>Test Users:</h3>
            <p><strong>test.pilot@robertsspaceindustries.com</strong> / test_password_123</p>
            <p><strong>admin@robertsspaceindustries.com</strong> / admin_password</p>
        </div>
        
        <div style="margin-top: 30px; text-align: center;">
            <a href="/status" class="btn" style="text-decoration: none; display: inline-block;">📊 Server Status</a>
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').onsubmit = function(e) {
            e.preventDefault();
            
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();
            
            if (!email) {
                alert('Please enter an email address');
                return;
            }
            
            if (!password) {
                alert('Please enter a password');
                return;
            }
            
            // Create form data manually to ensure it's sent correctly
            const formData = new URLSearchParams();
            formData.append('email', email);
            formData.append('password', password);
            
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.body.innerHTML = `
                        <div class="container">
                            <div class="header">
                                <h1>✅ Authentication Successful</h1>
                                <p>Welcome, ${data.displayname}!</p>
                            </div>
                            <div class="status success">
                                <p><strong>Session ID:</strong> ${data.session_id}</p>
                                <p><strong>Account ID:</strong> ${data.account_id}</p>
                                <p><strong>Character:</strong> ${data.displayname}</p>
                                <p><strong>Status:</strong> Authentication tokens written to loginData.json</p>
                            </div>
                            <div style="text-align: center; margin-top: 30px;">
                                <p>🎮 You can now launch Star Citizen</p>
                                <button onclick="location.reload()" class="btn">🔄 Login Again</button>
                                <form method="post" action="/logout" style="display: inline;">
                                    <button type="submit" class="btn" style="background: #dc3545;">🚪 Logout</button>
                                </form>
                            </div>
                        </div>
                    `;
                } else {
                    alert('❌ Authentication failed: ' + data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('❌ Error: ' + error);
            });
        };
    </script>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_status_page(self):
        """Serve the status page"""
        # Check current authentication status
        login_data = self.login_server.verify_session()
        
        if login_data:
            status_html = f"""
            <div class="status success">
                <h3>✅ Authentication Status: AUTHENTICATED</h3>
                <p><strong>User:</strong> {login_data.get('displayname', 'Unknown')}</p>
                <p><strong>Email:</strong> {login_data.get('email', 'Unknown')}</p>
                <p><strong>Session:</strong> {login_data.get('session_id', 'Unknown')}</p>
                <p><strong>Expires:</strong> {datetime.fromtimestamp(login_data.get('launcher_session', {}).get('expires_at', 0))}</p>
            </div>
            """
        else:
            status_html = """
            <div class="status error">
                <h3>❌ Authentication Status: NOT AUTHENTICATED</h3>
                <p>No valid authentication session found.</p>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Login Server Status</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .container {{ background: #f5f5f5; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; color: #333; margin-bottom: 30px; }}
        .status {{ margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .success {{ background: #d4edda; color: #155724; }}
        .error {{ background: #f8d7da; color: #721c24; }}
        .info {{ background: #d1ecf1; color: #0c5460; }}
        .btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Star Citizen Login Server Status</h1>
        </div>
        
        {status_html}
        
        <div class="status info">
            <h3>🔧 Server Information</h3>
            <p><strong>Login Server:</strong> Running on port {self.login_server.port}</p>
            <p><strong>Active Sessions:</strong> {len(self.login_server.active_sessions)}</p>
            <p><strong>Registered Users:</strong> {len(self.login_server.users_db)}</p>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <a href="/" class="btn">🔑 Login Page</a>
            <a href="/verify" class="btn">🔍 Verify Auth</a>
            <a href="/test-diffusion" class="btn">🎮 Test Diffusion Server</a>
            <a href="/test" class="btn">🧪 Test Page</a>
            <button onclick="location.reload()" class="btn">🔄 Refresh</button>
        </div>
    </div>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_login_request(self):
        """Handle login authentication"""
        try:
            # Parse form data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Debug: Log the raw post data
            logging.info(f"🔍 Raw POST data: {post_data}")
            
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            
            # Debug: Log parsed form data
            logging.info(f"🔍 Parsed form data: {form_data}")
            
            email = form_data.get('email', [''])[0].strip()
            password = form_data.get('password', [''])[0].strip()
            
            # Validate inputs
            if not email:
                logging.warning("❌ Login attempt with empty email")
                response = {
                    'success': False,
                    'error': 'Email is required'
                }
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                return
            
            if not password:
                logging.warning("❌ Login attempt with empty password")
                response = {
                    'success': False,
                    'error': 'Password is required'
                }
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                return
            
            logging.info(f"🔐 Login attempt for: {email}")
            
            # Get client IP for login timeout tracking
            client_ip = self.client_address[0] if hasattr(self, 'client_address') else "127.0.0.1"
            
            # Authenticate user with enhanced tracking
            user_data, auth_result = self.login_server.authenticate_user(email, password, client_ip)
            
            if user_data:
                # Create session and login data
                session_id, login_data = self.login_server.create_session(email, user_data)
                
                if session_id:
                    response = {
                        'success': True,
                        'message': 'Authentication successful',
                        'session_id': session_id,
                        'account_id': user_data['account_id'],
                        'displayname': user_data['displayname']
                    }
                else:
                    response = {
                        'success': False,
                        'error': 'Failed to create session'
                    }
            else:
                response = {
                    'success': False,
                    'error': 'Invalid credentials'
                }
            
            # Send JSON response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"❌ Login error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_verify_request(self):
        """Handle authentication verification (for game server)"""
        try:
            login_data = self.login_server.verify_session()
            
            if login_data:
                response = {
                    'authenticated': True,
                    'account_id': login_data.get('account_id'),
                    'displayname': login_data.get('displayname'),
                    'session_id': login_data.get('session_id'),
                    'expires_at': login_data.get('launcher_session', {}).get('expires_at', 0)
                }
            else:
                response = {
                    'authenticated': False,
                    'error': 'No valid authentication found'
                }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"❌ Verify error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_test_diffusion_request(self):
        """Test the diffusion server integration"""
        try:
            import socket
            import ssl
            import struct
            
            # First check launcher authentication
            login_data = self.login_server.verify_session()
            if not login_data:
                response = {
                    'success': False,
                    'error': 'No valid launcher authentication found',
                    'suggestion': 'Please login first'
                }
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Test diffusion server connection
            try:
                # Create SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Connect to diffusion server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    
                    # Connect and establish TLS
                    with context.wrap_socket(sock, server_hostname='127.0.0.1') as ssl_sock:
                        ssl_sock.connect(('127.0.0.1', 8000))
                        
                        # Send test authentication request
                        auth_request = self.create_test_auth_request()
                        ssl_sock.send(auth_request)
                        
                        # Read response
                        response_data = ssl_sock.recv(4096)
                        
                        if response_data and len(response_data) >= 8:
                            # Parse response
                            success = self.parse_diffusion_response(response_data)
                            
                            response = {
                                'success': True,
                                'diffusion_server': {
                                    'connected': True,
                                    'authenticated': success,
                                    'response_size': len(response_data)
                                },
                                'launcher_auth': {
                                    'valid': True,
                                    'user': login_data.get('displayname'),
                                    'session': login_data.get('session_id')
                                }
                            }
                        else:
                            response = {
                                'success': False,
                                'error': 'No response from diffusion server',
                                'diffusion_server': {'connected': True, 'authenticated': False}
                            }
                            
            except Exception as conn_error:
                response = {
                    'success': False,
                    'error': f'Cannot connect to diffusion server: {conn_error}',
                    'diffusion_server': {'connected': False, 'authenticated': False},
                    'suggestion': 'Make sure diffusion server is running on port 8000'
                }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"❌ Test diffusion error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def create_test_auth_request(self):
        """Create a test authentication request for diffusion server"""
        # Message type 0x40 = AuthenticationRequest
        payload = bytes([0x40])
        
        # Add basic auth data
        auth_data = b"launcher_auth_request"
        payload += b'\x0a'  # field 1, wire type 2
        payload += bytes([len(auth_data)])
        payload += auth_data
        
        # Create packet with length and magic
        total_length = len(payload) + 4
        packet = struct.pack('<I', total_length)
        packet += b'\xef\xbe\xad\xde'  # Magic bytes
        packet += payload
        
        return packet
    
    def parse_diffusion_response(self, response):
        """Parse diffusion server response"""
        try:
            if len(response) < 8:
                return False
                
            # Extract length and magic
            length = struct.unpack('<I', response[:4])[0]
            magic = response[4:8]
            payload = response[8:]
            
            if magic != b'\xef\xbe\xad\xde':
                return False
            
            # Check for success indicators in the service acknowledgment
            # The diffusion server sends service acks when authenticated
            return len(payload) > 50  # Service acks are typically larger
            
        except Exception:
            return False
    
    def serve_test_page(self):
        """Serve the diffusion server test page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Diffusion Server Test</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
        .header { text-align: center; color: #333; margin-bottom: 30px; }
        .status { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .info { background: #d1ecf1; color: #0c5460; }
        .warning { background: #fff3cd; color: #856404; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .test-results { margin-top: 20px; }
        .loading { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎮 Diffusion Server Integration Test</h1>
            <p>Test the connection between login server and diffusion protocol server</p>
        </div>
        
        <div id="testResults" class="test-results"></div>
        
        <div style="text-align: center; margin-top: 30px;">
            <button onclick="runTest()" class="btn">🔍 Run Integration Test</button>
            <button onclick="runContinuousTest()" class="btn">🔄 Continuous Test</button>
            <a href="/status" class="btn">📊 Server Status</a>
            <a href="/" class="btn">🔑 Login</a>
        </div>
        
        <div class="loading" id="loading">
            <div class="status info">
                <p>🔄 Running test... Please wait.</p>
            </div>
        </div>
    </div>
    
    <script>
        let continuousTestInterval = null;
        
        function showLoading(show) {
            document.getElementById('loading').style.display = show ? 'block' : 'none';
        }
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('testResults');
            let html = '';
            
            if (data.success) {
                html += '<div class="status success"><h3>✅ Integration Test Passed</h3>';
                
                if (data.diffusion_server) {
                    const ds = data.diffusion_server;
                    html += '<p><strong>Diffusion Server:</strong></p>';
                    html += `<ul>`;
                    html += `<li>Connected: ${ds.connected ? '✅' : '❌'}</li>`;
                    html += `<li>Authenticated: ${ds.authenticated ? '✅' : '❌'}</li>`;
                    html += `<li>Response Size: ${ds.response_size || 0} bytes</li>`;
                    html += `</ul>`;
                }
                
                if (data.launcher_auth) {
                    const la = data.launcher_auth;
                    html += '<p><strong>Launcher Authentication:</strong></p>';
                    html += `<ul>`;
                    html += `<li>Valid: ${la.valid ? '✅' : '❌'}</li>`;
                    html += `<li>User: ${la.user || 'Unknown'}</li>`;
                    html += `<li>Session: ${la.session || 'Unknown'}</li>`;
                    html += `</ul>`;
                }
                
                html += '</div>';
            } else {
                html += '<div class="status error"><h3>❌ Integration Test Failed</h3>';
                html += `<p><strong>Error:</strong> ${data.error || 'Unknown error'}</p>`;
                
                if (data.suggestion) {
                    html += `<p><strong>Suggestion:</strong> ${data.suggestion}</p>`;
                }
                
                if (data.diffusion_server) {
                    const ds = data.diffusion_server;
                    html += '<p><strong>Diffusion Server Status:</strong></p>';
                    html += `<ul>`;
                    html += `<li>Connected: ${ds.connected ? '✅' : '❌'}</li>`;
                    html += `<li>Authenticated: ${ds.authenticated ? '✅' : '❌'}</li>`;
                    html += `</ul>`;
                }
                
                html += '</div>';
            }
            
            html += `<div class="status info"><small>Test completed at: ${new Date().toLocaleString()}</small></div>`;
            resultsDiv.innerHTML = html;
        }
        
        function runTest() {
            showLoading(true);
            
            fetch('/test-diffusion')
                .then(response => response.json())
                .then(data => {
                    showLoading(false);
                    displayResults(data);
                })
                .catch(error => {
                    showLoading(false);
                    displayResults({
                        success: false,
                        error: `Network error: ${error.message}`,
                        suggestion: 'Check if the login server is running'
                    });
                });
        }
        
        function runContinuousTest() {
            if (continuousTestInterval) {
                clearInterval(continuousTestInterval);
                continuousTestInterval = null;
                document.querySelector('button[onclick="runContinuousTest()"]').textContent = '🔄 Continuous Test';
                return;
            }
            
            document.querySelector('button[onclick="runContinuousTest()"]').textContent = '⏹️ Stop Continuous Test';
            
            runTest(); // Run immediately
            continuousTestInterval = setInterval(runTest, 5000); // Then every 5 seconds
        }
        
        // Run test automatically when page loads
        window.onload = function() {
            runTest();
        };
    </script>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_logout_request(self):
        """Handle logout request"""
        try:
            # Clear session data
            # In a full implementation, you'd parse session ID from request
            self.login_server.active_sessions.clear()
            
            # Remove loginData.json
            if os.path.exists(self.login_server.logindata_path):
                os.remove(self.login_server.logindata_path)
                logging.info("🚪 User logged out, loginData.json removed")
            
            response = {'success': True, 'message': 'Logged out successfully'}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"❌ Logout error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    # ...existing code...
def create_handler_class(login_server):
    """Create a request handler class with the login server instance"""
    class Handler(LoginRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, login_server=login_server, **kwargs)
    return Handler

def main():
    """Main entry point"""
    logging.info("🚀 Starting Star Citizen Dedicated Login Server")
    
    # Create login server
    login_server = LoginServer(port=9000)
    
    # Create HTTP server
    handler_class = create_handler_class(login_server)
    httpd = HTTPServer(('127.0.0.1', login_server.port), handler_class)
    
    logging.info(f"✅ Login server running on http://127.0.0.1:{login_server.port}")
    logging.info(f"🌐 Web interface: http://127.0.0.1:{login_server.port}")
    logging.info(f"🔍 Verify endpoint: http://127.0.0.1:{login_server.port}/verify")
    logging.info(f"📊 Status page: http://127.0.0.1:{login_server.port}/status")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("🛑 Login server shutting down...")
        httpd.shutdown()

if __name__ == "__main__":
    main()

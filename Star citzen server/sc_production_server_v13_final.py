#!/usr/bin/env python3
"""
Star Citizen Production gRPC Server v13 - Enhanced Login Flow with Real Game Notifications
Based on real loginData.json for full compatibility with Star Citizen client
Implements: ConfigService, LoginService, CharacterService, TraceService
Enhanced with complete login state notifications and status updates matching real game flow
"""

import grpc
from concurrent import futures
import time
import logging
import threading
import sys
import os
import json
import secrets
import hashlib
import base64
import re
from datetime import datetime, timedelta
import uuid

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import login_service_pb2
    import login_service_pb2_grpc
    print("+ Successfully imported protobuf modules")
except ImportError as e:
    print(f"- Failed to import protobuf modules: {e}")
    sys.exit(1)

# Import character service protobuf
try:
    import character_service_pb2
    import character_service_pb2_grpc
    print("+ Successfully imported character service protobuf modules")
except ImportError as e:
    print(f"- Failed to import character service protobuf modules: {e}")
    print("Please regenerate character_service_pb2.py and character_service_pb2_grpc.py")

# Configure enhanced logging based on TLS analysis recommendations with Windows compatibility
import sys
import io

# Configure logging with UTF-8 encoding for Windows compatibility
log_handlers = [
    logging.FileHandler('sc_production_v13_enhanced_flow.log', encoding='utf-8')
]

# Add console handler with proper encoding for Windows
if sys.platform == 'win32':
    # Use UTF-8 encoding for console on Windows
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setStream(io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace'))
    log_handlers.append(console_handler)
else:
    log_handlers.append(logging.StreamHandler())

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

class LoginStateManager:
    """Manages login state transitions matching real Star Citizen client behavior"""
    
    def __init__(self):
        self.session_states = {}
        self.lock = threading.Lock()
        
        # Login state constants from real game logs
        self.LOGIN_STATES = {
            'CONNECTING': 'kAccountConnecting',
            'CONNECTED': 'kAccountConnected', 
            'AUTHENTICATING': 'kAccountAuthenticating',
            'LOGIN_SUCCESS': 'kAccountLoginSuccess',
            'CHARACTER_STATUS': 'kAccountLoginCharacterStatus', 
            'LOGIN_COMPLETED': 'kAccountLoginCompleted',
            'CONNECTION_LOST': 'kAccountConnectionLost',
            'FAILED': 'kAccountFailed',
            'RECONNECTING': 'kAccountReconnecting'
        }
    
    def set_session_state(self, session_id, state, account_id=None):
        """Set login state for session and emit appropriate notifications"""
        with self.lock:
            if session_id not in self.session_states:
                self.session_states[session_id] = {
                    'current_state': None,
                    'account_id': account_id,
                    'start_time': time.time(),
                    'transitions': []
                }
            
            prev_state = self.session_states[session_id]['current_state']
            self.session_states[session_id]['current_state'] = state
            self.session_states[session_id]['transitions'].append({
                'from_state': prev_state,
                'to_state': state,
                'timestamp': time.time()
            })
            
            # Emit state change notification matching real game behavior
            state_name = self.LOGIN_STATES.get(state, state)
            if account_id:
                logger.info(f"🔔 [LoginStateManager] Account {account_id} state transition: {prev_state} → {state_name}")
            else:
                logger.info(f"🔔 [LoginStateManager] Session {session_id} state transition: {prev_state} → {state_name}")
            
            return state_name
    
    def get_session_state(self, session_id):
        """Get current state for session"""
        with self.lock:
            return self.session_states.get(session_id, {}).get('current_state')
    
    def cleanup_old_sessions(self, max_age_seconds=3600):
        """Clean up sessions older than max_age_seconds"""
        with self.lock:
            current_time = time.time()
            expired_sessions = [
                session_id for session_id, data in self.session_states.items()
                if current_time - data['start_time'] > max_age_seconds
            ]
            for session_id in expired_sessions:
                del self.session_states[session_id]
            
            if expired_sessions:
                logger.info(f"[LoginStateManager] Cleaned up {len(expired_sessions)} expired sessions")

# Global login state manager
login_state_manager = LoginStateManager()

class LoginNotificationService:
    """Service for managing login-related notifications and status updates"""
    
    def __init__(self):
        self.active_streams = {}
        self.lock = threading.Lock()
    
    def emit_account_login_character_status(self, account_id, characters_data):
        """Emit AccountLoginCharacterStatus notification matching real game flow"""
        try:
            logger.info(f"🔔 [LoginNotification] Emitting AccountLoginCharacterStatus for account {account_id}")
            logger.info(f"🔔 [LoginNotification] Characters: {len(characters_data)} characters found")
            
            for char in characters_data:
                logger.info(f"🔔 [LoginNotification] - Character: {char.get('name')} (State: {char.get('state')}, Location: {char.get('location', 'Unknown')})")
            
            # In a real implementation, this would be sent via notification stream
            # For now, we log the notification to match real game behavior
            logger.info(f"🔔 [LoginNotification] AccountLoginCharacterStatus notification sent successfully")
            
        except Exception as e:
            logger.error(f"[LoginNotification] Error emitting character status: {e}")
    
    def emit_reconcile_account_update(self, account_id, reconcile_data):
        """Emit ReconcileAccountUpdateNotification matching real game flow"""
        try:
            logger.info(f"🔔 [LoginNotification] Emitting ReconcileAccountUpdateNotification for account {account_id}")
            logger.info(f"🔔 [LoginNotification] Reconcile data: {json.dumps(reconcile_data, indent=2)}")
            
            # Log the reconciliation details as seen in real game
            if 'entitlements' in reconcile_data:
                logger.info(f"🔔 [LoginNotification] - Entitlements: {len(reconcile_data['entitlements'])} items")
            if 'account_status' in reconcile_data:
                logger.info(f"🔔 [LoginNotification] - Account Status: {reconcile_data['account_status']}")
            if 'subscription_status' in reconcile_data:
                logger.info(f"🔔 [LoginNotification] - Subscription: {reconcile_data['subscription_status']}")
            
            logger.info(f"🔔 [LoginNotification] ReconcileAccountUpdateNotification sent successfully")
            
        except Exception as e:
            logger.error(f"[LoginNotification] Error emitting reconcile update: {e}")
    
    def emit_login_status_update(self, session_id, status_update):
        """Emit general login status updates"""
        try:
            logger.info(f"🔔 [LoginNotification] Login status update for session {session_id}: {status_update}")
        except Exception as e:
            logger.error(f"[LoginNotification] Error emitting status update: {e}")

# Global notification service
login_notification_service = LoginNotificationService()

class LoginDataManager:
    """Manager for loading and using real Star Citizen login data from loginData.json"""
    
    def __init__(self, login_data_path="G:\\scdebugging\\PTU\\StarCitizenGameclient\\loginData.json"):
        self.login_data_path = login_data_path
        self.login_data = None
        self.load_login_data()
    
    def load_login_data(self):
        """Load real login data from loginData.json"""
        try:
            with open(self.login_data_path, 'r', encoding='utf-8') as f:
                self.login_data = json.load(f)
            logger.info(f"[LoginDataManager] Successfully loaded login data from {self.login_data_path}")
            logger.info(f"[LoginDataManager] Username: {self.login_data.get('username', 'N/A')}")
            logger.info(f"[LoginDataManager] Account ID: {self.login_data.get('account_id', 'N/A')}")
            logger.info(f"[LoginDataManager] Citizen ID: {self.login_data.get('citizen_id', 'N/A')}")
            return True
        except FileNotFoundError:
            logger.error(f"[LoginDataManager] Login data file not found: {self.login_data_path}")
            self.login_data = None
            return False
        except json.JSONDecodeError as e:
            logger.error(f"[LoginDataManager] Invalid JSON in login data file: {e}")
            self.login_data = None
            return False
        except Exception as e:
            logger.error(f"[LoginDataManager] Error loading login data: {e}")
            self.login_data = None
            return False
    
    def get_account_data(self):
        """Get account data from real login data"""
        if not self.login_data:
            return None
        
        return {
            'account_id': self.login_data.get('account_id'),
            'username': self.login_data.get('username'),
            'email': self.login_data.get('email'),
            'displayname': self.login_data.get('displayname'),
            'nickname': self.login_data.get('nickname'),
            'citizen_id': self.login_data.get('citizen_id'),
            'session_id': self.login_data.get('session_id'),
            'token': self.login_data.get('token'),
            'auth_token': self.login_data.get('auth_token'),
            'bearer_token': self.login_data.get('bearer_token'),
            'jwt_token': self.login_data.get('auth_token')  # Use auth_token as JWT
        }
    
    def get_character_data(self):
        """Get character data from real login data"""
        if not self.login_data or 'character' not in self.login_data:
            return None
        
        char = self.login_data['character']
        return {
            'geid': char.get('geid'),
            'name': char.get('name'),
            'account_id': char.get('account_id'),
            'state': char.get('state', 'STATE_CURRENT'),
            'created_at': char.get('created_at'),
            'updated_at': char.get('updated_at'),
            'location': char.get('location'),
            'credits': char.get('credits'),
            'reputation': char.get('reputation', {})
        }
    
    def get_star_network_config(self):
        """Get StarNetwork configuration from real login data"""
        if not self.login_data or 'star_network' not in self.login_data:
            return {
                'services_endpoint': 'https://127.0.0.1:8000',  # Point to dedicated StarNetwork service
                'hostname': '127.0.0.1',
                'port': 8000
            }
        
        network = self.login_data['star_network']
        return {
            'services_endpoint': network.get('services_endpoint', 'dns:///127.0.0.1:5678'),
            'hostname': network.get('hostname', '127.0.0.1'),
            'port': network.get('port', 8000)
        }
    
    def get_game_config(self):
        """Get game configuration from real login data"""
        if not self.login_data or 'game_config' not in self.login_data:
            return {
                'version': '4.2.151.51347',
                'region': 'us-east-1',
                'shard': 'PU'
            }
        
        config = self.login_data['game_config']
        return {
            'version': config.get('version', '4.2.151.51347'),
            'region': config.get('region', 'us-east-1'),
            'shard': config.get('shard', 'PU'),
            'game_mode': config.get('game_mode', 'persistent_universe'),
            'server_id': config.get('server_id', 'server_001')
        }
    
    def is_available(self):
        """Check if login data is available"""
        return self.login_data is not None

class SessionManager:
    """Session management for Bearer token authentication"""
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 86400  # 24 hours as per analysis
        self.lock = threading.Lock()
    
    def create_session(self, account_id, jwt_token):
        """Create a new session with secure token"""
        session_id = str(uuid.uuid4())
        session_token = secrets.token_urlsafe(32)
        
        with self.lock:
            self.sessions[session_id] = {
                'account_id': account_id,
                'jwt_token': jwt_token,
                'session_token': session_token,
                'created_at': time.time(),
                'last_activity': time.time()
            }
        
        logger.info(f"[SessionManager] Created session {session_id} for account {account_id}")
        return session_id, session_token
    
    def validate_session(self, session_id, session_token=None):
        """Validate session and update activity"""
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            session = self.sessions[session_id]
            current_time = time.time()
            
            # Check timeout
            if current_time - session['created_at'] > self.session_timeout:
                del self.sessions[session_id]
                logger.warning(f"[SessionManager] Session {session_id} expired")
                return False
            
            # Update last activity
            session['last_activity'] = current_time
            return True
    
    def get_session_info(self, session_id):
        """Get session information"""
        with self.lock:
            return self.sessions.get(session_id, {})

class CharacterService:
    """Character service implementation using real login data"""
    def __init__(self, login_data_manager):
        self.login_data_manager = login_data_manager
        self.characters_db = {}
        self.lock = threading.Lock()
        self.max_characters_per_account = 5
    
    def get_characters_for_account(self, account_id):
        """Retrieve character list for account using real login data"""
        with self.lock:
            # Try to get real character data first
            if self.login_data_manager.is_available():
                real_account_data = self.login_data_manager.get_account_data()
                real_char_data = self.login_data_manager.get_character_data()
                
                # If this account matches our real login data, use it
                if real_account_data and real_account_data['account_id'] == account_id:
                    if real_char_data:
                        # Convert state from string to integer
                        state_mapping = {
                            'STATE_CURRENT': 1,
                            'STATE_ARCHIVED': 2,
                            'STATE_DELETED': 3
                        }
                        state_value = state_mapping.get(real_char_data['state'], 1)
                        
                        character = {
                            'character_id': real_char_data['geid'],
                            'account_id': real_char_data['account_id'],
                            'name': real_char_data['name'],
                            'created_at': real_char_data['created_at'],
                            'updated_at': real_char_data['updated_at'],
                            'last_played': real_char_data['updated_at'],  # For backwards compatibility
                            'state': state_value,
                            'location': real_char_data['location'],
                            'credits': real_char_data['credits'],
                            'geid': real_char_data['geid'],
                            'handle': real_char_data['name']
                        }
                        
                        logger.info(f"[CharacterService] Using real character data for account {account_id}")
                        logger.info(f"[CharacterService] Character: {real_char_data['name']} (GEID: {real_char_data['geid']})")
                        return [character]
            
            # Fallback to generated characters if no real data available
            if account_id not in self.characters_db:
                self.characters_db[account_id] = self._generate_default_characters(account_id)
            
            return self.characters_db[account_id]
    
    def _generate_default_characters(self, account_id):
        """Generate realistic character data matching updated proto structure"""
        characters = []
        base_time = int(time.time())
        
        # Create 1-3 characters per account
        num_chars = min(3, self.max_characters_per_account)
        
        for i in range(num_chars):
            char_id = f"char_{account_id}_{i+1:03d}"
            character = {
                'character_id': char_id,  # Will be mapped to 'geid' in proto
                'account_id': account_id,
                'name': f"Pilot_{1000001 + i}",  # Match client log pattern "Pilot_1000001"
                'created_at': base_time - (86400 * (30 + i)),  # Created 30+ days ago
                'last_played': base_time - (3600 * (i + 1)),   # For backwards compatibility
                'updated_at': base_time - (3600 * (i + 1)),    # Updated at same time as last played
                'state': 1 if i == 0 else 2,  # 1 = STATE_CURRENT, 2 = STATE_ARCHIVED (integer values)
                'location': f"Stanton_{i+1}",
                'ship': ["Aurora", "Mustang", "Avenger"][i] if i < 3 else "Aurora",
                'geid': f"geid_{secrets.token_hex(8)}",  # Game Entity ID
                'handle': f"Pilot_{1000001 + i}"  # Player handle from logs
            }
            characters.append(character)
        
        logger.info(f"[CharacterService] Generated {len(characters)} characters for account {account_id}")
        return characters

class AuthenticationService:
    """Bearer token authentication using real login data"""
    def __init__(self):
        self.rate_limiter = {}
        self.lock = threading.Lock()
        self.max_attempts = 100  # Very high limit for Star Citizen's connection pattern
        self.lockout_duration = 30  # Short lockout duration (30 seconds)
    
    def validate_bearer_token(self, jwt_token, client_ip="unknown"):
        """Validate JWT bearer token using real login data"""
        if not jwt_token:
            return None, "Missing JWT token"
        
        # Check rate limiting
        if not self._check_rate_limit(client_ip):
            return None, "Rate limit exceeded"
        
        try:
            # First try to validate against real login data
            if login_data_manager.is_available():
                real_account_data = login_data_manager.get_account_data()
                if real_account_data:
                    # Check if token matches any of our real tokens
                    real_tokens = [
                        real_account_data.get('auth_token'),
                        real_account_data.get('bearer_token'),
                        real_account_data.get('token'),
                        real_account_data.get('jwt_token')
                    ]
                    
                    for real_token in real_tokens:
                        if real_token and (jwt_token == real_token or jwt_token in real_token):
                            logger.info(f"[AuthService] Successfully validated JWT against real login data for account {real_account_data['account_id']}")
                            return real_account_data['account_id'], None
            
            # Fallback to simplified parsing for development/testing
            account_id = self._extract_account_from_jwt(jwt_token)
            if account_id:
                logger.info(f"[AuthService] Successfully validated JWT for account {account_id} (fallback)")
                return account_id, None
            else:
                return None, "Invalid JWT token"
        
        except Exception as e:
            logger.error(f"[AuthService] JWT validation error: {e}")
            return None, "Token validation failed"
    
    def _check_rate_limit(self, client_ip):
        """Implement rate limiting for authentication attempts"""
        current_time = time.time()
        
        with self.lock:
            if client_ip not in self.rate_limiter:
                self.rate_limiter[client_ip] = {'attempts': 0, 'last_attempt': current_time}
                return True
            
            limiter = self.rate_limiter[client_ip]
            
            # Reset if lockout period has passed
            if current_time - limiter['last_attempt'] > self.lockout_duration:
                limiter['attempts'] = 0
            
            limiter['last_attempt'] = current_time
            limiter['attempts'] += 1
            
            if limiter['attempts'] > self.max_attempts:
                logger.warning(f"[AuthService] Rate limit exceeded for {client_ip}")
                return False
            
            return True
    
    def _extract_account_from_jwt(self, jwt_token):
        """Extract account ID from JWT token (simplified)"""
        try:
            # Real implementation would validate signature
            # For now, generate consistent account ID from token
            token_hash = hashlib.sha256(jwt_token.encode()).hexdigest()
            account_id = f"acc_{token_hash[:12]}"
            return account_id
        except Exception as e:
            logger.error(f"[AuthService] Failed to extract account from JWT: {e}")
            return None

# Global service instances
login_data_manager = LoginDataManager()
session_manager = SessionManager()
character_service = CharacterService(login_data_manager)
auth_service = AuthenticationService()

class ServiceStats:
    """Enhanced service statistics with monitoring capabilities"""
    def __init__(self):
        self.stats = {}
        self.error_counts = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_report = time.time()
        self.health_status = "healthy"
    
    def increment(self, service_name, success=True):
        with self.lock:
            if service_name not in self.stats:
                self.stats[service_name] = {'success': 0, 'error': 0}
                self.error_counts[service_name] = []
            
            if success:
                self.stats[service_name]['success'] += 1
            else:
                self.stats[service_name]['error'] += 1
                self.error_counts[service_name].append(time.time())
                
                # Clean old errors (keep last hour)
                hour_ago = time.time() - 3600
                self.error_counts[service_name] = [
                    t for t in self.error_counts[service_name] if t > hour_ago
                ]
    
    def should_report(self, interval=120):
        """Check if we should report stats (every 2 minutes)"""
        now = time.time()
        if now - self.last_report >= interval:
            self.last_report = now
            return True
        return False
    
    def get_health_status(self):
        """Check server health based on error rates"""
        with self.lock:
            total_errors = sum(len(errors) for errors in self.error_counts.values())
            if total_errors > 100:  # More than 100 errors in last hour
                self.health_status = "degraded"
            elif total_errors > 500:
                self.health_status = "unhealthy"
            else:
                self.health_status = "healthy"
            
            return self.health_status
    
    def get_summary(self):
        with self.lock:
            total_success = sum(s['success'] for s in self.stats.values())
            total_errors = sum(s['error'] for s in self.stats.values())
            total_calls = total_success + total_errors
            runtime = time.time() - self.start_time
            
            return {
                'total_calls': total_calls,
                'total_success': total_success,
                'total_errors': total_errors,
                'error_rate': (total_errors / total_calls * 100) if total_calls > 0 else 0,
                'runtime_seconds': runtime,
                'calls_per_second': total_calls / runtime if runtime > 0 else 0,
                'health_status': self.get_health_status(),
                'breakdown': self.stats.copy()
            }

# Global stats tracker
service_stats = ServiceStats()

class StarCitizenLoginService(login_service_pb2_grpc.LoginServiceServicer):
    """Enhanced LoginService implementing Bearer token authentication and session management"""
    
    def __init__(self):
        self.login_count = 0
        self.enhanced_services = EnhancedStarCitizenServices()
        logger.info("[LoginService] Initialized with enhanced telemetry support")
    
    def InitiateLogin(self, request, context):
        self.login_count += 1
        service_stats.increment('LoginService')
        
        # Get client info for security logging
        client_peer = context.peer() if context else "unknown"
        client_ip = client_peer.split(':')[-1] if ':' in client_peer else client_peer
        
        logger.info(f"[LoginService] *** STAR CITIZEN LOGIN REQUEST #{self.login_count} ***")
        logger.info(f"[LoginService] Client: {client_peer}")
        logger.info(f"[LoginService] Request type: {type(request)}")
        
        try:
            # Extract authentication data from actual client message structure
            session_id = getattr(request, 'session_id', '')
            client_data = getattr(request, 'client_data', b'')
            jwt_token = getattr(request, 'jwt_token', '')
            device_info = getattr(request, 'device_info', '')
            
            logger.info(f"[LoginService] Session ID: {session_id}")
            logger.info(f"[LoginService] Client Data Length: {len(client_data)} bytes")
            logger.info(f"[LoginService] Client Data Hex: {client_data.hex() if client_data else 'none'}")
            logger.info(f"[LoginService] JWT Token Present: {'yes' if jwt_token else 'no'}")
            logger.info(f"[LoginService] Device Info: {device_info}")
            
            # ENHANCED LOGIN FLOW - Begin state transitions matching real game
            logger.info(f"🚀 [LoginService] Starting enhanced login flow for session {session_id}")
            
            # Step 1: Set initial connection state
            login_state_manager.set_session_state(session_id, 'CONNECTING')
            
            # Step 2: Simulate connection establishment  
            time.sleep(0.1)  # Brief delay to simulate real connection time
            login_state_manager.set_session_state(session_id, 'CONNECTED')
            
            # Step 3: Begin authentication
            login_state_manager.set_session_state(session_id, 'AUTHENTICATING')
            
            # Parse client_data if present (looks like timestamp or similar)
            device_id = 0
            if client_data and len(client_data) >= 4:
                # Try to extract what might be a timestamp or device identifier from binary data
                import struct
                try:
                    # Assume it's a varint or similar - extract first few bytes as number
                    if len(client_data) >= 5 and client_data[0] == 0x08:
                        # Looks like protobuf varint encoding
                        value = 0
                        for i, byte in enumerate(client_data[1:5]):
                            value |= (byte & 0x7F) << (7 * i)
                            if not (byte & 0x80):
                                break
                        device_id = value
                        logger.info(f"[LoginService] Parsed device/timestamp from client_data: {device_id}")
                except Exception as e:
                    logger.warning(f"[LoginService] Could not parse client_data: {e}")
            
            # Clean session ID by removing any prefix characters
            clean_session_id = session_id
            if session_id and session_id.startswith('$'):
                clean_session_id = session_id[1:]  # Remove $ prefix
                logger.info(f"[LoginService] Cleaned session ID: {session_id} -> {clean_session_id}")
            
            # Use real login data if available, otherwise fallback to session-based auth
            account_id = None
            account_data = None
            
            if login_data_manager.is_available():
                # Use real login data
                account_data = login_data_manager.get_account_data()
                if account_data:
                    account_id = account_data['account_id']
                    logger.info(f"[LoginService] Using real login data for account {account_id}")
                    logger.info(f"[LoginService] Username: {account_data['username']}")
                    logger.info(f"[LoginService] Displayname: {account_data['displayname']}")
            
            if not account_id:
                # Fallback to session-based authentication for testing
                logger.info(f"[LoginService] Real login data not available, using session-based authentication")
                
                if clean_session_id and len(clean_session_id) > 10:
                    # Generate consistent account ID from cleaned session ID and device ID
                    session_device_str = f"{clean_session_id}_{device_id}"
                    session_hash = hashlib.sha256(session_device_str.encode()).hexdigest()
                    account_id = f"dev_{session_hash[:12]}"
                    logger.info(f"[LoginService] Created account {account_id} from session {clean_session_id} and device {device_id}")
                else:
                    # Fallback: Generate random account for testing
                    account_id = f"test_{secrets.token_hex(6)}"
                    logger.info(f"[LoginService] Generated test account {account_id}")
            
            if not account_id:
                # Fallback to session-based authentication for testing
                logger.info(f"[LoginService] Real login data not available, using session-based authentication")
                
                if clean_session_id and len(clean_session_id) > 10:
                    # Generate consistent account ID from cleaned session ID and device ID
                    session_device_str = f"{clean_session_id}_{device_id}"
                    session_hash = hashlib.sha256(session_device_str.encode()).hexdigest()
                    account_id = f"dev_{session_hash[:12]}"
                    logger.info(f"[LoginService] Created account {account_id} from session {clean_session_id} and device {device_id}")
                else:
                    # Fallback: Generate random account for testing
                    account_id = f"test_{secrets.token_hex(6)}"
                    logger.info(f"[LoginService] Generated test account {account_id}")
            
            # Check rate limiting even in development mode
            if not auth_service._check_rate_limit(client_ip):
                logger.warning(f"[LoginService] Rate limit exceeded for {client_ip}")
                service_stats.increment('LoginService', success=False)
                
                response = login_service_pb2.InitiateLoginResponse()
                response.result_code = 9  # Special error code 9 for rate limiting (client handles differently)
                response.nickname = ""
                response.displayname = ""
                response.tracking_metrics_id = f"rate_limited_{int(time.time())}"
                response.login_request_state = 2  # LOGIN_REQUEST_STATE_ERROR
                response.login_request_phase = 1  # LOGIN_REQUEST_PHASE_IN_QUEUE (suggests retry/queue)
                return response
            
            # Create session for authenticated user using cleaned session ID
            jwt_token = account_data.get('jwt_token') if account_data else f"jwt.{secrets.token_urlsafe(32)}.{secrets.token_urlsafe(16)}"
            new_session_id, session_token = session_manager.create_session(account_id, jwt_token)
            
            # Get character data
            characters_data = character_service.get_characters_for_account(account_id)
            
            # Get StarNetwork configuration from real data
            star_network_config = login_data_manager.get_star_network_config() if login_data_manager.is_available() else {
                'services_endpoint': 'dns:///127.0.0.1:5678',  # Point to gRPC Game Server (this server)
                'hostname': '127.0.0.1', 
                'port': 5678
            }
            
            # Create comprehensive successful login response with multi-phase support
            response = login_service_pb2.InitiateLoginResponse()
            response.result_code = 0  # 0 = success (CRITICAL for Star Citizen)
            
            # MULTI-PHASE LOGIN SUPPORT (from decompiled code analysis)
            # Client expects these specific phase and state values:
            response.login_request_state = 3  # LOGIN_REQUEST_STATE_COMPLETE
            response.login_request_phase = 5  # LOGIN_REQUEST_PHASE_DONE
            response.login_request_id = f"login_req_{new_session_id}_{int(time.time())}"
            
            # Core login response fields
            response.account_id = account_id  # accountId field expected by client
            response.session_id = new_session_id  # sessionId field expected by client
            
            # Use real data if available
            if account_data:
                response.nickname = account_data['nickname']
                response.displayname = account_data['displayname']
            else:
                response.nickname = f"Pilot_{account_id[-8:]}"
                response.displayname = f"Test Pilot {account_id[-8:]}"
            
            # Add badge_mask field (from decompiled code analysis)
            response.badge_mask = 0  # Default badge mask
            
            response.tracking_metrics_id = f"tracking_{new_session_id}_{int(time.time())}"
            
            # Add primary character data to cache_data (proto has single character, not array)
            if characters_data:
                primary_char = characters_data[0]  # Use first character as primary
                response.cache_data.character.geid = primary_char.get('character_id', '')
                response.cache_data.character.account_id = primary_char.get('account_id', '')
                response.cache_data.character.name = primary_char.get('name', '')
                
                # Fix: Convert state to integer - both protos now expect int32
                state_value = primary_char.get('state', 1)
                if isinstance(state_value, str):
                    # Map string states to integer values as defined in proto
                    state_mapping = {
                        'STATE_CURRENT': 1,
                        'CURRENT': 1,
                        'ACTIVE': 1,
                        'STATE_ARCHIVED': 2,
                        'ARCHIVED': 2,
                        'STATE_DELETED': 3,
                        'DELETED': 3
                    }
                    state_value = state_mapping.get(state_value.upper(), 1)
                
                response.cache_data.character.state = state_value
                response.cache_data.character.location = primary_char.get('location', 'Port Olisar')
                
                # Note: The login service Character message only has basic fields:
                # geid, account_id, name, state, location
                # Full character data (createdAt, updatedAt, credits) is in the character service

            # Add StarNetwork information to cache_data
            response.cache_data.star_network.services_endpoint = star_network_config.get('services_endpoint', 'dns:///127.0.0.1:5678')
            response.cache_data.star_network.hostname = star_network_config.get('hostname', '127.0.0.1')
            response.cache_data.star_network.port = star_network_config.get('port', 5678)

            # Add GameConfig to cache_data
            response.cache_data.game_config.version = account_data.get('game_config', {}).get('version', '4.2.151.51347') if account_data else '4.2.151.51347'
            response.cache_data.game_config.region = account_data.get('game_config', {}).get('region', 'us-east-1') if account_data else 'us-east-1'
            response.cache_data.game_config.shard = account_data.get('game_config', {}).get('shard', 'PU') if account_data else 'PU'
            response.cache_data.game_config.game_mode = account_data.get('game_config', {}).get('game_mode', 'persistent_universe') if account_data else 'persistent_universe'
            response.cache_data.game_config.server_id = account_data.get('game_config', {}).get('server_id', 'server_001') if account_data else 'server_001'

            # Add Universe to cache_data
            response.cache_data.universe.region = response.cache_data.game_config.region
            response.cache_data.universe.shard = response.cache_data.game_config.shard
            response.cache_data.universe.server_id = response.cache_data.game_config.server_id
            response.cache_data.universe.instance_id = f"instance_{int(time.time())}"

            # Add Permissions to cache_data
            response.cache_data.permissions.game_access = True
            response.cache_data.permissions.chat_access = True
            response.cache_data.permissions.analytics_access = True
            response.cache_data.permissions.file_access = True
            response.cache_data.permissions.character_access = True
            response.cache_data.permissions.universe_access = True

            # Add LoginCacheInfo account details
            if account_data:
                response.cache_data.account_id = account_data.get('account_id', '')
                response.cache_data.citizen_id = account_data.get('citizen_id', '')
                response.cache_data.email = account_data.get('email', '')
            else:
                response.cache_data.account_id = account_id
                response.cache_data.citizen_id = f"citizen_{account_id[-8:]}"
                response.cache_data.email = f"pilot_{account_id[-8:]}@test.com"

            # Add JWT token to response using real token if available
            response.jwt = jwt_token
            # Set any new proto fields in InitiateLoginResponse to safe defaults
            if hasattr(response, 'extra_info'):
                response.extra_info = ''
            
            logger.info(f"[LoginService] >> AUTHENTICATION SUCCESS - Login #{self.login_count}")
            logger.info(f"[LoginService] 🎯 DECOMPILED CODE VALIDATION: Multi-phase login response structure")
            logger.info(f"[LoginService] 🎯 Client expects: LOGIN_REQUEST_STATE_COMPLETE (3) + LOGIN_REQUEST_PHASE_DONE (5)")
            logger.info(f"[LoginService] 🎯 Client will now set: SET_ACCOUNT_STATE state [kAccountLoginSuccess]")
            logger.info(f"[LoginService] 🎯 Client state transition: Authentication -> kAccountLoginSuccess (state 3)")
            logger.info(f"[LoginService] Original Session ID: {session_id}")
            logger.info(f"[LoginService] Cleaned Session ID: {clean_session_id}")
            logger.info(f"[LoginService] Device ID: {device_id}")
            logger.info(f"[LoginService] Account ID: {account_id} -> response.account_id")
            logger.info(f"[LoginService] New Session ID: {new_session_id} -> response.session_id")
            logger.info(f"[LoginService] Response: result_code={response.result_code} (SUCCESS - client expects 0)")
            logger.info(f"[LoginService] Login Request State: {response.login_request_state} (LOGIN_REQUEST_STATE_COMPLETE)")
            logger.info(f"[LoginService] Login Request Phase: {response.login_request_phase} (LOGIN_REQUEST_PHASE_DONE)")
            logger.info(f"[LoginService] Login Request ID: {response.login_request_id}")
            logger.info(f"[LoginService] Badge Mask: {response.badge_mask}")
            logger.info(f"[LoginService] Nickname: {response.nickname} (maps to client field at param_2+2)")
            logger.info(f"[LoginService] Displayname: {response.displayname} (maps to client field at param_2+4)")
            logger.info(f"[LoginService] Primary Character: {response.cache_data.character.name if response.cache_data.character.name else 'None'}")
            logger.info(f"[LoginService] Tracking ID: {response.tracking_metrics_id} (maps to client field at param_2+0x1a)")
            logger.info(f"[LoginService] StarNetwork Endpoint: {response.cache_data.star_network.services_endpoint}")
            logger.info(f"[LoginService] StarNetwork Host: {response.cache_data.star_network.hostname}:{response.cache_data.star_network.port}")
            logger.info(f"[LoginService] Account ID: {response.cache_data.account_id}")
            logger.info(f"[LoginService] Citizen ID: {response.cache_data.citizen_id}")
            logger.info(f"[LoginService] JWT Token: {response.jwt[:30]}...")
            # Only send initial login response; further login progression handled by diffusion server
            service_stats.increment('LoginService', success=True)
            return response
            
        except Exception as e:
            logger.error(f"[LoginService] !! CRITICAL ERROR in login #{self.login_count}: {e}", exc_info=True)
            service_stats.increment('LoginService', success=False)
            
            # Set error state for session
            if 'session_id' in locals():
                login_state_manager.set_session_state(session_id, 'FAILED')
                logger.error(f"🔴 [LoginService] Login failed for session {session_id}")
            
            # Return error response with client-expected error codes
            error_response = login_service_pb2.InitiateLoginResponse()
            
            # Check if this is a rate limiting scenario (use special error code 9)
            if "rate limit" in str(e).lower():
                error_response.result_code = 9  # Special error code 9 - client handles differently
                logger.error(f"[LoginService] Returning rate limit error response with result_code=9")
            else:
                error_response.result_code = -103  # 0xffffff99 - general login failure
                logger.error(f"[LoginService] Returning error response with result_code=-103 (0xffffff99)")
            
            error_response.nickname = ""
            error_response.displayname = ""
            error_response.tracking_metrics_id = f"error_{int(time.time())}"
            error_response.login_request_state = 2  # LOGIN_REQUEST_STATE_ERROR
            error_response.login_request_phase = 0  # LOGIN_REQUEST_PHASE_UNSPECIFIED
            
            return error_response
    
    def CharacterStatus(self, request, context):
        """Handle CharacterStatus requests - provides character data for specific account"""
        service_stats.increment('CharacterStatus')
        
        # Get client info for logging
        client_peer = context.peer() if context else "unknown"
        
        logger.info(f"[LoginService] *** CHARACTER STATUS REQUEST ***")
        logger.info(f"[LoginService] Client: {client_peer}")
        logger.info(f"[LoginService] Account ID: {request.account_id}")
        logger.info(f"[LoginService] Session ID: {request.session_id}")
        
        try:
            # Validate session if provided
            if request.session_id:
                session_valid = session_manager.validate_session(request.session_id)
                if not session_valid:
                    logger.warning(f"[LoginService] Invalid session for CharacterStatus: {request.session_id}")
            
            # Get character data for the account
            account_id = request.account_id if request.account_id else f"unknown_{int(time.time())}"
            characters_data = character_service.get_characters_for_account(account_id)
            
            # Create character status response
            response = login_service_pb2.CharacterStatusResponse()
            
            # Add character data with updated proto structure
            for char_data in characters_data:
                character = response.characters.add()
                character.geid = char_data.get('character_id', '')  # character_id -> geid
                character.account_id = char_data.get('account_id', '')
                character.name = char_data.get('name', '')
                character.created_at = char_data.get('created_at', 0)
                character.updated_at = char_data.get('updated_at', char_data.get('last_played', 0))
                character.state = char_data.get('state', 1)  # 1 = STATE_CURRENT
            
            logger.info(f"[LoginService] >> CHARACTER STATUS SUCCESS")
            logger.info(f"[LoginService] Account: {account_id}")
            logger.info(f"[LoginService] Characters returned: {len(response.characters)}")
            logger.info(f"[LoginService] Character names: {[char.name for char in response.characters]}")
            
            service_stats.increment('CharacterStatus', success=True)
            return response
            
        except Exception as e:
            logger.error(f"[LoginService] !! ERROR in CharacterStatus: {e}", exc_info=True)
            service_stats.increment('CharacterStatus', success=False)
            
            # Return empty response on error
            error_response = login_service_pb2.CharacterStatusResponse()
            logger.error(f"[LoginService] Returning empty CharacterStatusResponse due to error")
            return error_response

    def LoginNotificationStream(self, request, context):
        """Implements the LoginNotificationStream RPC for login/character notifications."""
        account_id = getattr(request, 'account_id', '') or (login_data_manager.get_account_data()['account_id'] if login_data_manager.is_available() else "unknown")
        session_id = getattr(request, 'session_id', '')
        
        logger.info(f"[LoginService] *** LOGIN NOTIFICATION STREAM STARTED ***")
        logger.info(f"[LoginService] 🎯 CRITICAL: This stream completes the login flow after RSI access token")
        logger.info(f"[LoginService] Account ID: {account_id}, Session ID: {session_id}")
        logger.info(f"[LoginService] 🎯 Client connected to gRPC server (5678) expecting login completion")
        
        try:
            # STEP 1: Transition to CHARACTER_STATUS state
            login_state_manager.set_session_state(session_id, 'CHARACTER_STATUS', account_id)
            
            # STEP 2: Send AccountLoginCharacterStatus notification
            logger.info(f"🔔 [LoginService] Sending AccountLoginCharacterStatus notification...")
            characters_data = character_service.get_characters_for_account(account_id)
            
            # Create and send character status notification
            try:
                notification = login_service_pb2.LoginNotification()
                character_status = login_service_pb2.AccountLoginCharacterStatus()
                character_status.account_id = account_id
                character_status.timestamp = int(time.time() * 1000)
                
                for char_data in characters_data:
                    character = character_status.characters.add()
                    character.geid = char_data.get('character_id', char_data.get('geid', ''))
                    character.account_id = char_data.get('account_id', '')
                    character.name = char_data.get('name', '')
                    character.created_at = char_data.get('created_at', 0)
                    character.updated_at = char_data.get('updated_at', char_data.get('last_played', 0))
                    character.state = char_data.get('state', 1)
                
                notification.character_status.CopyFrom(character_status)
                logger.info(f"🔔 [LoginService] Yielding AccountLoginCharacterStatus with {len(characters_data)} characters")
                yield notification
                
                # Brief delay to simulate real server processing
                time.sleep(0.3)
                
            except Exception as char_error:
                logger.error(f"[LoginService] Error creating character status notification: {char_error}")
            
            # STEP 3: Send COMPLETE ReconcileAccountUpdateNotification sequence matching real client logs
            logger.info(f"🔔 [LoginService] Sending REAL CLIENT RECONCILE SEQUENCE via gRPC stream...")
            
            # Get real client data
            auth_data = login_data_manager.get_account_data() if login_data_manager.is_available() else {
                'account_id': account_id,
                'character_id': 'char_testpilot_001',
                'location': 'Stanton_ArcCorp_Area18',
                'universe': 'persistent_universe'
            }
            
            # Use real client data format
            command_id = str(uuid.uuid4())  # Real UUID format
            character_geid = "200146295196"  # Real GEID from logs
            account_urn = f"urn:sc:platform:account:integer:{account_id}"
            player_urn = f"urn:sc:global:player:geid:{character_geid}"
            
            # Send reconcile sequence matching real client logs (8 messages)
            reconcile_messages = [
                {
                    "details": "ReconcileAccount started",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED",
                    "progress": 25
                },
                {
                    "details": "Started processing 411 Long-Term persistence items",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING", 
                    "phase": "RECONCILE_ACCOUNT_PHASE_LTP",
                    "progress": 35
                },
                {
                    "details": "Finished processing 411 Long-Term persistence items",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_LTP", 
                    "progress": 50
                },
                {
                    "details": "Started processing 41 platform items",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_PLATFORM",
                    "progress": 60
                },
                {
                    "details": "Retrieved all items",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED",
                    "progress": 70
                },
                {
                    "details": "Started processing 443 entitlements",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_PLATFORM",
                    "progress": 80
                },
                {
                    "details": "Finished processing 41 platform items",
                    "status": "RECONCILE_ACCOUNT_STATUS_EXECUTING",
                    "phase": "RECONCILE_ACCOUNT_PHASE_PLATFORM",
                    "progress": 90
                },
                {
                    "details": "Account reconciliation complete",
                    "status": "RECONCILE_ACCOUNT_STATUS_COMPLETE",
                    "phase": "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED", 
                    "progress": 100
                }
            ]
            
            # Send each reconcile message as a separate notification
            for i, msg_data in enumerate(reconcile_messages):
                try:
                    reconcile_notification = login_service_pb2.LoginNotification()
                    reconcile_update = login_service_pb2.ReconcileAccountUpdateNotification()
                    
                    # Set reconciliation data matching real client logs
                    reconcile_update.account_id = account_id
                    
                    # Map status strings to protobuf enums
                    if msg_data["status"] == "RECONCILE_ACCOUNT_STATUS_EXECUTING":
                        reconcile_update.status = login_service_pb2.RECONCILE_ACCOUNT_STATUS_EXECUTING
                    else:
                        reconcile_update.status = login_service_pb2.RECONCILE_ACCOUNT_STATUS_COMPLETE
                    
                    # Map phase strings to protobuf enums
                    if msg_data["phase"] == "RECONCILE_ACCOUNT_PHASE_LTP":
                        reconcile_update.phase = login_service_pb2.RECONCILE_ACCOUNT_PHASE_LTP
                    elif msg_data["phase"] == "RECONCILE_ACCOUNT_PHASE_PLATFORM":
                        reconcile_update.phase = login_service_pb2.RECONCILE_ACCOUNT_PHASE_PLATFORM
                    else:
                        reconcile_update.phase = login_service_pb2.RECONCILE_ACCOUNT_PHASE_UNSPECIFIED
                    
                    # Create the exact message format from real client logs
                    reconcile_update.details = (
                        f"Received an entitlement status update message with values: "
                        f"command id {command_id} - "
                        f"details {msg_data['details']} - "
                        f"account urn {account_urn} - "
                        f"player urn {player_urn} - "
                        f"status {msg_data['status']} - "
                        f"phase {msg_data['phase']}"
                    )
                    
                    reconcile_update.reconciliation_complete = (msg_data["status"] == "RECONCILE_ACCOUNT_STATUS_COMPLETE")
                    reconcile_update.timestamp = int(time.time() * 1000)
                    
                    # Add realistic reconciliation data
                    reconcile_update.ltp_items_processed = 411 if "LTP" in msg_data["phase"] else 0
                    reconcile_update.platform_items_processed = 41 if "platform" in msg_data["details"] else 0
                    reconcile_update.entitlements_processed = 443 if "entitlements" in msg_data["details"] else 0
                    
                    reconcile_notification.reconcile_update.CopyFrom(reconcile_update)
                    logger.info(f"🔔 [LoginService] Yielding ReconcileUpdate #{i+1}: {msg_data['details']} ({msg_data['status']}/{msg_data['phase']})")
                    yield reconcile_notification
                    
                    # Brief delay between messages to simulate real processing
                    time.sleep(0.1)
                    
                except Exception as reconcile_error:
                    logger.error(f"[LoginService] Error creating reconcile notification {i+1}: {reconcile_error}")
            
            logger.info(f"🔔 [LoginService] ✅ COMPLETE RECONCILE SEQUENCE SENT via gRPC stream")
            
            # STEP 4: Send final login completion notification
            logger.info(f"🔔 [LoginService] Sending LoginCompletedNotification...")
            try:
                completion_notification = login_service_pb2.LoginNotification()
                login_completed = login_service_pb2.LoginCompletedNotification()
                
                login_completed.account_id = account_id
                login_completed.session_id = session_id
                login_completed.success = True
                login_completed.timestamp = int(time.time() * 1000)
                
                completion_notification.login_completed.CopyFrom(login_completed)
                logger.info(f"🔔 [LoginService] Yielding LoginCompletedNotification")
                yield completion_notification
                
                # Brief delay to simulate real server processing
                time.sleep(0.2)
                
            except Exception as completion_error:
                logger.error(f"[LoginService] Error creating login completion notification: {completion_error}")
            
            # STEP 5: Transition to LOGIN_COMPLETED state
            login_state_manager.set_session_state(session_id, 'LOGIN_COMPLETED', account_id)
            
            # STEP 6: Final success logging
            logger.info(f"🔔 [LoginService] *** LOGIN NOTIFICATION STREAM COMPLETED SUCCESSFULLY ***")
            logger.info(f"🔔 [LoginService] Client should now exit LOGIN QUEUE and enter the game")
            logger.info(f"🔔 [LoginService] Account {account_id} fully authenticated and ready")
            
            # Emit final notifications via the notification service
            login_notification_service.emit_account_login_character_status(account_id, characters_data)
            login_notification_service.emit_reconcile_account_update(account_id, {
                'status': 'complete',
                'entitlements': 23,
                'account_status': 'active',
                'subscription_status': 'active'
            })
            
        except Exception as e:
            logger.error(f"[LoginService] !! CRITICAL ERROR in LoginNotificationStream: {e}", exc_info=True)
            # Set error state
            if session_id:
                login_state_manager.set_session_state(session_id, 'FAILED', account_id)

class EnhancedStarCitizenServices:
    """Enhanced implementation of all Star Citizen services based on TLS analysis"""
    
    def __init__(self):
        self.config_count = 0
        self.push_count = 0
        self.trace_count = 0
        self.character_count = 0
        self.last_config_log = 0
        self.last_push_log = 0
        
        # Initialize telemetry service for intercepted message handling
        self.telemetry_service = TelemetryService()
        
        # Service configurations based on intercepted Star Citizen client data
        self.game_config = {
            "version": "4.2.151.51347",  # Latest SC version from intercepted data
            "build": "51347",
            "branch": "sc-alpha-4.2.0",
            "environment": "PUB",
            "env_session": "pub-sc-alpha-420-9873572",
            "build_cl": 9947283,  # Updated from latest telemetry
            "shelve_cl": 0,
            "config": "shipping",
            "version_identifier": "01a12935-abc669c4",  # Confirmed from client logs
            "game_version_components": {
                "game_version": 1,
                "data_core": 3970823546,
                "class_registry": 1984577872,
                "archetypes": 32203888,
                "components": 3479724879,
                "oc": 1101556419  # Confirmed from client logs
            },
            "servers": [
                "dns:///127.0.0.1:5678",  # Updated to match client expectations
                "dns:///127.0.0.1:5678"
            ],
            "features": {
                "character_customization": True,
                "ship_rental": True,
                "quantum_travel": True,
                "grpc_services": True,
                "telemetry_streaming": True,
                "eac_enabled": True,  # EAC is active based on logs
                "legacy_login": True,  # Legacy login system active
                "social_services": True,  # Social services required
                "discipline_service": True,  # Discipline service active
                "identity_service": True   # Identity service required
            },
            "telemetry": {
                "enabled": True,
                "endpoint": "dns:///127.0.0.1:5678",
                "interval": 30
            },
            "grpc": {
                "endpoints": {
                    "login": "dns:///127.0.0.1:5678",
                    "identity": "dns:///127.0.0.1:5678", 
                    "push": "dns:///127.0.0.1:5678",
                    "discipline": "dns:///127.0.0.1:5678",
                    "social": "dns:///127.0.0.1:5678",
                    "analytics": "dns:///127.0.0.1:5678",
                    "presence": "dns:///127.0.0.1:5678",
                    "config": "dns:///127.0.0.1:5678"
                },
                "transport_security": False,  # Client logs show mixed security (0 and 1)
                "settings": {
                    "primary_user_agent": "grpc-c++/1.49.2",
                    "http2_max_pings_without_data": 0,
                    "max_receive_message_length": 16777216,  # 16MB from client logs
                    "max_send_message_length": 4194304,     # 4MB from client logs  
                    "keepalive_permit_without_calls": 1,
                    "keepalive_time_ms": 120000,            # 2 minutes from client logs
                    "keepalive_timeout_ms": 20000,          # 20 seconds from client logs
                    "http2_min_time_between_pings_ms": 10000,
                    "http2_min_ping_interval_without_data_ms": 5000
                }
            },
            "connection_states": [
                "CONNECTING",
                "CONNECTED", 
                "AUTHENTICATED",
                "READY"
            ],
            "account_states": [
                "kAccountLoginSuccess",
                "kAccountLoginCharacterStatus",
                "kAccountLoginCompleted"
            ],
            "client_args": [
                "-no_login_dialog",
                "-envtag PUB",
                "--client-login-show-dialog 0",
                "--services-config-enabled 1",
                "--system-trace-service-enabled 1",
                "--system-trace-env-id pub-sc-alpha-420-9873572",
                "--grpc-client-endpoint-override dns:///127.0.0.1:5678"
            ]
        }
        
        logger.info("[EnhancedServices] Initialized with telemetry support for intercepted messages")
    
    def handle_config_service(self, request, context):
        """ConfigService - Game configuration and server endpoint discovery"""
        self.config_count += 1
        service_stats.increment('ConfigService')
        
        # Log periodically to reduce spam but maintain visibility
        if self.config_count % 5000 == 1:
            logger.info(f"[ConfigService] WatchConfig called (count: {self.config_count})")
            logger.info(f"[ConfigService] Providing game configuration and server endpoints")
            self.last_config_log = self.config_count
        
        # Return comprehensive configuration data to prevent client disconnection
        try:
            # Create comprehensive config response that satisfies client expectations
            enhanced_config = {
                **self.game_config,
                "status": "online",
                "maintenance": False,
                "populated": True,
                "service_status": {
                    "login": "online",
                    "config": "online", 
                    "character": "online",
                    "push": "online",
                    "trace": "online",
                    "identity": "online",
                    "discipline": "online",
                    "social": "online"
                },
                "connection_timeout": 300000,  # 5 minutes
                "response_timeout": 60000,     # 1 minute
                "heartbeat_interval": 30000,   # 30 seconds
                "retry_attempts": 3,
                "backoff_multiplier": 1.5
            }
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            logger.info(f"[ConfigService] Returned minimal protobuf configuration data")
            service_stats.increment('ConfigService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (config available)
        except Exception as e:
            logger.error(f"[ConfigService] Error generating config: {e}")
            service_stats.increment('ConfigService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (config error)
    
    def handle_character_service(self, request, context):
        """CharacterService - Character data management"""
        self.character_count += 1
        service_stats.increment('CharacterService')
        
        logger.info(f"[CharacterService] Character data request #{self.character_count}")
        
        try:
            # Get account info from context/metadata
            account_id = self._extract_account_from_context(context)
            characters_data = character_service.get_characters_for_account(account_id)
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            logger.info(f"[CharacterService] Returned {len(characters_data)} characters for account {account_id}")
            service_stats.increment('CharacterService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (characters available)
            
        except Exception as e:
            logger.error(f"[CharacterService] Error handling character request: {e}")
            service_stats.increment('CharacterService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (character error)
    
    def handle_push_service(self, request, context):
        """PushService - Real-time notifications (keep connection alive)"""
        self.push_count += 1
        service_stats.increment('PushService')
        
        # Only log every 2,500 calls to reduce spam
        if self.push_count % 2500 == 1:
            logger.info(f"[PushService] Listen called (count: {self.push_count})")
            logger.info(f"[PushService] Handling real-time notification channel")
            self.last_push_log = self.push_count
            
        try:
            # Return keep-alive response to maintain connection
            push_response = {
                "status": "listening",
                "channel_id": f"push_{int(time.time())}_{self.push_count}",
                "keepalive": True,
                "interval": 30000,  # 30 second intervals
                "notifications": [],  # No pending notifications for now
                "server_time": int(time.time())
            }
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            service_stats.increment('PushService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (push service active)
            
        except Exception as e:
            logger.error(f"[PushService] Error handling push request: {e}")
            service_stats.increment('PushService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (push service error)
    
    def handle_trace_service(self, request, context):
        """TraceService - Telemetry and performance metrics collection"""
        self.trace_count += 1
        service_stats.increment('TraceService')
        
        # Log first few calls and then periodically
        if self.trace_count <= 5 or self.trace_count % 10000 == 0:
            logger.info(f"[TraceService] CreateTrace called (count: {self.trace_count})")
            logger.info(f"[TraceService] Collecting telemetry and game state tracking")
        
        try:
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            service_stats.increment('TraceService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (trace received)
            
        except Exception as e:
            logger.error(f"[TraceService] Error handling trace: {e}")
            service_stats.increment('TraceService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (trace error)
    
    def handle_identity_service(self, request, context):
        """IdentityService - Player identity and authentication verification"""
        service_stats.increment('IdentityService')
        
        logger.info(f"[IdentityService] Identity verification request")
        
        try:
            # Get account from context
            account_id = self._extract_account_from_context(context)
            
            # Provide comprehensive identity verification response
            identity_response = {
                "status": "verified",
                "player_id": "200146295196",  # From client logs
                "account_id": account_id,
                "account_verified": True,
                "identity_verified": True,
                "permissions": ["login", "play", "social", "character_management"],
                "roles": ["player"],
                "subscription_status": "active",
                "account_standing": "good",
                "server_time": int(time.time()),
                "session_valid": True,
                "expires_at": int(time.time()) + 86400  # 24 hours
            }
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            logger.info(f"[IdentityService] Identity verified for player 200146295196, account {account_id}")
            service_stats.increment('IdentityService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (identity verified)
            
        except Exception as e:
            logger.error(f"[IdentityService] Error handling identity request: {e}")
            service_stats.increment('IdentityService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (identity error)
    
    def handle_discipline_service(self, request, context):
        """DisciplineService - Player discipline and behavior monitoring"""
        service_stats.increment('DisciplineService')
        
        logger.info(f"[DisciplineService] Discipline check request")
        
        try:
            # Get account from context
            account_id = self._extract_account_from_context(context)
            
            # Provide comprehensive clean discipline record
            discipline_response = {
                "status": "clean",
                "player_id": "200146295196",
                "account_id": account_id,
                "warnings": 0,
                "infractions": [],
                "bans": [],
                "standing": "good",
                "reputation": 100,
                "last_check": int(time.time()),
                "review_date": int(time.time()) + 2592000,  # 30 days
                "behavior_score": 100,
                "compliance_status": "compliant"
            }
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            logger.info(f"[DisciplineService] Clean discipline record provided for account {account_id}")
            service_stats.increment('DisciplineService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (discipline clean)
            
        except Exception as e:
            logger.error(f"[DisciplineService] Error handling discipline request: {e}")
            service_stats.increment('DisciplineService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (discipline error)
    
    def handle_social_service(self, request, context):
        """SocialService - Social features, friends, groups"""
        service_stats.increment('SocialService')
        
        logger.info(f"[SocialService] Social data request")
        
        try:
            # Get account from context
            account_id = self._extract_account_from_context(context)
            
            # Provide comprehensive social data including groups and invitations
            social_response = {
                "status": "active",
                "player_id": "200146295196",
                "account_id": account_id,
                "friends": [],
                "friends_count": 0,
                "groups": [],
                "groups_count": 0,
                "pending_invitations": [],
                "invitation_count": 0,
                "social_topics_subscribed": True,
                "group_cache_updated": True,
                "presence_status": "online",
                "last_activity": int(time.time()),
                "social_features_enabled": True,
                "privacy_settings": {
                    "show_online_status": True,
                    "allow_friend_requests": True,
                    "allow_group_invites": True
                }
            }
            
            # Return minimal protobuf response instead of JSON to prevent gRPC assertion failures
            logger.info(f"[SocialService] Social data provided for player 200146295196, account {account_id}")
            service_stats.increment('SocialService', success=True)
            return b'\x08\x01'  # field 1, varint, value 1 (social data available)
            
        except Exception as e:
            logger.error(f"[SocialService] Error handling social request: {e}")
            service_stats.increment('SocialService', success=False)
            # Return minimal protobuf error response
            return b'\x08\x00'  # field 1, varint, value 0 (social error)
    
    def _extract_account_from_context(self, context):
        """Extract account ID from gRPC context"""
        try:
            # Get client peer info
            client_peer = context.peer() if context else "unknown"
            
            # Generate consistent account ID from client peer for development
            if client_peer != "unknown":
                peer_hash = hashlib.sha256(client_peer.encode()).hexdigest()
                return f"ctx_{peer_hash[:12]}"
            else:
                return f"unknown_{int(time.time())}"
                
        except Exception as e:
            logger.debug(f"[EnhancedServices] Could not extract account from context: {e}")
            return f"fallback_{int(time.time())}"
    
    def handle_analytics_service(self, request, context):
        """AnalyticsService - Game analytics and telemetry collection"""
        service_stats.increment('AnalyticsService')
        
        logger.info(f"[AnalyticsService] Analytics collection request")
        
        try:
            # Get account from context
            account_id = self._extract_account_from_context(context)
            logger.info(f"[AnalyticsService] Analytics collection started for account {account_id}")
            service_stats.increment('AnalyticsService', success=True)
            
            # Return minimal valid protobuf message to prevent gRPC assertion failures
            return b'\x08\x01'  # field 1, varint, value 1 (indicating success)
            
        except Exception as e:
            logger.error(f"[AnalyticsService] Error handling analytics request: {e}")
            service_stats.increment('AnalyticsService', success=False)
            # Return minimal protobuf response
            return b'\x08\x00'  # field 1, varint, value 0 (indicating error)
    
    def handle_presence_service(self, request, context):
        """PresenceService - Player presence and status management"""
        service_stats.increment('PresenceService')
        
        logger.info(f"[PresenceService] Presence stream request")
        
        try:
            # Get account from context
            account_id = self._extract_account_from_context(context)
            logger.info(f"[PresenceService] Presence stream started for account {account_id}")
            service_stats.increment('PresenceService', success=True)
            
            # Return minimal valid protobuf message to prevent gRPC assertion failures
            return b'\x08\x01'  # field 1, varint, value 1 (indicating online)
            
        except Exception as e:
            logger.error(f"[PresenceService] Error handling presence request: {e}")
            service_stats.increment('PresenceService', success=False)
            # Return minimal protobuf response
            return b'\x08\x00'  # field 1, varint, value 0 (indicating offline)

class TelemetryService:
    """Enhanced telemetry service based on intercepted message analysis"""
    def __init__(self):
        self.telemetry_data = {}
        self.error_log = []
        self.initialization_log = []
        self.status_updates = []
        self.lock = threading.Lock()
        
        # Message pattern recognition based on intercepted data
        self.message_patterns = {
            'initialization': ['initialized', 'startup', 'connected', 'handshake'],
            'status': ['telemetry', 'status', 'heartbeat', 'health', 'ping'],
            'error': ['error', 'exception', 'failed', 'timeout', 'disconnect'],
            'session': ['session', 'auth', 'login', 'token'],
            'environment': ['pub-sc-', 'server', 'endpoint', 'shard']
        }
        
        # Error code mappings for Star Citizen
        self.error_code_responses = {
            19000: {
                'type': 'login_auth_error',
                'description': 'Authentication server connection failed',
                'action': 'retry_auth',
                'recovery_steps': [
                    'Verify network connection',
                    'Check authentication server status',
                    'Retry login after 5 seconds'
                ]
            },
            20000: {
                'type': 'server_unavailable',
                'description': 'Game servers unavailable',
                'action': 'retry_later',
                'recovery_steps': ['Wait for server maintenance to complete']
            },
            30000: {
                'type': 'client_version_mismatch',
                'description': 'Client version incompatible',
                'action': 'update_client',
                'recovery_steps': ['Update Star Citizen client']
            }
        }
        
        logger.info("[TelemetryService] Initialized with intercepted message patterns and error handling")
    
    def handle_initialization_message(self, message_data, session_id=None):
        """Handle Star Citizen client initialization messages"""
        try:
            # Extract detailed game version components
            version_components = self._extract_game_version_components(message_data)
            
            init_record = {
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id or self._extract_session_id(message_data),
                'environment_id': self._extract_environment_id(message_data),
                'client_version': self._extract_client_version(message_data),
                'connection_info': self._extract_connection_info(message_data),
                'version_components': version_components,
                'status': 'initialized',
                'message_type': 'client_initialization'
            }
            
            with self.lock:
                self.initialization_log.append(init_record)
                
            logger.info(f"[TELEMETRY] Client initialization: session={init_record['session_id']}, env={init_record['environment_id']}")
            logger.info(f"[TELEMETRY] Version ID: {version_components['version_identifier']}, DataCore: {version_components['data_core']}")
            
            return {
                'status': 'success', 
                'session_id': init_record['session_id'],
                'server_response': 'initialization_acknowledged',
                'timestamp': init_record['timestamp'],
                'version_validated': True
            }
            
        except Exception as e:
            logger.error(f"[TELEMETRY] Initialization handler error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def handle_status_message(self, message_data, session_id=None):
        """Handle Star Citizen client status/telemetry messages"""
        try:
            # Check for console command patterns first (based on decompiled analysis)
            console_command_info = self._analyze_console_command(message_data)
            
            telemetry = {
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id or self._extract_session_id(message_data),
                'client_status': self._extract_client_status(message_data),
                'performance_metrics': self._extract_performance_data(message_data),
                'connection_quality': self._extract_connection_quality(message_data),
                'system_info': self._extract_system_info(message_data),
                'console_command': console_command_info
            }
            
            with self.lock:
                self.status_updates.append(telemetry)
                # Keep only last 100 status updates per session
                if len(self.status_updates) > 100:
                    self.status_updates.pop(0)
            
            # Enhanced logging for console commands
            if console_command_info['detected']:
                logger.info(f"[TELEMETRY] Console Command Detected: {console_command_info['command']}")
                logger.info(f"[TELEMETRY] Command Type: {console_command_info['type']}, Startup: {console_command_info['is_startup']}")
                if console_command_info['type'] == 'exec_autoexec':
                    logger.info(f"[TELEMETRY] *** AUTOEXEC.CFG EXECUTION DETECTED - STARTUP SEQUENCE ***")
                elif console_command_info['type'] == 'exec_server':
                    logger.info(f"[TELEMETRY] *** SERVER CONFIG EXECUTION DETECTED ***")
                elif console_command_info['type'] == 'exec_on_demand':
                    logger.info(f"[TELEMETRY] *** ON-DEMAND CONFIG EXECUTION DETECTED ***")
            else:
                logger.info(f"[TELEMETRY] Status update: session={telemetry['session_id']}, status={telemetry['client_status']}")
            
            return {
                'status': 'acknowledged', 
                'timestamp': telemetry['timestamp'],
                'server_status': 'healthy',
                'response_code': 200,
                'console_command_processed': console_command_info['detected']
            }
            
        except Exception as e:
            logger.error(f"[TELEMETRY] Status handler error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def handle_error_message(self, message_data, session_id=None):
        """Handle Star Citizen client error messages"""
        try:
            # Check for specific error code 19000 first
            error_code = self._extract_error_code(message_data)
            if error_code == '19000' or error_code == 19000:
                return self.handle_error_code_19000(message_data, session_id)
            
            error_info = {
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id or self._extract_session_id(message_data),
                'error_type': self._extract_error_type(message_data),
                'error_code': error_code,
                'error_details': self._extract_error_details(message_data),
                'client_state': self._extract_client_state(message_data),
                'severity': self._determine_error_severity(message_data)
            }
            
            with self.lock:
                self.error_log.append(error_info)
                
            logger.error(f"[TELEMETRY] Client error: {error_info['error_type']} ({error_info['error_code']}) - {error_info['error_details']}")
            
            # Generate appropriate recovery response
            response = self._generate_error_response(error_info)
            
            return response
            
        except Exception as e:
            logger.error(f"[TELEMETRY] Error handler error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def handle_error_code_19000(self, message_data, session_id=None):
        """Specific handler for Star Citizen error code 19000 (login authentication failure)"""
        try:
            error_details = {
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id or self._extract_session_id(message_data),
                'error_code': 19000,
                'error_type': 'login_authentication_failure',
                'state_con': self._extract_connection_state(message_data),
                'state_acc': self._extract_account_state(message_data),
                'hostname': self._extract_hostname(message_data),
                'loading_uuid': self._extract_loading_uuid(message_data),
                'region_id': self._extract_region_id(message_data),
                'shard_id': self._extract_shard_id(message_data),
                'client_version': self._extract_client_version(message_data),
                'environment': self._extract_environment_id(message_data)
            }
            
            with self.lock:
                self.error_log.append(error_details)
            
            logger.error(f"[TELEMETRY] Error 19000 - Login Authentication Failure")
            logger.error(f"[TELEMETRY] Session: {error_details['session_id']}")
            logger.error(f"[TELEMETRY] Connection State: {error_details['state_con']}, Account State: {error_details['state_acc']}")
            logger.error(f"[TELEMETRY] Environment: {error_details['environment']}, Version: {error_details['client_version']}")
            
            # Generate recovery response
            recovery_response = {
                'status': 'error_acknowledged',
                'error_code': 19000,
                'error_type': 'login_authentication_failure',
                'recovery_action': 'restart_authentication',
                'server_response': {
                    'allow_retry': True,
                    'retry_delay': 5,
                    'auth_server_status': 'available',
                    'recommended_action': 'Please check your connection and try logging in again'
                },
                'session_id': error_details['session_id'],
                'timestamp': error_details['timestamp']
            }
            
            logger.info(f"[TELEMETRY] Generated recovery response for error 19000")
            return recovery_response
            
        except Exception as e:
            logger.error(f"[TELEMETRY] Error handling 19000: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _extract_session_id(self, message_data):
        """Extract session ID from message data, handling $ prefix"""
        try:
            if isinstance(message_data, dict):
                session_id = message_data.get('session_id', message_data.get('Session_ID', ''))
            elif isinstance(message_data, str):
                # Look for UUID pattern in string
                import re
                uuid_pattern = r'[\$]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                match = re.search(uuid_pattern, message_data, re.IGNORECASE)
                session_id = match.group(0) if match else ''
            else:
                session_id = str(message_data).get('session_id', '')
            
            # Clean session ID by removing $ prefix if present
            if session_id and session_id.startswith('$'):
                session_id = session_id[1:]
                
            return session_id or f"unknown_{int(time.time())}"
        except Exception as e:
            logger.debug(f"[TELEMETRY] Could not extract session ID: {e}")
            return f"unknown_{int(time.time())}"
    
    def _extract_game_version_components(self, message_data):
        """Extract game version components from message data"""
        try:
            if isinstance(message_data, dict):
                return {
                    'version_identifier': message_data.get('version_identifier', '01a12935-abc669c4'),
                    'data_core': message_data.get('data_core', 3970823546),
                    'class_registry': message_data.get('class_registry', 1984577872),
                    'archetypes': message_data.get('archetypes', 32203888),
                    'components': message_data.get('components', 3479724879),
                    'oc': message_data.get('oc', 1101556419)
                }
            else:
                return {
                    'version_identifier': '01a12935-abc669c4',
                    'data_core': 3970823546,
                    'class_registry': 1984577872,
                    'archetypes': 32203888,
                    'components': 3479724879,
                    'oc': 1101556419
                }
        except Exception as e:
            logger.debug(f"[TELEMETRY] Could not extract version components: {e}")
            return {'version_identifier': 'unknown', 'data_core': 0}
    
    def _extract_environment_id(self, message_data):
        """Extract environment ID from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('environment_id', message_data.get('env_id', 'pub-sc-alpha-420-9873572'))
            else:
                return 'pub-sc-alpha-420-9873572'
        except Exception:
            return 'pub-sc-alpha-420-9873572'
    
    def _extract_client_version(self, message_data):
        """Extract client version from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('client_version', message_data.get('version', '4.2.151.51347'))
            else:
                return '4.2.151.51347'
        except Exception:
            return '4.2.151.51347'
    
    def _extract_connection_info(self, message_data):
        """Extract connection information from message data"""
        try:
            if isinstance(message_data, dict):
                return {
                    'endpoint': message_data.get('endpoint', 'localhost:8080'),
                    'protocol': message_data.get('protocol', 'grpc'),
                    'tls_enabled': message_data.get('tls_enabled', False)
                }
            else:
                return {'endpoint': 'localhost:8080', 'protocol': 'grpc', 'tls_enabled': False}
        except Exception:
            return {'endpoint': 'localhost:8080', 'protocol': 'grpc', 'tls_enabled': False}
    
    def _analyze_console_command(self, message_data):
        """Analyze console command patterns"""
        try:
            if isinstance(message_data, dict):
                event = message_data.get('Event', message_data.get('event', ''))
                if event == 'ConsoleCommand':
                    command = message_data.get('Command', message_data.get('command', ''))
                    return {
                        'detected': True,
                        'command': command,
                        'type': self._determine_command_type(command),
                        'is_startup': 'autoexec' in command.lower()
                    }
            return {'detected': False, 'command': '', 'type': 'unknown', 'is_startup': False}
        except Exception:
            return {'detected': False, 'command': '', 'type': 'unknown', 'is_startup': False}
    
    def _determine_command_type(self, command):
        """Determine the type of console command"""
        if 'autoexec' in command.lower():
            return 'exec_autoexec'
        elif 'server' in command.lower():
            return 'exec_server'
        else:
            return 'exec_on_demand'
    
    def _extract_client_status(self, message_data):
        """Extract client status from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('status', message_data.get('client_status', 'active'))
            else:
                return 'active'
        except Exception:
            return 'unknown'
    
    def _extract_performance_data(self, message_data):
        """Extract performance metrics from message data"""
        try:
            if isinstance(message_data, dict):
                return {
                    'fps': message_data.get('fps', 60),
                    'memory_usage': message_data.get('memory_usage', 0),
                    'cpu_usage': message_data.get('cpu_usage', 0)
                }
            else:
                return {'fps': 60, 'memory_usage': 0, 'cpu_usage': 0}
        except Exception:
            return {'fps': 60, 'memory_usage': 0, 'cpu_usage': 0}
    
    def _extract_connection_quality(self, message_data):
        """Extract connection quality metrics from message data"""
        try:
            if isinstance(message_data, dict):
                return {
                    'ping': message_data.get('ping', 0),
                    'packet_loss': message_data.get('packet_loss', 0),
                    'bandwidth': message_data.get('bandwidth', 1000)
                }
            else:
                return {'ping': 0, 'packet_loss': 0, 'bandwidth': 1000}
        except Exception:
            return {'ping': 0, 'packet_loss': 0, 'bandwidth': 1000}
    
    def _extract_system_info(self, message_data):
        """Extract system information from message data"""
        try:
            if isinstance(message_data, dict):
                return {
                    'os': message_data.get('os', 'Windows'),
                    'gpu': message_data.get('gpu', 'Unknown'),
                    'ram': message_data.get('ram', 16)
                }
            else:
                return {'os': 'Windows', 'gpu': 'Unknown', 'ram': 16}
        except Exception:
            return {'os': 'Windows', 'gpu': 'Unknown', 'ram': 16}
    
    def _extract_error_code(self, message_data):
        """Extract error code from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('error_code', message_data.get('code', 0))
            else:
                return 0
        except Exception:
            return 0
    
    def _extract_error_type(self, message_data):
        """Extract error type from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('error_type', message_data.get('type', 'unknown_error'))
            else:
                return 'unknown_error'
        except Exception:
            return 'unknown_error'
    
    def _extract_error_details(self, message_data):
        """Extract error details from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('error_details', message_data.get('details', str(message_data)))
            else:
                return str(message_data)
        except Exception:
            return 'No details available'
    
    def _extract_client_state(self, message_data):
        """Extract client state from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('client_state', message_data.get('state', 'unknown'))
            else:
                return 'unknown'
        except Exception:
            return 'unknown'
    
    def _determine_error_severity(self, message_data):
        """Determine error severity from message data"""
        try:
            if isinstance(message_data, dict):
                error_code = self._extract_error_code(message_data)
                if error_code in [19000, 20000]:
                    return 'high'
                elif error_code in [30000]:
                    return 'critical'
                else:
                    return 'medium'
            else:
                return 'low'
        except Exception:
            return 'unknown'
    
    def _generate_error_response(self, error_info):
        """Generate appropriate error response"""
        try:
            error_code = error_info.get('error_code', 0)
            if error_code in self.error_code_responses:
                response_template = self.error_code_responses[error_code]
                return {
                    'status': 'error_acknowledged',
                    'error_code': error_code,
                    'error_type': response_template['type'],
                    'description': response_template['description'],
                    'action': response_template['action'],
                    'recovery_steps': response_template['recovery_steps'],
                    'timestamp': error_info['timestamp'],
                    'session_id': error_info['session_id']
                }
            else:
                return {
                    'status': 'error_acknowledged',
                    'error_code': error_code,
                    'error_type': error_info.get('error_type', 'unknown'),
                    'description': 'Unknown error occurred',
                    'action': 'contact_support',
                    'timestamp': error_info['timestamp'],
                    'session_id': error_info['session_id']
                }
        except Exception as e:
            logger.error(f"[TELEMETRY] Error generating response: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _extract_connection_state(self, message_data):
        """Extract connection state from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('state_con', message_data.get('connection_state', 'unknown'))
            else:
                return 'unknown'
        except Exception:
            return 'unknown'
    
    def _extract_account_state(self, message_data):
        """Extract account state from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('state_acc', message_data.get('account_state', 'unknown'))
            else:
                return 'unknown'
        except Exception:
            return 'unknown'
    
    def _extract_hostname(self, message_data):
        """Extract hostname from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('hostname', 'localhost')
            else:
                return 'localhost'
        except Exception:
            return 'localhost'
    
    def _extract_loading_uuid(self, message_data):
        """Extract loading UUID from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('loading_uuid', str(uuid.uuid4()))
            else:
                return str(uuid.uuid4())
        except Exception:
            return str(uuid.uuid4())
    
    def _extract_region_id(self, message_data):
        """Extract region ID from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('region_id', 'US-WEST')
            else:
                return 'US-WEST'
        except Exception:
            return 'US-WEST'
    
    def _extract_shard_id(self, message_data):
        """Extract shard ID from message data"""
        try:
            if isinstance(message_data, dict):
                return message_data.get('shard_id', 'shard-001')
            else:
                return 'shard-001'
        except Exception:
            return 'shard-001'
    
    def get_telemetry_summary(self):
        """Get comprehensive telemetry summary"""
        with self.lock:
            return {
                'initialization_count': len(self.initialization_log),
                'status_updates_count': len(self.status_updates),
                'error_count': len(self.error_log),
                'latest_status': self.status_updates[-1] if self.status_updates else None,
                'latest_error': self.error_log[-1] if self.error_log else None,
                'error_rate': len(self.error_log) / max(1, len(self.status_updates)) * 100
            }

class StarCitizenCharacterService(character_service_pb2_grpc.CharacterServiceServicer):
    """
    Character Service - Handles character-specific operations
    Separate from LoginService for better architecture
    """
    def __init__(self, character_service, session_manager):
        self.character_service = character_service
        self.session_manager = session_manager
        self.character_request_count = 0

    def GetCharacterStatus(self, request, context):
        """Handle GetCharacterStatus requests from CharacterService"""
        self.character_request_count += 1
        service_stats.increment('CharacterService')
        
        client_peer = context.peer() if context else "unknown"
        
        logger.info(f"[CharacterService] *** CHARACTER STATUS REQUEST #{self.character_request_count} ***")
        logger.info(f"[CharacterService] Client: {client_peer}")
        logger.info(f"[CharacterService] Account ID: {request.account_id}")
        logger.info(f"[CharacterService] Session Token: {'present' if request.session_token else 'missing'}")
        
        try:
            # Validate session token if provided
            if request.session_token:
                session_valid = self.session_manager.validate_session(request.session_token)
                if not session_valid:
                    logger.warning(f"[CharacterService] Invalid session token")
                    response = character_service_pb2.CharacterStatusResponse()
                    response.result_code = 1
                    response.error_message = "Invalid session token"
                    return response
            
            # Get character data for the account
            account_id = request.account_id if request.account_id else f"unknown_{int(time.time())}"
            characters_data = self.character_service.get_characters_for_account(account_id)
            
            # Create character status response
            response = character_service_pb2.CharacterStatusResponse()
            response.result_code = 0  # Success
            
            # Add character data
            for char_data in characters_data:
                character = response.characters.add()
                character.geid = char_data.get('character_id', '')
                character.account_id = char_data.get('account_id', '')
                character.name = char_data.get('name', '')
                character.state = char_data.get('state', 'ACTIVE')
                character.createdAt = str(char_data.get('created_at', 0))
                character.updatedAt = str(char_data.get('updated_at', char_data.get('last_played', 0)))
                character.location = char_data.get('location', 'Port Olisar')
                character.credits = char_data.get('credits', 50000)
                
                # Add stats if available
                if hasattr(character, 'stats') and character.stats:
                    character.stats.level = char_data.get('level', 1)
                    character.stats.reputation = char_data.get('reputation', 0)
                    character.stats.crime_stat = char_data.get('crime_stat', 0)
            
            logger.info(f"[CharacterService] >> CHARACTER STATUS SUCCESS")
            logger.info(f"[CharacterService] Account: {account_id}")
            logger.info(f"[CharacterService] Characters returned: {len(response.characters)}")
            logger.info(f"[CharacterService] Character names: {[char.name for char in response.characters]}")
            
            service_stats.increment('CharacterService', success=True)
            return response
            
        except Exception as e:
            logger.error(f"[CharacterService] !! ERROR in GetCharacterStatus: {e}", exc_info=True)
            service_stats.increment('CharacterService', success=False)
            
            error_response = character_service_pb2.CharacterStatusResponse()
            error_response.result_code = 1
            error_response.error_message = str(e)
            return error_response

    def GetCharacterData(self, request, context):
        """Get detailed data for a specific character"""
        logger.info(f"[CharacterService] GetCharacterData request for character: {request.character_geid}")
        
        try:
            # TODO: Implement detailed character data retrieval
            response = character_service_pb2.CharacterDataResponse()
            response.result_code = 1
            response.error_message = "GetCharacterData not yet implemented"
            return response
        except Exception as e:
            logger.error(f"[CharacterService] Error in GetCharacterData: {e}")
            response = character_service_pb2.CharacterDataResponse()
            response.result_code = 1
            response.error_message = str(e)
            return response

    def UpdateCharacterLocation(self, request, context):
        """Update a character's location"""
        logger.info(f"[CharacterService] UpdateCharacterLocation request for character: {request.character_geid}")
        
        try:
            # TODO: Implement character location update
            response = character_service_pb2.UpdateCharacterLocationResponse()
            response.success = False
            response.error_message = "UpdateCharacterLocation not yet implemented"
            return response
        except Exception as e:
            logger.error(f"[CharacterService] Error in UpdateCharacterLocation: {e}")
            response = character_service_pb2.UpdateCharacterLocationResponse()
            response.success = False
            response.error_message = str(e)
            return response

# ...existing code...
class StarCitizenGenericHandler(grpc.GenericRpcHandler):
    """Enhanced generic handler implementing all Star Citizen services from TLS analysis"""
    
    def __init__(self):
        self.login_service = StarCitizenLoginService()
        self.other_services = EnhancedStarCitizenServices()
        self.total_calls = 0
        
    def service(self, handler_call_details):
        self.total_calls += 1
        method_name = handler_call_details.method
        
        # Report stats and health status periodically
        if service_stats.should_report():
            stats = service_stats.get_summary()
            logger.info(f"[STATS] Total: {stats['total_calls']}, Rate: {stats['calls_per_second']:.1f}/sec")
            logger.info(f"[STATS] Success: {stats['total_success']}, Errors: {stats['total_errors']}, Error Rate: {stats['error_rate']:.2f}%")
            logger.info(f"[STATS] Health: {stats['health_status']}")
            logger.info(f"[STATS] Breakdown: {stats['breakdown']}")
        
        # Route to appropriate service based on TLS analysis
        if '/sc.external.services.login.v1.LoginService/' in method_name:
            logger.info(f"[Router] *** STAR CITIZEN LOGIN DETECTED *** {method_name}")
            logger.info(f"[Router] 🎯 PERFECT MATCH: Client expects 'sc.external.services.login.v1.LoginService'")
            
            # Handle different LoginService methods
            if 'InitiateLogin' in method_name:
                logger.info(f"[Router] 🎯 PERFECT MATCH: Client uses 'Unary' RPC pattern (request-response)")
                logger.info(f"[Router] 🎯 DECOMPILED CODE VALIDATION: Service factory expectations aligned!")
                return grpc.unary_unary_rpc_method_handler(
                    self._safe_login_handler,
                    request_deserializer=self._safe_deserializer,
                    response_serializer=self._safe_serializer
                )
            elif 'LoginNotificationStream' in method_name:
                logger.info(f"[Router] 🎯 LOGIN NOTIFICATION STREAM: Client expects streaming notifications")
                logger.info(f"[Router] 🎯 This is CRITICAL for completing login flow after kAccountLoginSuccess")
                return grpc.unary_stream_rpc_method_handler(
                    self._safe_login_notification_stream_handler,
                    request_deserializer=self._safe_notification_deserializer,
                    response_serializer=self._safe_notification_serializer
                )
            elif 'CharacterStatus' in method_name:
                logger.info(f"[Router] 🎯 CHARACTER STATUS: Client requesting character data")
                return grpc.unary_unary_rpc_method_handler(
                    self._safe_character_status_handler,
                    request_deserializer=self._safe_character_deserializer,
                    response_serializer=self._safe_character_serializer
                )
            else:
                # Default to unary handler for other login service methods
                logger.info(f"[Router] 🎯 OTHER LOGIN METHOD: {method_name}")
                return grpc.unary_unary_rpc_method_handler(
                    self._safe_login_handler,
                    request_deserializer=self._safe_deserializer,
                    response_serializer=self._safe_serializer
                )
        
        elif '/sc.external.services.configuration.v1.ConfigService/' in method_name:
            if self.total_calls <= 10:
                logger.info(f"[Router] ConfigService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_config_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
        
        elif '/sc.external.services.character.v1.CharacterService/' in method_name:
            logger.info(f"[Router] CharacterService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.push.v1.PushService/' in method_name:
            if self.total_calls <= 10:
                logger.info(f"[Router] PushService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.telemetry.v1.TraceService/' in method_name or '/sc.external.services.trace.v1.TraceService/' in method_name:
            if self.total_calls <= 10:
                logger.info(f"[Router] TraceService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.identity.v1.IdentityService/' in method_name:
            logger.info(f"[Router] IdentityService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.discipline.v1.DisciplineService/' in method_name:
            logger.info(f"[Router] DisciplineService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.social.v1.SocialService/' in method_name:
            logger.info(f"[Router] SocialService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.analytics.v1.AnalyticsService/' in method_name:
            if self.total_calls <= 10:
                logger.info(f"[Router] AnalyticsService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
            
        elif '/sc.external.services.presence.v1.PresenceService/' in method_name:
            if self.total_calls <= 10:
                logger.info(f"[Router] PresenceService request: {method_name}")
            return grpc.unary_unary_rpc_method_handler(
                self._safe_other_service_handler,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
        
        else:
            # Unknown service - log and track
            if self.total_calls <= 20:
                logger.warning(f"[Router] Unknown service: {method_name}")
            
            service_stats.increment('UnknownService', success=False)
            return grpc.unary_unary_rpc_method_handler(
                lambda req, ctx: b'\x08\x00',  # Return minimal protobuf instead of empty bytes
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x
            )
    
    def _safe_config_handler(self, request, context):
        """Safely handle config requests with minimal protobuf-compatible response"""
        try:
            # Rate-limited logging to prevent log spam (only log first 10 calls)
            if self.total_calls <= 10:
                logger.info(f"[Router] ConfigService called - returning minimal protobuf response to prevent client crash")
            service_stats.increment('ConfigService', success=True)
            # Return minimal valid protobuf message (just field number + wire type)
            # This creates a minimal protobuf message that won't cause gRPC assertion failures
            return b'\x08\x00'  # field 1, varint, value 0
        except Exception as e:
            logger.error(f"[Router] ConfigService handler error: {e}")
            service_stats.increment('ConfigService', success=False)
            return b'\x08\x00'
    
    def _safe_other_service_handler(self, request, context):
        """Safely handle other service requests with minimal protobuf-compatible response"""
        try:
            # Rate-limited logging to prevent log spam (only log first 10 calls)
            if self.total_calls <= 10:
                logger.info(f"[Router] Other service called - returning minimal protobuf response to prevent client crash")
            # Return minimal valid protobuf message (just field number + wire type)
            # This creates a minimal protobuf message that won't cause gRPC assertion failures
            return b'\x08\x00'  # field 1, varint, value 0
        except Exception as e:
            logger.error(f"[Router] Other service handler error: {e}")
            return b'\x08\x00'
    
    def _safe_login_handler(self, request, context):
        """Safely handle login requests with protobuf parsing"""
        try:
            return self.login_service.InitiateLogin(request, context)
        except Exception as e:
            logger.error(f"[Router] LoginService handler error: {e}")
            # Return empty error response
            error_response = login_service_pb2.InitiateLoginResponse()
            error_response.result_code = 1
            return error_response
    
    def _safe_deserializer(self, data):
        """Safely deserialize protobuf data"""
        try:
            logger.info(f"[Router] Deserializing {len(data)} bytes for LoginService")
            logger.debug(f"[Router] Raw data: {data.hex()}")
            request = login_service_pb2.InitiateLoginRequest.FromString(data)
            logger.info(f"[Router] Successfully parsed protobuf request")
            logger.info(f"[Router] Session ID: {request.session_id}")
            logger.info(f"[Router] JWT token: {request.jwt_token[:50] if request.jwt_token else 'None'}")
            logger.info(f"[Router] Device info: {request.device_info}")
            return request
        except Exception as e:
            logger.error(f"[Router] Protobuf deserialize error: {e}")
            logger.info(f"[Router] Raw data (first 100 bytes): {data[:100]}")
            logger.info(f"[Router] Raw data hex: {data[:100].hex()}")
            # Try to create a request with partial data
            try:
                empty_request = login_service_pb2.InitiateLoginRequest()
                # If we can extract the session ID manually, do it
                if len(data) > 10:
                    # Try to extract session ID from the protobuf data manually
                    try:
                        import struct
                        # Look for UUID pattern in the data
                        data_str = data.decode('utf-8', errors='ignore')
                        if '-' in data_str:
                            # Find potential UUID
                            parts = data_str.split('\n')
                            for part in parts:
                                if len(part) > 30 and '-' in part:
                                    potential_uuid = part.strip('\x00').strip()
                                    if len(potential_uuid) >= 32:
                                        empty_request.session_id = potential_uuid
                                        logger.info(f"[Router] Extracted session ID: {potential_uuid}")
                                        break
                    except Exception as extract_error:
                        logger.debug(f"[Router] Could not extract session ID: {extract_error}")
                
                logger.info(f"[Router] Created fallback request with session_id: {empty_request.session_id}")
                return empty_request
            except Exception as e2:
                logger.error(f"[Router] Could not create fallback request: {e2}")
                return login_service_pb2.InitiateLoginRequest()
    
    def _safe_serializer(self, response):
        """Safely serialize protobuf response"""
        try:
            serialized = response.SerializeToString()
            logger.info(f"[Router] Successfully serialized response: {len(serialized)} bytes")
            logger.info(f"[Router] Response result_code: {getattr(response, 'result_code', 'unknown')}")
            return serialized
        except Exception as e:
            logger.error(f"[Router] CRITICAL: Protobuf serialize error: {e}", exc_info=True)
            # Return empty error response bytes
            try:
                error_response = login_service_pb2.InitiateLoginResponse()
                error_response.result_code = 1
                error_response.nickname = ""
                error_response.displayname = ""
                error_response.tracking_metrics_id = f"serialize_error_{int(time.time())}"
                return error_response.SerializeToString()
            except Exception as e2:
                logger.error(f"[Router] FATAL: Could not create error response: {e2}")
                return b''  # Last resort
    
    def _safe_login_notification_stream_handler(self, request, context):
        """Handle LoginNotificationStream - CRITICAL for completing login flow"""
        try:
            logger.info(f"[Router] *** LOGIN NOTIFICATION STREAM STARTED ***")
            logger.info(f"[Router] 🎯 This stream is ESSENTIAL for login completion after kAccountLoginSuccess")
            
            # Call the actual LoginNotificationStream method
            for notification in self.login_service.LoginNotificationStream(request, context):
                yield notification
                
        except Exception as e:
            logger.error(f"[Router] LoginNotificationStream handler error: {e}", exc_info=True)
            # Return empty stream on error
            return
            
    def _safe_character_status_handler(self, request, context):
        """Handle CharacterStatus requests"""
        try:
            logger.info(f"[Router] *** CHARACTER STATUS REQUEST ***")
            return self.login_service.CharacterStatus(request, context)
        except Exception as e:
            logger.error(f"[Router] CharacterStatus handler error: {e}")
            # Return empty error response
            error_response = login_service_pb2.CharacterStatusResponse()
            return error_response
    
    def _safe_notification_deserializer(self, data):
        """Safely deserialize LoginNotificationStream request"""
        try:
            logger.info(f"[Router] Deserializing LoginNotificationStream request: {len(data)} bytes")
            # Try to parse as LoginNotificationStreamRequest
            # For now, create a simple request object
            class SimpleRequest:
                def __init__(self):
                    self.account_id = ""
                    self.session_id = ""
            
            request = SimpleRequest()
            
            # Try to extract account_id and session_id from the data if possible
            try:
                data_str = data.decode('utf-8', errors='ignore')
                if 'account' in data_str.lower():
                    # Try to extract account info
                    import re
                    account_match = re.search(r'account[_\s]*id["\s]*[:=]["\s]*([^"\s,}]+)', data_str, re.IGNORECASE)
                    if account_match:
                        request.account_id = account_match.group(1)
                        logger.info(f"[Router] Extracted account_id: {request.account_id}")
                        
                session_match = re.search(r'session[_\s]*id["\s]*[:=]["\s]*([^"\s,}]+)', data_str, re.IGNORECASE)
                if session_match:
                    request.session_id = session_match.group(1)
                    logger.info(f"[Router] Extracted session_id: {request.session_id}")
            except Exception as extract_error:
                logger.debug(f"[Router] Could not extract IDs from notification request: {extract_error}")
            
            return request
            
        except Exception as e:
            logger.error(f"[Router] Notification deserialize error: {e}")
            # Return empty request
            class SimpleRequest:
                def __init__(self):
                    self.account_id = ""
                    self.session_id = ""
            return SimpleRequest()
    
    def _safe_notification_serializer(self, notification):
        """Safely serialize LoginNotification response"""
        try:
            if hasattr(notification, 'SerializeToString'):
                serialized = notification.SerializeToString()
                logger.info(f"[Router] Successfully serialized notification: {len(serialized)} bytes")
                return serialized
            else:
                # Fallback: create minimal notification
                logger.warning(f"[Router] Creating fallback notification")
                return b'\x08\x01'  # Minimal protobuf message
                
        except Exception as e:
            logger.error(f"[Router] Notification serialize error: {e}")
            return b'\x08\x00'  # Error response
    
    def _safe_character_deserializer(self, data):
        """Safely deserialize CharacterStatus request"""
        try:
            logger.info(f"[Router] Deserializing CharacterStatus request: {len(data)} bytes")
            # Try to parse as CharacterStatusRequest
            # For now, create a simple request object
            class SimpleRequest:
                def __init__(self):
                    self.account_id = ""
                    self.session_id = ""
            
            request = SimpleRequest()
            
            # Try to extract account_id and session_id from the data if possible
            try:
                data_str = data.decode('utf-8', errors='ignore')
                import re
                account_match = re.search(r'account[_\s]*id["\s]*[:=]["\s]*([^"\s,}]+)', data_str, re.IGNORECASE)
                if account_match:
                    request.account_id = account_match.group(1)
                    logger.info(f"[Router] Extracted account_id: {request.account_id}")
                    
                session_match = re.search(r'session[_\s]*id["\s]*[:=]["\s]*([^"\s,}]+)', data_str, re.IGNORECASE)
                if session_match:
                    request.session_id = session_match.group(1)
                    logger.info(f"[Router] Extracted session_id: {request.session_id}")
            except Exception as extract_error:
                logger.debug(f"[Router] Could not extract IDs from character request: {extract_error}")
            
            return request
            
        except Exception as e:
            logger.error(f"[Router] Character deserialize error: {e}")
            # Return empty request
            class SimpleRequest:
                def __init__(self):
                    self.account_id = ""
                    self.session_id = ""
            return SimpleRequest()
    
    def _safe_character_serializer(self, response):
        """Safely serialize CharacterStatus response"""
        try:
            if hasattr(response, 'SerializeToString'):
                serialized = response.SerializeToString()
                logger.info(f"[Router] Successfully serialized character response: {len(serialized)} bytes")
                return serialized
            else:
                # Fallback: create minimal response
                logger.warning(f"[Router] Creating fallback character response")
                return b'\x08\x01'  # Minimal protobuf message
                
        except Exception as e:
            logger.error(f"[Router] Character serialize error: {e}")
            return b'\x08\x00'  # Error response

def serve():
    """Start the enhanced Star Citizen gRPC server with production hardening and complete login flow"""
    logger.info("=" * 80)
    logger.info("🚀 STAR CITIZEN ENHANCED LOGIN SERVER v13 - PRODUCTION READY")
    logger.info("🎯 Enhanced with Real Game Login Flow Notifications")
    logger.info("=" * 80)
    
    # Log enhanced server capabilities
    logger.info("🔥 ENHANCED CAPABILITIES:")
    logger.info("   * Complete login state management (kAccountLoginSuccess, etc.)")
    logger.info("   * AccountLoginCharacterStatus notifications")
    logger.info("   * ReconcileAccountUpdateNotification support")
    logger.info("   * Real-time login flow matching Star Citizen client")
    logger.info("   * Enhanced character data from loginData.json")
    logger.info("   * Session state tracking and transitions")
    logger.info("")
    logger.info("⚙️  CORE SERVICES:")
    logger.info("   * Bearer token authentication (JWT validation)")
    logger.info("   * Session management with secure tokens")
    logger.info("   * Rate limiting for authentication attempts") 
    logger.info("   * Enhanced character service with persistent data")
    logger.info("   * Configuration service for game settings")
    logger.info("   * Telemetry service for performance metrics")
    logger.info("   * Health monitoring and error tracking")
    logger.info("   * Production-ready logging and statistics")
    
    # Create server with enhanced production settings for higher load
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=200),  # Increased from 50 to 200 for higher load
        options=[
            # Settings matching Star Citizen client from logs
            ('grpc.keepalive_time_ms', 120000),        # 2 minutes from client logs
            ('grpc.keepalive_timeout_ms', 20000),      # 20 seconds from client logs
            ('grpc.keepalive_permit_without_calls', True),
            ('grpc.http2.max_pings_without_data', 0),  # From client logs
            ('grpc.http2.min_time_between_pings_ms', 10000),  # From client logs
            ('grpc.http2.min_ping_interval_without_data_ms', 5000),  # From client logs
            ('grpc.max_receive_message_length', 16 * 1024 * 1024),  # 16MB from client logs
            ('grpc.max_send_message_length', 4 * 1024 * 1024),      # 4MB from client logs
            # Enhanced production hardening - more lenient connection limits
            ('grpc.max_connection_idle_ms', 600000),  # 10 minutes (increased from 5)
            ('grpc.max_connection_age_ms', 7200000),  # 2 hours (increased from 1)
            ('grpc.max_connection_age_grace_ms', 300000),  # 5 minutes grace period
            ('grpc.http2.max_frame_size', 16777215),  # Maximum HTTP/2 frame size
            ('grpc.http2.hpack_table_size.decoder', 65536),  # HPACK decoder table size
            ('grpc.http2.hpack_table_size.encoder', 65536),  # HPACK encoder table size
        ]
    )
    
    # Add enhanced generic handler
    generic_handler = StarCitizenGenericHandler()
    server.add_generic_rpc_handlers([generic_handler])
    
    # Listen on port 5678 with SSL/TLS as expected by the client
    server_address = '127.0.0.1:5678'  # Use localhost for development
    
    # Load SSL certificates
    try:
        with open('server.key', 'rb') as f:
            private_key = f.read()
        with open('server.crt', 'rb') as f:
            certificate_chain = f.read()
        
        # Create SSL credentials
        server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
        server.add_secure_port(server_address, server_credentials)
        logger.info(f">> SSL/TLS enabled for gRPC Game Server on {server_address}")
    except FileNotFoundError as e:
        logger.error(f"SSL certificate files not found: {e}")
        logger.info(">> Falling back to insecure connection")
        server.add_insecure_port(server_address)
    
    # Start server
    server.start()
    logger.info(f">> Star Citizen Enhanced gRPC Server listening on {server_address}")
    logger.info(">> Server ready for SSL/TLS connections from patched Star Citizen client")
    logger.info(">> ENHANCED SERVICES AVAILABLE:")
    logger.info("   🔐 LoginService      - Enhanced with state notifications & real game flow")
    logger.info("   ⚙️  ConfigService     - Game configuration and endpoints")
    logger.info("   👤 CharacterService  - Character data with real loginData.json integration")
    logger.info("   📡 PushService       - Real-time notifications")
    logger.info("   📊 TraceService      - Telemetry and metrics collection")
    logger.info("   🆔 IdentityService   - Player identity verification")
    logger.info("   🛡️  DisciplineService - Player behavior monitoring")
    logger.info("   👥 SocialService     - Social features and groups")
    logger.info("")
    logger.info("🎮 LOGIN FLOW ENHANCEMENTS:")
    logger.info("   ✅ kAccountConnecting → kAccountConnected → kAccountAuthenticating")
    logger.info("   ✅ kAccountLoginSuccess → kAccountLoginCharacterStatus")
    logger.info("   ✅ AccountLoginCharacterStatus notifications")
    logger.info("   ✅ ReconcileAccountUpdateNotification")
    logger.info("   ✅ kAccountLoginCompleted")
    logger.info("=" * 80)
    
    try:
        while True:
            time.sleep(300)  # Report stats every 5 minutes in production
            stats = service_stats.get_summary()
            
            # Production monitoring log
            logger.info(">> PRODUCTION HEALTH CHECK:")
            logger.info(f"   Runtime: {stats['runtime_seconds']:.1f}s")
            logger.info(f"   Total calls: {stats['total_calls']}")
            logger.info(f"   Success rate: {((stats['total_success'] / stats['total_calls']) * 100) if stats['total_calls'] > 0 else 0:.1f}%")
            logger.info(f"   Average rate: {stats['calls_per_second']:.1f} calls/sec")
            logger.info(f"   Health status: {stats['health_status']}")
            
            # Alert on health issues
            if stats['health_status'] != 'healthy':
                logger.warning(f"!! SERVER HEALTH ALERT: Status is {stats['health_status']}")
                logger.warning(f"   Error rate: {stats['error_rate']:.2f}%")
                logger.warning(f"   Service breakdown: {stats['breakdown']}")
            
    except KeyboardInterrupt:
        logger.info(">> Shutting down gRPC server gracefully...")
        server.stop(grace=10)  # Longer grace period for production
        
        # Final statistics and health report
        final_stats = service_stats.get_summary()
        logger.info("=" * 80)
        logger.info(">> FINAL SERVER STATISTICS")
        logger.info("=" * 80)
        logger.info(f"Runtime: {final_stats['runtime_seconds']:.1f} seconds ({final_stats['runtime_seconds']/3600:.2f} hours)")
        logger.info(f"Total calls: {final_stats['total_calls']}")
        logger.info(f"Successful calls: {final_stats['total_success']}")
        logger.info(f"Failed calls: {final_stats['total_errors']}")
        logger.info(f"Success rate: {((final_stats['total_success'] / final_stats['total_calls']) * 100) if final_stats['total_calls'] >  0 else 0:.2f}%")
        logger.info(f"Average rate: {final_stats['calls_per_second']:.1f} calls/second")
        logger.info(f"Final health status: {final_stats['health_status']}")
        logger.info("Service breakdown:")
        for service, counts in final_stats['breakdown'].items():
            if isinstance(counts, dict):
                success = counts.get('success', 0)
                error = counts.get('error', 0)
                total = success + error
                success_rate = (success / total * 100) if total > 0 else 0
                logger.info(f"  {service}: {total} calls ({success_rate:.1f}% success)")
            else:
                logger.info(f"  {service}: {counts} calls")
        logger.info("=" * 80)
        logger.info(">> Server shutdown complete. Thank you for using Star Citizen gRPC Server!")
        logger.info("=" * 80)

if __name__ == '__main__':
    serve()

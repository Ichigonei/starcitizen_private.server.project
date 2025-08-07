#!/usr/bin/env python3
"""
Google APIs HTTP Server (OAuth2 Token Endpoint)
Handles HTTP requests for OAuth2 token refresh - based on reverse engineering
"""

import asyncio
import json
import logging
import time
from urllib.parse import parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('google_apis_http_server.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class OAuth2TokenHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth2 token requests"""
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"HTTP {format % args}")
    
    def do_POST(self):
        """Handle POST requests (OAuth2 token refresh)"""
        logger.info(f"🔄 POST request to {self.path} from {self.client_address[0]}")
        
        if self.path == '/token' or self.path.endswith('/token'):
            self.handle_oauth2_token_request()
        else:
            self.handle_generic_post_request()
    
    def do_GET(self):
        """Handle GET requests"""
        logger.info(f"📄 GET request to {self.path} from {self.client_address[0]}")
        
        if self.path == '/token' or self.path.endswith('/token'):
            self.handle_oauth2_token_request()
        else:
            self.handle_generic_get_request()
    
    def handle_oauth2_token_request(self):
        """Handle OAuth2 token refresh requests - based on reverse engineering"""
        logger.info("🔑 Processing OAuth2/STS token request via HTTP")
        
        try:
            # Read request body for POST data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = ""
            
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8')
                logger.info(f"📝 POST data received: {post_data[:200]}..." if len(post_data) > 200 else f"📝 POST data: {post_data}")
            
            # Parse form data
            form_data = parse_qs(post_data)
            
            # Extract parameters
            grant_type = form_data.get('grant_type', [''])[0]
            audience = form_data.get('audience', [''])[0]
            requested_token_type = form_data.get('requested_token_type', [''])[0]
            subject_token_type = form_data.get('subject_token_type', [''])[0]
            subject_token = form_data.get('subject_token', [''])[0]
            scope = form_data.get('scope', [''])[0]
            options = form_data.get('options', [''])[0]
            user_project = form_data.get('userProject', [''])[0]
            
            logger.info(f"🔍 Token request - grant_type: {grant_type}")
            logger.info(f"🔍 Token request - audience: {audience}")
            logger.info(f"🔍 Token request - requested_token_type: {requested_token_type}")
            
            # Determine response type based on grant_type
            if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
                # STS Token Exchange - matching reverse-engineered format from FUN_147808b20
                token_response = {
                    "access_token": f"ya29.star_citizen_exchanged_{int(time.time())}_{len(subject_token) if subject_token else 0}",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope or "https://127.0.0.1:8000",  # Use the local server scope
                    "resource": audience or "https://127.0.0.1:8000",
                    "audience": audience or "https://127.0.0.1:8000",
                    # Additional fields that Star Citizen might expect based on reverse engineering
                    "refresh_token": f"1//star_citizen_sts_refresh_{int(time.time())}",
                    "project_id": user_project or "star-citizen-local",
                    "user_project": user_project or "star-citizen-local"
                }
                logger.info("✅ STS Token Exchange response created (RFC 8693 compliant)")
                logger.info(f"📋 Exchange details - audience: {audience}, scope: {scope}")
                if options:
                    logger.info(f"📋 Options provided: {options}")
            elif grant_type == "refresh_token":
                # OAuth2 Token Refresh
                token_response = {
                    "access_token": f"star_citizen_refresh_token_{int(time.time())}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope or "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email",
                    "refresh_token": f"star_citizen_refresh_{int(time.time())}"
                }
                logger.info("✅ OAuth2 Token Refresh response created")
            else:
                # Generic OAuth2 token
                token_response = {
                    "access_token": f"star_citizen_http_token_{int(time.time())}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope or "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
                }
                logger.info("✅ Generic OAuth2 token response created")
            
            # Send response
            response_json = json.dumps(token_response, indent=2)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_json)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response_json.encode('utf-8'))
            
            logger.info("✅ Token response sent via HTTP")
            
        except Exception as e:
            logger.error(f"❌ Error handling token request: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_generic_post_request(self):
        """Handle generic POST requests"""
        logger.info(f"🌐 Generic POST request to {self.path}")
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8')
                logger.info(f"📝 POST data: {post_data[:200]}..." if len(post_data) > 200 else f"📝 POST data: {post_data}")
            
            # Generic success response
            response = {
                "status": "ok",
                "path": self.path,
                "server": "star_citizen_local_google_apis_http",
                "timestamp": int(time.time())
            }
            
            response_json = json.dumps(response, indent=2)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_json)))
            self.end_headers()
            self.wfile.write(response_json.encode('utf-8'))
            
            logger.info("✅ Generic POST response sent")
            
        except Exception as e:
            logger.error(f"❌ Error handling POST request: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def handle_generic_get_request(self):
        """Handle generic GET requests"""
        logger.info(f"🌐 Generic GET request to {self.path}")
        
        response = {
            "status": "ok",
            "path": self.path,
            "method": "GET",
            "server": "star_citizen_local_google_apis_http",
            "timestamp": int(time.time())
        }
        
        response_json = json.dumps(response, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))
        
        logger.info("✅ Generic GET response sent")

def start_http_server(host='127.0.0.1', port=50052):
    """Start the HTTP server for OAuth2 token requests"""
    logger.info(f"🚀 Starting Google APIs HTTP server on {host}:{port}")
    
    server = HTTPServer((host, port), OAuth2TokenHandler)
    
    logger.info(f"✅ Google APIs HTTP server running on {host}:{port}")
    logger.info("🔧 Handling HTTP endpoints:")
    logger.info("   * POST /token (OAuth2 token refresh)")
    logger.info("   * GET /token (OAuth2 token info)")
    logger.info("   * Generic Google API HTTP endpoints")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🛑 Stopping HTTP server...")
        server.shutdown()
        logger.info("✅ HTTP server stopped")

if __name__ == "__main__":
    start_http_server()

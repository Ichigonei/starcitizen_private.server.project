#!/usr/bin/env python3
"""
Star Citizen Diffusion Server - Port 8000
Initial connection point for Star Citizen clients before authentication redirection
Handles SSL handshake and service discovery protocol

This server implements the first layer of the Star Citizen client communication:
Client → Diffusion Server (8000) → Authentication Service (8443) → gRPC Server (5678)
"""

import asyncio
import ssl
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import struct

# Import generated protobuf classes
try:
    import star_network_pb2
    import star_network_pb2_grpc
    PROTOBUF_AVAILABLE = True
    logging.info("🔷 Protobuf classes loaded successfully")
except ImportError as e:
    PROTOBUF_AVAILABLE = False
    logging.warning(f"⚠️  Protobuf classes not available: {e}")

# Configure logging
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# Remove all existing handlers
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] %(message)s'))
root_logger.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler('diffusion_server.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] %(message)s'))
root_logger.addHandler(file_handler)
logger = logging.getLogger(__name__)

class StarCitizenDiffusionServer:
    """
    Diffusion Server for Star Citizen client initial connections
    Only handles heartbeat messages (redirection removed)
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8001):  # Changed to port 8001
        self.host = host
        self.port = port
        self.running = False
        self.clients = {}
        self.session_tokens = {}
        
        # Service configuration - only heartbeat remains
        self.service_config = {
            "network_config": {
                "heartbeat_interval": 30
            }
        }

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for secure connections"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # For development - create self-signed certificate if needed
        try:
            context.load_cert_chain('server.crt', 'server.key')
            logger.info("🔒 SSL certificate loaded successfully")
        except FileNotFoundError:
            logger.warning("⚠️ SSL certificate not found, creating self-signed certificate")
            self.create_self_signed_cert()
            try:
                context.load_cert_chain('server.crt', 'server.key')
            except Exception as e:
                logger.error(f"❌ Failed to load SSL certificate: {e}")
                # Fall back to no SSL for development
                return None
                
        return context

    def create_self_signed_cert(self):
        """Create a self-signed certificate for development"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Certificate details
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Star Citizen Test Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate and key
            with open("server.crt", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                
            with open("server.key", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            logger.info("✅ Self-signed certificate created")
            
        except ImportError:
            logger.error("❌ cryptography library not installed. Install with: pip install cryptography")
        except Exception as e:
            logger.error(f"❌ Failed to create self-signed certificate: {e}")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        client_addr = writer.get_extra_info('peername')
        session_id = str(uuid.uuid4())
        
        logger.info(f"🔌 New client connection from {client_addr[0]}:{client_addr[1]} (session: {session_id})")
        
        self.clients[session_id] = {
            'address': client_addr,
            'connected_at': time.time(),
            'last_activity': time.time(),
            'reader': reader,
            'writer': writer,
            'is_star_citizen_client': False,
            'message_count': 0,
            'protocol_stage': 'initial',
            'heartbeat_count': 0
        }
        
        try:
            while True:
                # Read message from client with timeout
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                    if not data:
                        break
                        
                    self.clients[session_id]['last_activity'] = time.time()
                    self.clients[session_id]['message_count'] += 1
                    
                    # Detect if this is a real Star Citizen client
                    if b"Star Citizen Game Client" in data or b"sc_client" in data:
                        self.clients[session_id]['is_star_citizen_client'] = True
                        logger.info(f"🎮 Detected real Star Citizen client connection!")
                    
                    # Track protocol stages
                    if b"diff.service.online" in data:
                        self.clients[session_id]['protocol_stage'] = 'service_discovery'
                    elif b"cmsg_ls_req_dests" in data:
                        self.clients[session_id]['protocol_stage'] = 'lobby_discovery'
                    elif b"cmsg_set_region_id" in data:
                        self.clients[session_id]['protocol_stage'] = 'region_setup'
                    elif b"heartbeat" in data:
                        self.clients[session_id]['protocol_stage'] = 'heartbeat_active'
                        self.clients[session_id]['heartbeat_count'] += 1
                    
                    # Process the message
                    response = await self.process_message(data, session_id)
                    
                    if response:
                        writer.write(response)
                        await writer.drain()
                        logger.info(f"📤 Sent response to client ({len(response)} bytes)")
                        
                        # For real Star Citizen clients, keep connection open briefly
                        if self.clients[session_id]['is_star_citizen_client']:
                            await asyncio.sleep(0.1)  # Brief delay for client processing
                        
                except asyncio.TimeoutError:
                    logger.debug(f"⏰ Client {client_addr} connection timeout")
                    break
                    
        except asyncio.CancelledError:
            logger.info(f"🔌 Client {client_addr} connection cancelled")
        except ConnectionResetError:
            logger.info(f"🔌 Client {client_addr} connection reset by peer")
        except Exception as e:
            logger.error(f"❌ Error handling client {client_addr}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            if session_id in self.clients:
                client_info = self.clients[session_id]
                client_type = "Star Citizen Client" if client_info['is_star_citizen_client'] else "Test Client"
                duration = time.time() - client_info['connected_at']
                
                logger.info(f"🔌 {client_type} {client_addr} disconnected (session: {session_id})")
                logger.info(f"📊 Session stats: {duration:.1f}s duration, {client_info['message_count']} messages, "
                           f"stage: {client_info['protocol_stage']}, heartbeats: {client_info['heartbeat_count']}")
                
                del self.clients[session_id]

    async def process_message(self, data: bytes, session_id: str) -> Optional[bytes]:
        """Process incoming messages from Star Citizen client"""
        try:
            # Extract real client information from the data
            self.extract_client_info_from_data(data, session_id)
            
            # Only handle heartbeat messages
            try:
                message_text = data.decode('utf-8').strip()
                logger.info(f"📨 Received text message: {message_text}")
                if "heartbeat" in message_text:
                    return await self.handle_heartbeat(message_text, session_id)
                else:
                    # Ignore all other messages
                    return None
            except UnicodeDecodeError:
                # Handle binary protocol messages
                logger.info(f"📨 Received binary message ({len(data)} bytes)")
                if b"heartbeat" in data:
                    return await self.handle_binary_heartbeat(data, session_id)
                elif b"diff.service.online" in data:
                    return await self.handle_service_discovery(data, session_id)
                elif b"cmsg_ls_req_dests" in data:
                    return await self.handle_lobby_destinations(data, session_id)
                elif b"cmsg_set_region_id" in data:
                    return await self.handle_region_setup(data, session_id)
                else:
                    # Ignore all other binary messages
                    return None
        except Exception as e:
            logger.error(f"❌ Error processing message: {e}")
        return None

    async def handle_heartbeat(self, message: str, session_id: str) -> bytes:
        """Handle heartbeat messages - respond with protobuf format for consistency"""
        logger.debug(f"💓 Text heartbeat from session {session_id} - converting to protobuf response")
        
        # Use the same protobuf response format as binary heartbeats
        return await self.handle_binary_heartbeat(b"heartbeat", session_id)

    async def handle_binary_service_online(self, data: bytes, session_id: str) -> bytes:
        """Handle binary diff.service.online from real Star Citizen client"""
        logger.info(f"🚀 Processing binary service online from real SC client (session: {session_id})")
        
        # Generate session token
        session_token = f"sc_session_{int(time.time())}_{session_id[:8]}"
        self.session_tokens[session_id] = {
            'token': session_token,
            'created_at': time.time(),
            'client_address': self.clients[session_id]['address'] if session_id in self.clients else None
        }
        
        # Load authentication data for immediate auth
        try:
            with open('login_data.json', 'r') as f:
                auth_data = json.load(f)
        except:
            auth_data = {
                "access_token": "access_test123",
                "account_id": "1000001",
                "displayname": "TestPilot"
            }
        
        # Redirection removed, respond with minimal heartbeat ack
        return await self.handle_binary_heartbeat(b"heartbeat", session_id)

    async def handle_binary_lobby_destinations(self, data: bytes, session_id: str) -> bytes:
        """Handle binary lobby destination requests"""
        # Redirection removed, respond with minimal heartbeat ack
        return await self.handle_binary_heartbeat(b"heartbeat", session_id)

    async def handle_binary_heartbeat(self, data: bytes, session_id: str) -> bytes:
        """Handle binary heartbeat messages - respond with proper protobuf format"""
        logger.debug(f"💓 Binary heartbeat from real SC client - parsing protobuf")
        
        # Try to parse incoming heartbeat request
        try:
            # Extract protobuf data after header and magic bytes
            if len(data) > 8:  # Skip length(4) + magic(4) if present
                protobuf_data = data[8:] if data[4:8] == b'\xef\xbe\xad\xde' else data
            else:
                protobuf_data = data
                
            # Try to parse as HeartbeatRequest
            heartbeat_request = star_network_pb2.HeartbeatRequest()
            heartbeat_request.ParseFromString(protobuf_data)
            
            logger.info(f"📊 Parsed heartbeat request: {heartbeat_request}")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to parse heartbeat protobuf: {e}")
            # Fall back to manual parsing for non-standard format
            logger.info(f"📊 Raw heartbeat data: {data.hex()}")
        
        # Create proper protobuf heartbeat response
        heartbeat_response = star_network_pb2.HeartbeatResponse()
        heartbeat_response.heartbeat_ack = "heartbeat_ack"
        heartbeat_response.server_time = int(time.time() * 1000)
        
        # Get the session token - handle both string and dict formats
        session_token_data = self.session_tokens.get(session_id, "")
        if isinstance(session_token_data, dict):
            heartbeat_response.session_token = session_token_data.get('token', "")
        else:
            heartbeat_response.session_token = session_token_data
            
        heartbeat_response.keep_alive = True
        heartbeat_response.heartbeat_interval = 30
        
        # Check if this is a real Star Citizen client and trigger authentication redirect ONCE
        if (session_id in self.clients and 
            self.clients[session_id]['is_star_citizen_client'] and 
            not self.clients[session_id].get('auth_triggered', False)):
            # Mark authentication as triggered to prevent repeated sends
            self.clients[session_id]['auth_triggered'] = True
            # Trigger authentication redirect (but let gRPC server handle the full flow)
            asyncio.create_task(self.trigger_authentication_redirect(session_id))
        
        # Serialize to binary
        response_bytes = heartbeat_response.SerializeToString()
        
        # Wrap in Star Citizen protocol format
        header = struct.pack('<I', len(response_bytes))
        magic = b'\xef\xbe\xad\xde'
        
        full_response = header + magic + response_bytes
        logger.info(f"📤 Sending protobuf heartbeat response: {heartbeat_response}")
        logger.debug(f"📤 Response hex: {full_response.hex()}")
        
        return full_response
    
    async def trigger_authentication_redirect(self, session_id: str) -> None:
        """Trigger authentication redirect to RSI servers - minimal flow to get client moving"""
        try:
            # Wait a moment for the heartbeat response to be sent
            await asyncio.sleep(0.5)
            
            logger.info(f"🔐 Triggering AUTHENTICATION REDIRECT for session {session_id}")
            logger.info(f"🎯 Sending client to authentication server (port 443) for login")
            
            # Load real user data from the actual client hex dump
            try:
                with open('login_data_real_client.json', 'r') as f:
                    auth_data = json.load(f)
                logger.info(f"📊 Using real client data: {auth_data['displayname']} at {auth_data['location']}")
            except:
                # Fallback to extracted hex data values
                auth_data = {
                    "access_token": "fa8a335e-c3de-da45-b336-ef1ffc15d7eb",
                    "account_id": "1000001",
                    "displayname": "TestPilot",
                    "email": "test.pilot@robertsspaceindustries.com",
                    "character_id": "char_testpilot_001",
                    "server_version": "4.2.151.51347",
                    "game_version": "sc-alpha-4.2.0",
                    "environment": "PUB",
                    "region": "us-east-1",
                    "location": "Stanton_ArcCorp_Area18",
                    "universe": "persistent_universe",
                    "server_instance": "server_00120",
                    "instance_id": "instance_1754500660"
                }
            
            client_info = self.clients.get(session_id)
            if not client_info:
                logger.warning(f"⚠️ No client info found for session {session_id}")
                return
                
            writer = client_info['writer']
            
            # Send already authenticated intent message
            await self.send_already_authenticated_intent(writer, session_id)
            await asyncio.sleep(0.1)
            
            # Send minimal progression to signal client to move to authentication server
            logger.info("📤 Sending minimal redirect sequence...")
            sequence_number = 2  # Start at 2 since intent message used sequence 1
            
            await self.send_processing_queue_joined(writer, auth_data, session_id, sequence_number)
            await asyncio.sleep(0.2)
            sequence_number += 1
            
            # CRITICAL: Send queue exit message to get client out of login queue and redirect
            await self.send_processing_queue_exited(writer, auth_data, session_id, sequence_number)
            await asyncio.sleep(0.2)
            sequence_number += 1
            
            # Send login completed with redirect to authentication server
            await self.send_login_completed_redirect(writer, auth_data, session_id, sequence_number)
            await asyncio.sleep(0.5)
            
            # Close connection gracefully to signal client should move to next server
            logger.info("🔚 Closing Diffusion Server connection - client should now connect to authentication server")
            writer.close()
            await writer.wait_closed()
            
            # Remove client from active clients
            if session_id in self.clients:
                del self.clients[session_id]
            
            logger.info(f"✅ Authentication REDIRECT completed for session {session_id}")
            logger.info("🎯 Client should now connect to authentication server (port 443)")
        except Exception as e:
            logger.error(f"❌ Error in authentication redirect for session {session_id}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")

    async def send_already_authenticated_intent(self, writer, session_id):
        """Send a StarCitizenMessage with client_intent 'already_authenticated'"""
        if not PROTOBUF_AVAILABLE:
            logger.warning("Protobuf not available, cannot send intent message.")
            return
        
        # Build ClientIntentMessage
        intent_msg = star_network_pb2.ClientIntentMessage(
            intent_type="already_authenticated",
            details="Client is already authenticated; proceeding with login progression."
        )
        # Build StarCitizenMessage wrapper
        star_msg = star_network_pb2.StarCitizenMessage(
            client_intent=intent_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=1,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info("📤 Sent already_authenticated ClientIntentMessage")
    
    async def send_entitlement_started(self, writer, auth_data):
        """Send EntitlementStartedMessage"""
        entitlement_msg = star_network_pb2.EntitlementStartedMessage()
        entitlement_msg.account_id = auth_data.get("account_id", "1000001")
        entitlement_msg.session_token = auth_data.get("access_token", "access_test123")
        entitlement_msg.entitlements.extend(["star_citizen_game_access", "persistent_universe_access"])
        entitlement_msg.start_time = int(time.time() * 1000)
        
        await self.send_protobuf_message(writer, entitlement_msg)
        logger.info("📤 Sent EntitlementStartedMessage")
    
    async def send_processing_queue_joined(self, writer, auth_data, session_id, sequence_number):
        """Send ProcessingQueueJoinedMessage wrapped in StarCitizenMessage"""
        queue_msg = star_network_pb2.ProcessingQueueJoinedMessage()
        queue_msg.queue_id = "login_queue_001"
        queue_msg.position = 1
        queue_msg.estimated_wait_time = 0
        queue_msg.queue_type = "character_login"
        
        star_msg = star_network_pb2.StarCitizenMessage(
            processing_queue_joined=queue_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info("📤 Sent ProcessingQueueJoinedMessage (wrapped)")
    
    async def send_processing_queue_exited(self, writer, auth_data, session_id, sequence_number):
        """Send ProcessingQueueExitedMessage to get client out of login queue"""
        queue_exit_msg = star_network_pb2.ProcessingQueueExitedMessage()
        queue_exit_msg.queue_id = "login_queue_001"
        queue_exit_msg.exit_reason = "authentication_completed"
        queue_exit_msg.success = True
        queue_exit_msg.next_step = "character_selection"
        
        star_msg = star_network_pb2.StarCitizenMessage(
            processing_queue_exited=queue_exit_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info("📤 Sent ProcessingQueueExitedMessage - CLIENT SHOULD EXIT LOGIN QUEUE NOW")
    
    async def send_account_login_character_status(self, writer, auth_data, session_id, sequence_number):
        """Send AccountLoginCharacterStatusMessage wrapped in StarCitizenMessage"""
        char_status_msg = star_network_pb2.AccountLoginCharacterStatusMessage()
        char_status_msg.account_id = auth_data.get("account_id", "1000001")
        char_status_msg.selected_character_id = auth_data.get("character_id", "char_001")
        char_status_msg.character_selection_required = False
        
        # Add character info with real location data
        char_info = char_status_msg.characters.add()
        char_info.character_id = auth_data.get("character_id", "char_001")
        char_info.character_name = auth_data.get("displayname", "TestPilot")
        char_info.character_class = "Citizen"
        char_info.level = 1
        char_info.location = auth_data.get("location", "Stanton_ArcCorp_Area18")  # Real location from hex data
        char_info.available = True
        
        star_msg = star_network_pb2.StarCitizenMessage(
            account_login_character_status=char_status_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent AccountLoginCharacterStatusMessage for {char_info.character_name} at {char_info.location} (wrapped)")
    
    async def send_reconcile_account_update(self, writer, auth_data, session_id, sequence_number):
        """Send ReconcileAccountUpdateNotificationMessage wrapped in StarCitizenMessage - based on reverse engineering"""
        reconcile_msg = star_network_pb2.ReconcileAccountUpdateNotificationMessage()
        
        # Based on reverse engineered function FUN_140ba5af0:
        # Phase values: LTP(1), PLATFORM(2/3), UNSPECIFIED(0)
        # Status values: EXECUTING(1), COMPLETE(2), FAILED(3), UNSPECIFIED(0)
        reconcile_msg.phase = star_network_pb2.ReconcileAccountUpdateNotificationMessage.Phase.COMPLETED  # Status 2 = COMPLETE
        reconcile_msg.account_id = auth_data.get("account_id", "1000001")
        reconcile_msg.progress_percentage = 100
        
        # Add the fields that the reverse engineered function expects:
        # command_id, details, account_urn, player_urn, status, phase
        command_id = f"reconcile_cmd_{int(time.time())}"
        account_urn = f"urn:rsi:account:{auth_data.get('account_id', '1000001')}"
        player_urn = f"urn:rsi:player:{auth_data.get('character_id', 'char_001')}"
        
        # Details message matching the log format from reverse engineering
        reconcile_msg.update_details = (
            f"Received an entitlement status update message with values: "
            f"command id {command_id} - "
            f"details Character data synchronized for {auth_data.get('location', 'Stanton_ArcCorp_Area18')} in {auth_data.get('universe', 'persistent_universe')} - "
            f"account urn {account_urn} - "
            f"player urn {player_urn} - "
            f"status RECONCILE_ACCOUNT_STATUS_COMPLETE - "
            f"phase RECONCILE_ACCOUNT_PHASE_PLATFORM"
        )
        
        star_msg = star_network_pb2.StarCitizenMessage(
            reconcile_account_update_notification=reconcile_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent ReconcileAccountUpdateNotificationMessage - {reconcile_msg.update_details} (wrapped)")
        logger.info("🔍 Message format matches reverse engineered function FUN_140ba5af0")
    
    async def send_login_completed(self, writer, auth_data, session_id, sequence_number):
        """Send LoginCompletedMessage wrapped in StarCitizenMessage"""
        login_complete_msg = star_network_pb2.LoginCompletedMessage()
        login_complete_msg.account_id = auth_data.get("account_id", "1000001")
        login_complete_msg.session_token = auth_data.get("access_token", "access_test123")
        login_complete_msg.success = True
        
        # CRITICAL: Provide the game server endpoint for the client to connect to next
        login_complete_msg.next_service_endpoint = "127.0.0.1:5678"
        
        # Add available services so client knows where to go next
        game_service = login_complete_msg.available_services.add()
        game_service.service_name = "game_server"
        game_service.host = "127.0.0.1"
        game_service.port = 5678
        game_service.ssl_enabled = False
        game_service.protocols.extend(["grpc", "http2"])
        
        # Add LoginService specifically for LoginNotificationStream
        login_service = login_complete_msg.available_services.add()
        login_service.service_name = "login_service"
        login_service.host = "127.0.0.1"
        login_service.port = 5678
        login_service.ssl_enabled = False
        login_service.protocols.extend(["grpc", "http2"])
        
        # Add universe service with real server instance data
        universe_service = login_complete_msg.available_services.add()
        universe_service.service_name = auth_data.get("universe", "persistent_universe")
        universe_service.host = auth_data.get("server_ip", "127.0.0.1")
        universe_service.port = 5678
        universe_service.ssl_enabled = False
        universe_service.protocols.extend(["grpc", "http2"])
        
        star_msg = star_network_pb2.StarCitizenMessage(
            login_completed=login_complete_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent LoginCompletedMessage for {auth_data.get('universe', 'persistent_universe')} server {auth_data.get('server_instance', 'unknown')}")
        logger.info("🎯 Client should now connect to gRPC server for LoginNotificationStream")
    
    async def send_login_completed_redirect(self, writer, auth_data, session_id, sequence_number):
        """Send LoginCompletedMessage with redirect to dedicated login server (port 9000)"""
        login_complete_msg = star_network_pb2.LoginCompletedMessage()
        login_complete_msg.account_id = auth_data.get("account_id", "1000001")
        login_complete_msg.session_token = auth_data.get("access_token", "access_test123")
        login_complete_msg.success = True
        
        # CRITICAL: Redirect to dedicated login server for authentication
        login_complete_msg.next_service_endpoint = "http://127.0.0.1:9000"
        
        # Add dedicated login server as the authentication service
        auth_service = login_complete_msg.available_services.add()
        auth_service.service_name = "authentication_service"
        auth_service.host = "127.0.0.1"
        auth_service.port = 9000
        auth_service.ssl_enabled = False
        auth_service.protocols.extend(["http", "websocket"])
        
        # Add game server for after authentication
        game_service = login_complete_msg.available_services.add()
        game_service.service_name = "game_server"
        game_service.host = "127.0.0.1"
        game_service.port = 5678
        game_service.ssl_enabled = True
        game_service.protocols.extend(["grpc", "http2"])
        
        star_msg = star_network_pb2.StarCitizenMessage(
            login_completed=login_complete_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent LoginCompletedMessage with redirect to dedicated login server (port 9000)")
        logger.info("🎯 Client should now connect to dedicated login server for authentication")
    
    async def send_character_ready_message(self, writer, auth_data):
        """Send a character ready message to trigger world entry"""
        try:
            # Create a simple message indicating the character is ready to enter the world
            # This might be what the client needs to transition from kAccountLoginSuccess
            
            # Try using a region setup response to indicate the world is ready
            region_msg = star_network_pb2.RegionSetupResponse()
            region_msg.success = True
            region_msg.region_id = "persistent_universe"
            region_msg.message = "Character ready for world entry"
            
            await self.send_protobuf_message(writer, region_msg)
            logger.info("📤 Sent CharacterReady/RegionReady message")
            
        except Exception as e:
            logger.error(f"❌ Error sending character ready message: {e}")
    
    async def send_protobuf_message(self, writer, message):
        """Send a protobuf message with proper Star Citizen protocol wrapping"""
        response_bytes = message.SerializeToString()
        header = struct.pack('<I', len(response_bytes))
        magic = b'\xef\xbe\xad\xde'
        full_response = header + magic + response_bytes
        
        writer.write(full_response)
        await writer.drain()
    
    async def handle_service_discovery(self, data: bytes, session_id: str) -> bytes:
        """Handle service discovery requests using protobuf"""
        logger.info(f"🔍 Service discovery request from session {session_id}")
        
        # Generate session token for this client
        session_token = f"sc_session_{int(time.time())}_{session_id[:8]}"
        self.session_tokens[session_id] = {
            'token': session_token,
            'created_at': time.time(),
            'client_address': self.clients[session_id]['address'] if session_id in self.clients else None
        }
        
        # Create service discovery response
        service_response = star_network_pb2.ServiceDiscoveryResponse()
        service_response.service_online = True
        service_response.server_version = "1.0.0"
        service_response.server_time = int(time.time() * 1000)
        
        # Add authentication service endpoint (dedicated login server)
        auth_endpoint = service_response.endpoints.add()
        auth_endpoint.service_name = "authentication_service"
        auth_endpoint.host = "127.0.0.1"
        auth_endpoint.port = 9000  # Dedicated login server port
        auth_endpoint.ssl_enabled = False
        auth_endpoint.protocols.extend(["http", "websocket"])
        
        # Add diffusion service endpoint
        diffusion_endpoint = service_response.endpoints.add()
        diffusion_endpoint.service_name = "diffusion_service"
        diffusion_endpoint.host = "127.0.0.1"
        diffusion_endpoint.port = 8000
        diffusion_endpoint.ssl_enabled = False
        diffusion_endpoint.protocols.extend(["http", "websocket"])
        
        # Add game server endpoint
        game_endpoint = service_response.endpoints.add()
        game_endpoint.service_name = "game_server"
        game_endpoint.host = "127.0.0.1"
        game_endpoint.port = 5678
        game_endpoint.ssl_enabled = False
        game_endpoint.protocols.extend(["grpc", "http2"])
        
        # Serialize and wrap
        response_bytes = service_response.SerializeToString()
        header = struct.pack('<I', len(response_bytes))
        magic = b'\xef\xbe\xad\xde'
        
        logger.info(f"📤 Sending service discovery response with auth redirect: {service_response}")
        
        return header + magic + response_bytes
    
    async def handle_lobby_destinations(self, data: bytes, session_id: str) -> bytes:
        """Handle lobby destination requests using protobuf"""
        logger.info(f"🎮 Lobby destinations request from session {session_id}")
        
        # Create lobby response with real client data
        lobby_response = star_network_pb2.LobbyDestinationResponse()
        lobby_response.region_id = "us-east-1"  # From hex data
        lobby_response.response_time = int(time.time() * 1000)
        
        # Add a destination with real server instance data
        destination = lobby_response.destinations.add()
        destination.destination_id = "server_00120"  # From hex data
        destination.name = "Persistent Universe - Stanton System"
        destination.host = "127.0.0.1"
        destination.port = 5678
        destination.player_count = 1
        destination.max_players = 50
        destination.game_mode = "persistent_universe"  # From hex data
        destination.available = True
        
        # Serialize and wrap
        response_bytes = lobby_response.SerializeToString()
        header = struct.pack('<I', len(response_bytes))
        magic = b'\xef\xbe\xad\xde'
        
        logger.info(f"📤 Sending lobby destinations response with real server data: {lobby_response}")
        return header + magic + response_bytes
    
    async def handle_region_setup(self, data: bytes, session_id: str) -> bytes:
        """Handle region setup requests using protobuf"""
        logger.info(f"🌍 Region setup request from session {session_id}")
        
        # Create region setup response
        region_response = star_network_pb2.RegionSetupResponse()
        region_response.success = True
        region_response.region_id = "us-east-1"
        region_response.message = "Region configured successfully"
        
        # Add region services
        service = region_response.region_services.add()
        service.service_name = "game_server"
        service.host = "127.0.0.1"
        service.port = 5678
        service.ssl_enabled = False
        service.protocols.extend(["grpc", "http2"])
        
        # Serialize and wrap
        response_bytes = region_response.SerializeToString()
        header = struct.pack('<I', len(response_bytes))
        magic = b'\xef\xbe\xad\xde'
        
        logger.info(f"📤 Sending region setup response: {region_response}")
        return header + magic + response_bytes

    async def handle_binary_set_region(self, data: bytes, session_id: str) -> bytes:
        """Handle binary region setup requests from real Star Citizen client"""
        # Redirection removed, respond with minimal heartbeat ack
        return await self.handle_binary_heartbeat(b"heartbeat", session_id)

    async def create_binary_response(self, original_data: bytes, session_id: str) -> bytes:
        """Create a generic binary response for unknown messages"""
        # Redirection removed, respond with minimal heartbeat ack
        return await self.handle_binary_heartbeat(b"heartbeat", session_id)

    async def start_server(self):
        """Start the diffusion server"""
        logger.info("🚀 Starting Star Citizen Diffusion Server...")
        logger.info("=" * 80)
        logger.info("🎮 STAR CITIZEN DIFFUSION SERVER READY")
        logger.info("=" * 80)
        logger.info("🔥 CAPABILITIES:")
        logger.info("   * SSL/TLS handshake support")
        logger.info("   * Protobuf-based message handling (star_network.proto)")
        logger.info("   * Heartbeat monitoring with proper protobuf responses")
        logger.info("   * Service discovery protobuf responses")
        logger.info("   * Lobby destination protobuf responses")
        logger.info("   * Region setup protobuf responses")
        logger.info("   * Running on port 8001 (behind MITM proxy on 8000)")
        logger.info("")
        logger.info("🌐 NETWORK FLOW:")
        logger.info(f"   Star Citizen Client (8000) → MITM Proxy → Diffusion Server ({self.port}) → Redirect to Services")
        logger.info("   * Service Discovery → Authentication Service (8443)")
        logger.info("   * Lobby Destinations → Game Servers (5678)")
        logger.info("   * Region Setup → Backend Services")
        logger.info("=" * 80)
        
        self.running = True
        # Disable SSL for MITM compatibility - proxy handles the connection layer
        logger.info("🔓 SSL disabled - running behind MITM proxy")
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        logger.info(f"🔓 Diffusion Server listening on {self.host}:{self.port} (No SSL - behind proxy)")
        async with server:
            await server.serve_forever()

    async def stop_server(self):
        """Stop the diffusion server"""
        logger.info("🛑 Stopping Diffusion Server...")
        self.running = False
        
        # Close all client connections
        for session_id, client in self.clients.items():
            try:
                client['writer'].close()
                await client['writer'].wait_closed()
            except Exception as e:
                logger.error(f"Error closing client {session_id}: {e}")
        
        self.clients.clear()
        self.session_tokens.clear()
        logger.info("✅ Diffusion Server stopped")

    def extract_client_info_from_data(self, data: bytes, session_id: str):
        """Extract and log real client information from binary data"""
        try:
            # Convert to hex string for pattern matching
            hex_data = data.hex()
            
            # Known patterns from the hex dump
            patterns = {
                "TestPilot": "54 65 73 74 50 69 6C 6F 74".replace(" ", ""),
                "127.0.0.1": "31 32 37 2E 30 2E 30 2E 31".replace(" ", ""),
                "Stanton_ArcCorp_Area18": "53 74 61 6E 74 6F 6E 5F 41 72 63 43 6F 72 70 5F 41 72 65 61 31 38".replace(" ", ""),
                "us-east-1": "75 73 2D 65 61 73 74 2D 31".replace(" ", ""),
                "persistent_universe": "70 65 72 73 69 73 74 65 6E 74 5F 75 6E 69 76 65 72 73 65".replace(" ", ""),
                "server_00120": "73 65 72 76 65 72 5F 30 30 31 32 30".replace(" ", ""),
                "instance_1754500660": "69 6E 73 74 61 6E 63 65 5F 31 37 35 34 35 30 30 36 36 30".replace(" ", ""),
                "test.pilot@robertsspaceindustries.com": "74 65 73 74 2E 70 69 6C 6F 74 40 72 6F 62 65 72 74 73 73 70 61 63 65 69 6E 64 75 73 74 72 69 65 73 2E 63 6F 6D".replace(" ", ""),
                "4.2.151.51347": "34 2E 32 2E 31 35 31 2E 35 31 33 34 37".replace(" ", ""),
                "sc-alpha-4.2.0": "73 63 2D 61 6C 70 68 61 2D 34 2E 32 2E 30".replace(" ", ""),
                "PUB": "50 55 42".replace(" ", ""),
                "fa8a335e-c3de-da45-b336-ef1ffc15d7eb": "66 61 38 61 33 33 35 65 2D 63 33 64 65 2D 64 61 34 35 2D 62 33 33 36 2D 65 66 31 66 66 63 31 35 64 37 65 62".replace(" ", "")
            }
            
            found_patterns = []
            for name, pattern in patterns.items():
                if pattern.lower() in hex_data.lower():
                    found_patterns.append(name)
            
            if found_patterns:
                logger.info(f"🔍 Detected real client data in session {session_id}: {', '.join(found_patterns)}")
                # Mark this as a real Star Citizen client
                if session_id in self.clients:
                    self.clients[session_id]['is_star_citizen_client'] = True
                    self.clients[session_id]['detected_patterns'] = found_patterns
            
        except Exception as e:
            logger.debug(f"Error extracting client info: {e}")

    async def send_reconcile_account_executing(self, writer, auth_data, session_id, sequence_number):
        """Send ReconcileAccountUpdateNotificationMessage in EXECUTING status - based on reverse engineering"""
        reconcile_msg = star_network_pb2.ReconcileAccountUpdateNotificationMessage()
        
        # Based on reverse engineered function FUN_140ba5af0:
        # Send EXECUTING status first (status = 1)
        reconcile_msg.phase = star_network_pb2.ReconcileAccountUpdateNotificationMessage.Phase.IN_PROGRESS  # Phase for executing
        reconcile_msg.account_id = auth_data.get("account_id", "1000001")
        reconcile_msg.progress_percentage = 50  # In progress
        
        # Add the fields that the reverse engineered function expects
        command_id = f"reconcile_cmd_{int(time.time())}"
        account_urn = f"urn:rsi:account:{auth_data.get('account_id', '1000001')}"
        player_urn = f"urn:rsi:player:{auth_data.get('character_id', 'char_001')}"
        
        # Details message matching the log format from reverse engineering
        reconcile_msg.update_details = (
            f"Received an entitlement status update message with values: "
            f"command id {command_id} - "
            f"details Synchronizing character data for {auth_data.get('location', 'Stanton_ArcCorp_Area18')} in {auth_data.get('universe', 'persistent_universe')} - "
            f"account urn {account_urn} - "
            f"player urn {player_urn} - "
            f"status RECONCILE_ACCOUNT_STATUS_EXECUTING - "
            f"phase RECONCILE_ACCOUNT_PHASE_PLATFORM"
        )
        
        star_msg = star_network_pb2.StarCitizenMessage(
            reconcile_account_update_notification=reconcile_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent ReconcileAccountUpdateNotificationMessage (EXECUTING) - {reconcile_msg.update_details} (wrapped)")
        logger.info("🔍 Message format matches reverse engineered function FUN_140ba5af0")

    async def send_reconcile_account_sequence(self, writer, auth_data, session_id, sequence_number):
        """Send the complete ReconcileAccountUpdateNotification sequence matching real client logs"""
        logger.info("📤 Sending REAL CLIENT RECONCILE SEQUENCE...")
        
        # Use real client data format
        command_id = str(uuid.uuid4())  # Real UUID format like ccba28d8-0837-484e-b9eb-49c9a652f69c
        account_id = auth_data.get("account_id", "1000001")
        character_geid = "200146295196"  # Real GEID from logs
        account_urn = f"urn:sc:platform:account:integer:{account_id}"
        player_urn = f"urn:sc:global:player:geid:{character_geid}"
        
        # Sequence 1: ReconcileAccount started - EXECUTING/UNSPECIFIED
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "ReconcileAccount started",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED",
            25  # Progress
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 2: Started processing LTP items - EXECUTING/LTP
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Started processing 411 Long-Term persistence items",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_LTP",
            35
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 3: Finished processing LTP items - EXECUTING/LTP
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Finished processing 411 Long-Term persistence items",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_LTP",
            50
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 4: Started processing platform items - EXECUTING/PLATFORM
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Started processing 41 platform items",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_PLATFORM",
            60
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 5: Retrieved all items - EXECUTING/UNSPECIFIED
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Retrieved all items",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED",
            70
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 6: Started processing entitlements - EXECUTING/PLATFORM
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Started processing 443 entitlements",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_PLATFORM",
            80
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 7: Finished processing platform items - EXECUTING/PLATFORM
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Finished processing 41 platform items",
            "RECONCILE_ACCOUNT_STATUS_EXECUTING",
            "RECONCILE_ACCOUNT_PHASE_PLATFORM",
            90
        )
        await asyncio.sleep(0.1)
        sequence_number += 1
        
        # Sequence 8: Account reconciliation complete - COMPLETE/UNSPECIFIED
        await self.send_single_reconcile_message(
            writer, auth_data, session_id, sequence_number,
            command_id, account_urn, player_urn,
            "Account reconciliation complete",
            "RECONCILE_ACCOUNT_STATUS_COMPLETE",
            "RECONCILE_ACCOUNT_PHASE_UNSPECIFIED",
            100
        )
        await asyncio.sleep(0.2)
        
        logger.info("✅ REAL CLIENT RECONCILE SEQUENCE COMPLETED")

    async def send_single_reconcile_message(self, writer, auth_data, session_id, sequence_number, 
                                           command_id, account_urn, player_urn, details, status, phase, progress):
        """Send a single ReconcileAccountUpdateNotification message matching real client format"""
        reconcile_msg = star_network_pb2.ReconcileAccountUpdateNotificationMessage()
        
        # Map status strings to protobuf enums
        if status == "RECONCILE_ACCOUNT_STATUS_EXECUTING":
            # Use IN_PROGRESS for executing status
            reconcile_msg.phase = star_network_pb2.ReconcileAccountUpdateNotificationMessage.Phase.IN_PROGRESS
        elif status == "RECONCILE_ACCOUNT_STATUS_COMPLETE":
            reconcile_msg.phase = star_network_pb2.ReconcileAccountUpdateNotificationMessage.Phase.COMPLETED
        else:
            reconcile_msg.phase = star_network_pb2.ReconcileAccountUpdateNotificationMessage.Phase.COMPLETED
        
        reconcile_msg.account_id = auth_data.get("account_id", "1000001")
        reconcile_msg.progress_percentage = progress
        
        # Create the exact message format from real client logs
        reconcile_msg.update_details = (
            f"Received an entitlement status update message with values: "
            f"command id {command_id} - "
            f"details {details} - "
            f"account urn {account_urn} - "
            f"player urn {player_urn} - "
            f"status {status} - "
            f"phase {phase}"
        )
        
        star_msg = star_network_pb2.StarCitizenMessage(
            reconcile_account_update_notification=reconcile_msg,
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time() * 1000),
            sequence_number=sequence_number,
            session_id=session_id
        )
        await self.send_protobuf_message(writer, star_msg)
        logger.info(f"📤 Sent ReconcileAccountUpdate: {details} ({status}/{phase})")

async def main():
    """Main entry point"""
    server = StarCitizenDiffusionServer()
    
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
        await server.stop_server()
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        await server.stop_server()

if __name__ == "__main__":
    asyncio.run(main())

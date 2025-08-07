#!/usr/bin/env python3
"""
Google APIs gRPC Server
Handles all Google API endpoints and protobuf types including:
- OAuth2, IAM, Traffic Director
- gRPC status types
- Envoy configuration
- Protobuf well-known types
"""

import asyncio
import grpc
import json
import logging
import time
from concurrent import futures
from typing import Dict, Any, Optional
import struct
from google.protobuf import any_pb2, struct_pb2, wrappers_pb2
from google.protobuf.json_format import MessageToDict, ParseDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('google_apis_server.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class GoogleAPIsHandler:
    """Handler for all Google APIs and protobuf types"""
    
    def __init__(self):
        self.type_registry = {
            # Core Google APIs
            "type.googleapis.com": self.handle_type_url,
            "oauth2.googleapis.com": self.handle_oauth2,
            "iam.googleapis.com": self.handle_iam,
            "traffic-director-c2p.xds.googleapis.com": self.handle_traffic_director,
            "directpath-pa.googleapis.com": self.handle_directpath,
            
            # gRPC status types
            "type.googleapis.com/grpc.status": self.handle_grpc_status,
            
            # Envoy types
            "type.googleapis.com/envoy.config.route.v3.FilterConfig": self.handle_envoy_filter,
            "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager": self.handle_envoy_http_manager,
            
            # XDS types
            "type.googleapis.com/xds.type.v3.TypedStruct": self.handle_xds_typed_struct,
            "type.googleapis.com/udpa.type.v1.TypedStruct": self.handle_udpa_typed_struct,
            
            # Protobuf well-known types
            "type.googleapis.com/google.protobuf.NullValue": self.handle_null_value,
            "type.googleapis.com/google.protobuf.Value": self.handle_protobuf_value,
        }
        
        # gRPC status field mappings
        self.grpc_status_fields = {
            "int": ["errno", "file_line", "stream_id", "grpc_status", "offset", "index", 
                   "size", "http2_error", "tsi_code", "wsa_error", "fd", "http_status",
                   "occurred_during_write", "channel_connectivity_state", "lb_policy_drop"],
            "str": ["description", "file", "os_error", "syscall", "target_address",
                   "grpc_message", "raw_bytes", "tsi_error", "filename", "key", "value"],
            "time": ["created_time"]
        }

    async def handle_type_url(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle generic type.googleapis.com URLs"""
        logger.info(f"🔗 Handling type URL: {type_url}")
        
        if type_url.endswith("/%s"):
            # Template URL - return format info
            return {
                "type_url": type_url,
                "format": "template",
                "description": "Template URL for dynamic type resolution"
            }
        
        return {
            "type_url": type_url,
            "status": "handled",
            "timestamp": time.time()
        }

    async def handle_oauth2(self, endpoint: str, data: bytes = None) -> Dict[str, Any]:
        """Handle OAuth2 API requests"""
        logger.info(f"🔐 OAuth2 request to: {endpoint}")
        
        return {
            "service": "oauth2",
            "endpoint": endpoint,
            "token_type": "Bearer",
            "access_token": f"mock_token_{int(time.time())}",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/cloud-platform"
        }

    async def handle_iam(self, endpoint: str, data: bytes = None) -> Dict[str, Any]:
        """Handle IAM API requests"""
        logger.info(f"👤 IAM request to: {endpoint}")
        
        return {
            "service": "iam",
            "endpoint": endpoint,
            "permissions": ["iam.serviceAccounts.get", "iam.serviceAccounts.list"],
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:test@example.com"]
                }
            ]
        }

    async def handle_traffic_director(self, endpoint: str, data: bytes = None) -> Dict[str, Any]:
        """Handle Traffic Director XDS requests"""
        logger.info(f"🚦 Traffic Director request to: {endpoint}")
        
        return {
            "service": "traffic-director",
            "endpoint": endpoint,
            "version_info": "1.0",
            "resources": [
                {
                    "name": "default-route",
                    "type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
                }
            ]
        }

    async def handle_directpath(self, endpoint: str, data: bytes = None) -> Dict[str, Any]:
        """Handle DirectPath API requests"""
        logger.info(f"🛣️ DirectPath request to: {endpoint}")
        
        return {
            "service": "directpath",
            "endpoint": endpoint,
            "path_available": True,
            "latency_ms": 5
        }

    async def handle_grpc_status(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle gRPC status types"""
        logger.info(f"📊 gRPC status request: {type_url}")
        
        # Extract field type and name from URL
        parts = type_url.split(".")
        if len(parts) >= 4:
            field_type = parts[-2]  # int, str, time
            field_name = parts[-1]  # specific field name
            
            if field_type in self.grpc_status_fields:
                return {
                    "type_url": type_url,
                    "field_type": field_type,
                    "field_name": field_name,
                    "value": self.get_mock_status_value(field_type, field_name)
                }
        
        return {
            "type_url": type_url,
            "status": "unknown_field"
        }

    def get_mock_status_value(self, field_type: str, field_name: str) -> Any:
        """Generate mock values for gRPC status fields"""
        if field_type == "int":
            return {
                "errno": 0,
                "grpc_status": 0,  # OK
                "http_status": 200,
                "stream_id": 1,
                "offset": 0,
                "index": 0,
                "size": 1024
            }.get(field_name, 0)
        elif field_type == "str":
            return {
                "description": "Operation completed successfully",
                "grpc_message": "OK",
                "target_address": "127.0.0.1:8080",
                "filename": "server.log"
            }.get(field_name, "")
        elif field_type == "time":
            return int(time.time() * 1000000)  # microseconds
        
        return None

    async def handle_envoy_filter(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle Envoy filter configuration"""
        logger.info(f"🔧 Envoy filter config: {type_url}")
        
        return {
            "type_url": type_url,
            "name": "http_router",
            "typed_config": {
                "@type": type_url,
                "dynamic_stats": True
            }
        }

    async def handle_envoy_http_manager(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle Envoy HTTP connection manager"""
        logger.info(f"🌐 Envoy HTTP manager: {type_url}")
        
        return {
            "type_url": type_url,
            "stat_prefix": "ingress_http",
            "codec_type": "AUTO",
            "route_config": {
                "name": "local_route",
                "virtual_hosts": [
                    {
                        "name": "local_service",
                        "domains": ["*"],
                        "routes": [
                            {
                                "match": {"prefix": "/"},
                                "route": {"cluster": "service_cluster"}
                            }
                        ]
                    }
                ]
            }
        }

    async def handle_xds_typed_struct(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle XDS TypedStruct"""
        logger.info(f"📋 XDS TypedStruct: {type_url}")
        
        return {
            "type_url": type_url,
            "type": "struct",
            "value": {
                "fields": {
                    "config": {
                        "string_value": "default_config"
                    }
                }
            }
        }

    async def handle_udpa_typed_struct(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle UDPA TypedStruct"""
        logger.info(f"📋 UDPA TypedStruct: {type_url}")
        
        return {
            "type_url": type_url,
            "type": "struct",
            "value": {
                "fields": {
                    "version": {
                        "string_value": "v1"
                    }
                }
            }
        }

    async def handle_null_value(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle protobuf NullValue"""
        logger.info(f"🔄 Protobuf NullValue: {type_url}")
        
        return {
            "type_url": type_url,
            "value": None
        }

    async def handle_protobuf_value(self, type_url: str, data: bytes = None) -> Dict[str, Any]:
        """Handle protobuf Value"""
        logger.info(f"🔄 Protobuf Value: {type_url}")
        
        return {
            "type_url": type_url,
            "kind": "string_value",
            "string_value": "default_value"
        }

class GoogleAPIsServer:
    """Main server for handling Google APIs"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 443):
        self.host = host
        self.port = port
        self.handler = GoogleAPIsHandler()
        self.server = None

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming requests"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"🔌 New connection from {client_addr}")
        
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                # Try to parse as HTTP-like request
                request_str = data.decode('utf-8', errors='ignore')
                logger.info(f"📥 Received: {request_str[:200]}...")
                
                # Extract endpoint from request
                endpoint = self.extract_endpoint(request_str)
                response = await self.process_request(endpoint, data)
                
                # Send JSON response
                response_json = json.dumps(response, indent=2)
                http_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_json)}\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "\r\n"
                    f"{response_json}"
                )
                
                writer.write(http_response.encode())
                await writer.drain()
                
                logger.info(f"📤 Sent response ({len(response_json)} bytes)")
                break
                
        except Exception as e:
            logger.error(f"❌ Error handling request: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    def extract_endpoint(self, request_str: str) -> str:
        """Extract endpoint from request string"""
        lines = request_str.split('\n')
        if lines:
            first_line = lines[0]
            parts = first_line.split()
            if len(parts) >= 2:
                return parts[1].lstrip('/')
        return "unknown"

    async def process_request(self, endpoint: str, data: bytes) -> Dict[str, Any]:
        """Process request and route to appropriate handler"""
        logger.info(f"🔄 Processing endpoint: {endpoint}")
        
        # Check if endpoint matches any registered type
        for type_pattern, handler in self.handler.type_registry.items():
            if type_pattern in endpoint or endpoint.startswith(type_pattern):
                return await handler(endpoint, data)
        
        # Default response for unmatched endpoints
        return {
            "endpoint": endpoint,
            "status": "not_found",
            "message": "Endpoint not recognized",
            "available_types": list(self.handler.type_registry.keys())
        }

    def create_ssl_context(self):
        """Create SSL context for HTTPS"""
        import ssl
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            context.load_cert_chain('server.crt', 'server.key')
            logger.info("🔒 SSL certificate loaded")
        except FileNotFoundError:
            logger.warning("⚠️ SSL certificate not found, using self-signed")
            self.create_self_signed_cert()
            context.load_cert_chain('server.crt', 'server.key')
        return context

    def create_self_signed_cert(self):
        """Create self-signed certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from datetime import datetime, timedelta
            import ipaddress
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False
            ).sign(private_key, hashes.SHA256())
            
            with open("server.crt", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open("server.key", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))
        except ImportError:
            logger.error("❌ Install cryptography: pip install cryptography")

    async def start_server(self):
        """Start the async server"""
        logger.info(f"🚀 Starting Google APIs HTTPS server on {self.host}:{self.port}")
        
        # Create SSL context
        ssl_context = self.create_ssl_context()
        
        server = await asyncio.start_server(
            self.handle_request,
            self.host,
            self.port,
            ssl=ssl_context
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f"✅ Server running on {addr[0]}:{addr[1]}")
        
        async with server:
            await server.serve_forever()

async def main():
    """Main entry point"""
    server = GoogleAPIsServer(host="127.0.0.1", port=443)
    
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Google APIs HTTPS Server - Port 443
Handles patched Google API endpoints redirected to 127.0.0.1
"""

import asyncio
import ssl
import json
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GoogleAPIsHTTPSServer:
    def __init__(self):
        self.endpoints = {
            "iam.googleapis.com": self.handle_iam,
            "oauth2.googleapis.com": self.handle_oauth2,
            "traffic-director-c2p.xds.googleapis.com": self.handle_traffic_director,
            "directpath-pa.googleapis.com": self.handle_directpath,
            ".googleapis.com": self.handle_generic_googleapis
        }

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            context.load_cert_chain('server.crt', 'server.key')
            logger.info("🔒 SSL certificate loaded")
        except FileNotFoundError:
            self.create_self_signed_cert()
            context.load_cert_chain('server.crt', 'server.key')
        return context

    def create_self_signed_cert(self):
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from datetime import datetime, timedelta
            import ipaddress
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
            
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
            logger.info("✅ Self-signed certificate created")
        except ImportError:
            logger.error("❌ Install cryptography: pip install cryptography")

    async def handle_iam(self, path, headers):
        return {
            "bindings": [{"role": "roles/viewer", "members": ["user:test@example.com"]}],
            "etag": "BwXhqDOoLuA=",
            "version": 1
        }

    async def handle_oauth2(self, path, headers):
        return {
            "access_token": f"ya29.mock_token_{int(time.time())}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/cloud-platform"
        }

    async def handle_traffic_director(self, path, headers):
        return {
            "version_info": "1.0",
            "resources": [{
                "@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
                "name": "default_route"
            }],
            "type_url": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
            "nonce": f"nonce_{int(time.time())}"
        }

    async def handle_directpath(self, path, headers):
        return {
            "path_available": True,
            "latency_ms": 5,
            "endpoints": [{"address": "127.0.0.1", "port": 443, "protocol": "HTTP2"}]
        }

    async def handle_generic_googleapis(self, path, headers):
        return {"status": "ok", "service": "googleapis", "timestamp": time.time()}

    async def handle_client(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"🔌 HTTPS connection from {client_addr}")
        
        try:
            data = await reader.read(4096)
            request = data.decode('utf-8', errors='ignore')
            
            # Parse HTTP request
            lines = request.split('\n')
            if not lines:
                return
                
            request_line = lines[0]
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract host and path
            host = headers.get('host', '127.0.0.1')
            path = request_line.split()[1] if len(request_line.split()) > 1 else '/'
            
            logger.info(f"📥 {host}{path}")
            
            # Route to handler
            response_data = {"error": "not_found"}
            for endpoint, handler in self.endpoints.items():
                if endpoint in host:
                    response_data = await handler(path, headers)
                    break
            
            # Send JSON response
            response_json = json.dumps(response_data, indent=2)
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
            logger.info(f"📤 Response sent ({len(response_json)} bytes)")
            
        except Exception as e:
            logger.error(f"❌ Error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start_server(self):
        ssl_context = self.create_ssl_context()
        server = await asyncio.start_server(
            self.handle_client, '127.0.0.1', 443, ssl=ssl_context
        )
        
        logger.info("🚀 Google APIs HTTPS server running on https://127.0.0.1:443")
        logger.info("📡 Handling: iam, oauth2, traffic-director, directpath, .googleapis.com")
        
        async with server:
            await server.serve_forever()

async def main():
    server = GoogleAPIsHTTPSServer()
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Google APIs gRPC Server - Multiple Ports
Runs on standard Google API ports: 443, 80, 8080, 9090
"""

import grpc
import json
import logging
import time
import threading
from concurrent import futures
from google.protobuf import any_pb2, struct_pb2, wrappers_pb2, empty_pb2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('google_apis_multi_port.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Import our existing servicer
import sys
sys.path.append('.')
from google_apis_grpc_server_sync import GoogleAPIsServicer, GenericServicer

def start_server_on_port(port, description="gRPC"):
    """Start a gRPC server on a specific port"""
    try:
        logger.info(f"🚀 Starting {description} server on 0.0.0.0:{port}")
        
        # Create server
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
        
        # Add our servicer
        generic_servicer = GenericServicer()
        server.add_generic_rpc_handlers((generic_servicer,))
        
        # Try to bind to the port
        listen_addr = f'0.0.0.0:{port}'
        
        if port == 443:
            # For HTTPS/gRPC over TLS
            try:
                import os
                cert_file = 'server.crt'
                key_file = 'server.key'
                
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    with open(key_file, 'rb') as f:
                        private_key = f.read()
                    with open(cert_file, 'rb') as f:
                        certificate_chain = f.read()
                    
                    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
                    server.add_secure_port(listen_addr, server_credentials)
                    logger.info(f"✅ {description} server (secure) running on {listen_addr}")
                else:
                    # Fallback to insecure for testing
                    server.add_insecure_port(listen_addr)
                    logger.info(f"✅ {description} server (insecure fallback) running on {listen_addr}")
            except Exception as e:
                logger.error(f"❌ Failed to start secure server on {port}: {e}")
                return None
        else:
            # Regular insecure gRPC
            server.add_insecure_port(listen_addr)
            logger.info(f"✅ {description} server running on {listen_addr}")
        
        server.start()
        return server
        
    except Exception as e:
        logger.error(f"❌ Failed to start {description} server on port {port}: {e}")
        return None

def main():
    """Start gRPC servers on multiple ports"""
    logger.info("🎮 Starting Star Citizen Google APIs servers on multiple ports...")
    
    # Common Google API ports
    servers = []
    ports_to_try = [
        (443, "HTTPS/gRPC (Google APIs standard)"),
        (80, "HTTP (Google APIs fallback)"),
        (8080, "HTTP Alternative"),
        (9090, "gRPC Standard"),
        (50051, "gRPC Default"),
        (18080, "Alternative gRPC"),
        (19090, "Alternative gRPC")
    ]
    
    for port, description in ports_to_try:
        server = start_server_on_port(port, description)
        if server:
            servers.append((server, port, description))
    
    if not servers:
        logger.error("❌ Failed to start any servers!")
        return
    
    logger.info(f"✅ Started {len(servers)} servers successfully:")
    for _, port, desc in servers:
        logger.info(f"   📡 Port {port}: {desc}")
    
    logger.info("🔧 All servers handling Google API and Star Citizen services")
    logger.info("⏳ Waiting for connections...")
    
    try:
        # Keep all servers running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("🛑 Stopping all servers...")
        for server, port, desc in servers:
            logger.info(f"🛑 Stopping {desc} on port {port}")
            server.stop(grace=5)
        logger.info("✅ All servers stopped")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Startup script for Google APIs servers
Runs both HTTP and gRPC versions simultaneously
"""

import asyncio
import logging
import signal
import sys
from google_apis_server import GoogleAPIsServer
from google_apis_grpc_server import GoogleAPIsGRPCServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

class GoogleAPIsServerManager:
    """Manager for running multiple Google APIs servers"""
    
    def __init__(self):
        self.http_server = GoogleAPIsServer(host="127.0.0.1", port=8080)
        self.grpc_server = GoogleAPIsGRPCServer(host="127.0.0.1", port=50051)
        self.running = False

    async def start_all_servers(self):
        """Start all servers concurrently"""
        logger.info("🚀 Starting all Google APIs servers...")
        
        self.running = True
        
        # Create tasks for both servers
        tasks = [
            asyncio.create_task(self.http_server.start_server(), name="HTTP-Server"),
            asyncio.create_task(self.grpc_server.start_server(), name="gRPC-Server"),
        ]
        
        logger.info("✅ All servers started successfully")
        logger.info("📡 HTTP Server: http://127.0.0.1:8080")
        logger.info("🔌 gRPC Server: 127.0.0.1:50051")
        logger.info("Press Ctrl+C to stop all servers")
        
        try:
            # Wait for all tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
        except KeyboardInterrupt:
            logger.info("🛑 Shutdown signal received")
        finally:
            self.running = False
            # Cancel all tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to finish cancellation
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("✅ All servers stopped")

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"🛑 Received signal {signum}")
            self.running = False
            # Create new event loop for cleanup if needed
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Schedule shutdown
                    loop.create_task(self.shutdown())
            except RuntimeError:
                # No event loop running
                sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("🔄 Initiating graceful shutdown...")
        self.running = False

async def main():
    """Main entry point"""
    manager = GoogleAPIsServerManager()
    manager.setup_signal_handlers()
    
    try:
        await manager.start_all_servers()
    except Exception as e:
        logger.error(f"❌ Server manager error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Application terminated by user")
        sys.exit(0)
# Star Citizen Local Server Infrastructure

A comprehensive local server infrastructure for Star Citizen that fully emulates the game's authentication and networking flow. This setup allows for local testing, debugging, and reverse engineering of Star Citizen's client-server communication.

## 🎯 Overview

This infrastructure implements the complete Star Citizen client connection flow:

```
Star Citizen Client → Diffusion Server → Dedicated Login Server → gRPC Game Server
```

### Server Components

1. **Diffusion Server (Port 8001)** - Initial connection point for service discovery
2. **SSL MITM Proxy (Port 8000)** - Intercepts and logs client traffic 
3. **Dedicated Login Server (Port 9000)** - Handles authentication and JWT token generation
4. **gRPC Game Server (Port 5678)** - Main game server with login notifications and entitlement processing
5. **Google APIs gRPC Server (Port 443)** - Additional API endpoints

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Windows PowerShell** (for the launcher script)
- **Star Citizen Client** (for testing)

### Installation

1. **Clone or extract the server files** to a directory (e.g., `h:\star.c\backup_grpc_server`)

2. **Install Python dependencies:**
   ```powershell
   cd "h:\star.c\backup_grpc_server"
   pip install grpcio grpcio-tools protobuf cryptography
   ```

3. **Generate SSL certificates** (if not present):
   ```powershell
   # The servers will auto-generate self-signed certificates on first run
   # Or manually create them:
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```

4. **Launch all servers:**
   ```powershell
   .\run_all_servers.ps1
   ```

### Verification

Check that all servers are running:
```powershell
netstat -an | Select-String ":443|:5678|:8000|:8001|:9000"
```

You should see all ports listening:
- Port 443: Google APIs gRPC Server
- Port 5678: Star Citizen gRPC Game Server 
- Port 8000: SSL MITM Proxy UI
- Port 8001: Diffusion Server
- Port 9000: Dedicated Login Server

## 🔧 Configuration

### User Accounts

Edit `dedicated_login_server.py` to add/modify user accounts:

```python
self.users_db = {
    'test.pilot@robertsspaceindustries.com': {
        'password_hash': self.hash_password('test_password_123'),
        'displayname': 'TestPilot',
        'citizen_id': '2001462951',
        'account_id': '1000001',
        'active': True
    }
}
```

### Game Data

Update `login_data_real_client.json` with appropriate game data:

```json
{
  "access_token": "fa8a335e-c3de-da45-b336-ef1ffc15d7eb",
  "account_id": "1000001",
  "displayname": "TestPilot",
  "email": "test.pilot@robertsspaceindustries.com",
  "character_id": "char_testpilot_001",
  "location": "Stanton_ArcCorp_Area18",
  "universe": "persistent_universe"
}
```

## 🌐 Network Flow

### 1. Service Discovery Phase
- Client connects to **Diffusion Server (port 8000 via MITM proxy)**
- Server responds with available services and endpoints
- Client discovers authentication and game server locations

### 2. Authentication Phase  
- Client redirected to **Dedicated Login Server (port 9000)**
- Web interface provides login form
- Server generates JWT tokens and updates `loginData.json`
- Client receives authentication credentials

### 3. Game Server Phase
- Client connects to **gRPC Game Server (port 5678)**
- Server handles `InitiateLogin` and `LoginNotificationStream`
- Complete reconcile account sequence sent via gRPC streaming
- Client receives entitlement status updates and character data

## 📊 Monitoring and Debugging

### Log Files

Each server generates detailed logs:
- `diffusion_server.log` - Service discovery and client routing
- `dedicated_login_server.log` - Authentication attempts and JWT generation
- `sc_production_v13_enhanced_flow.log` - Game server operations and gRPC calls
- `google_apis_grpc_server.log` - API server requests
- `ssl_mitm_ui.log` - Traffic interception and analysis

### Web Interfaces

- **Dedicated Login Server**: `http://127.0.0.1:9000`
  - Login interface for authentication
  - Status page showing active sessions
  - Verification endpoint: `/verify`

- **SSL MITM Proxy**: `http://127.0.0.1:8000` 
  - Traffic capture and analysis
  - Real-time packet inspection
  - Protocol decode and hex dumps

### Traffic Capture

Monitor real client traffic in `capture/sd.json`:
```json
{
  "timestamp": "2025-08-07T22:54:02.579022",
  "direction": "client->server", 
  "size": 66,
  "type": "Heartbeat",
  "hex_data": "3a000000efbeadde...",
  "connection": "127.0.0.1:50639"
}
```

## 🔍 Protocol Details

### Protobuf Messages

The infrastructure uses Star Citizen's protobuf definitions:
- `star_network.proto` - Core networking messages
- `login_service.proto` - Authentication and login flow
- `character_service.proto` - Character data management

### Message Flow

1. **ServiceDiscoveryResponse** - Available services and endpoints
2. **LobbyDestinationResponse** - Game server locations
3. **RegionSetupResponse** - Regional configuration
4. **InitiateLoginRequest/Response** - Authentication handshake
5. **LoginNotificationStream** - Real-time login progression
6. **ReconcileAccountUpdateNotification** - Entitlement processing

### JWT Token Structure

Generated tokens include all fields expected by the client:
```json
{
  "iss": "https://robertsspaceindustries.com",
  "account_id": "1000001",
  "citizen_id": "2001462951", 
  "displayname": "TestPilot",
  "scope": ["game:access", "game:play", "game:chat"],
  "roles": ["citizen", "backer", "player"]
}
```

## 🛠️ Troubleshooting

### Common Issues

**Client not connecting:**
- Verify all servers are running (`netstat` check)
- Check firewall/antivirus blocking ports
- Ensure SSL certificates are valid

**Authentication failures:**
- Check username/password in `dedicated_login_server.py`
- Verify JWT token generation in logs
- Confirm `loginData.json` is being updated

**gRPC errors:**
- Ensure protobuf files are generated correctly
- Check SSL certificate for gRPC server (port 5678)
- Verify client expects correct message formats

### Manual Server Control

Start individual servers for debugging:
```powershell
# Start specific servers
python dedicated_login_server.py
python sc_production_server_v13_final.py  
python diffusion_server.py
python ssl_mitm_ui.py
```

Stop all servers:
```powershell
Get-Process | Where-Object {$_.ProcessName -eq "python"} | Stop-Process -Force
```

## 📝 Development

### Adding New Features

1. **Extend protobuf definitions** in `.proto` files
2. **Regenerate Python classes**:
   ```bash
   python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. *.proto
   ```
3. **Update server handlers** in respective Python files
4. **Test with real client** using traffic capture

### Debugging Client Behavior

1. **Enable detailed logging** in server files
2. **Use MITM proxy** to capture all traffic
3. **Compare with real server responses** 
4. **Analyze hex dumps** in capture files

## 🔒 Security Notes

⚠️ **This is for development/testing only!**

- Uses self-signed SSL certificates
- Hardcoded passwords and tokens
- No rate limiting or security hardening
- Logs contain sensitive authentication data

## 📚 File Structure

```
backup_grpc_server/
├── README.md                           # This file
├── run_all_servers.ps1                 # Main launcher script
├── start.bat                           # Client launcher (batch file)
├── start_client.ps1                    # Client launcher (PowerShell - recommended)
├── dedicated_login_server.py           # Authentication server (port 9000)
├── diffusion_server.py                 # Service discovery (port 8001)  
├── sc_production_server_v13_final.py   # Main game server (port 5678)
├── ssl_mitm_ui.py                      # Traffic proxy (port 8000)
├── google_apis_grpc_server_sync.py     # API server (port 443)
├── *.proto                             # Protocol buffer definitions
├── *_pb2.py                            # Generated protobuf classes
├── login_data_real_client.json         # Game configuration data
├── server.crt / server.key             # SSL certificates
├── *.log                               # Server log files
└── capture/
    └── sd.json                         # Traffic capture data
```

## 🎮 Testing with Star Citizen

### Client Configuration

⚠️ **Important**: The Star Citizen client (`starcitizen.exe`) must be configured to redirect all network traffic to localhost (`127.0.0.1`) instead of the official servers.

**Method 1: Using start.bat (Simple)**
1. Use the provided `start.bat` file to launch Star Citizen
2. This batch file automatically applies the necessary redirects
3. Simply run: `start.bat` from the server directory

**Method 2: Using start_client.ps1 (Recommended)**
1. Run PowerShell as Administrator
2. Use the provided `start_client.ps1` PowerShell script
3. Enhanced error checking and automatic server detection
4. Run: `.\start_client.ps1` from the server directory

**Method 2: Manual Configuration**
- Modify hosts file or use network redirection tools
- Redirect all RSI domains to `127.0.0.1`
- Ensure the client connects to port 8000 (MITM proxy)

### Testing Steps

1. **Start all servers** using `run_all_servers.ps1`
2. **Verify servers are running** (see Verification section above)
3. **Launch Star Citizen** using `start.bat` or configured client
4. **Monitor logs** for connection progression
5. **Use web interfaces** for authentication and debugging

### Expected Client Flow

The client should progress through:
- **Service discovery** (Diffusion Server - port 8001 via 8000 proxy)
- **Authentication login** (Dedicated Login Server - port 9000)  
- **gRPC game server connection** (Game Server - port 5678)
- **Entitlement processing** (LoginNotificationStream with reconcile sequence)
- **Character data loading** (Character service responses)

### Client Network Redirection

The infrastructure expects the Star Citizen client to have **all network traffic redirected** to localhost:

```
Official RSI Servers          →    Local Infrastructure
api.robertsspaceindustries.com →    127.0.0.1:443 (Google APIs)
diffusion.robertsspaceindustries.com → 127.0.0.1:8000 (MITM Proxy)
auth.robertsspaceindustries.com →   127.0.0.1:9000 (Login Server)
game-servers.robertsspaceindustries.com → 127.0.0.1:5678 (gRPC Game Server)
```

⚠️ **Security Note**: This redirection intercepts all Star Citizen network communication. Only use this setup in isolated testing environments.

## 🤝 Contributing

This infrastructure is designed for Star Citizen research and development. Feel free to:
- Add new protocol message handlers
- Improve authentication security
- Enhance logging and debugging features
- Document additional client behaviors

## 📄 License

For educational and research purposes only. Star Citizen is a trademark of Cloud Imperium Games.

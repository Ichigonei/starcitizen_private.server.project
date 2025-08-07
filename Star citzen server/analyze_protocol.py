#!/usr/bin/env python3
"""
Star Citizen Binary Protocol Analyzer
Analyzes the binary messages from real Star Citizen clients
"""

import struct
import binascii

def analyze_binary_message(hex_data: str):
    """Analyze a binary message from Star Citizen client"""
    
    print(f"🔍 Analyzing message: {hex_data}")
    print(f"📏 Length: {len(hex_data) // 2} bytes")
    
    # Convert hex to bytes
    data = binascii.unhexlify(hex_data)
    
    # Try to parse header
    if len(data) >= 8:
        # First 4 bytes might be length
        length = struct.unpack('<I', data[:4])[0]
        print(f"📦 Possible length field: {length}")
        
        # Next 4 bytes might be magic/type
        magic = data[4:8]
        print(f"✨ Magic bytes: {magic.hex()} ({magic})")
    
    # Look for ASCII strings
    ascii_content = ""
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # Printable ASCII
            ascii_content += chr(byte)
        else:
            if ascii_content and len(ascii_content) > 2:
                print(f"📝 ASCII string at offset {i-len(ascii_content)}: '{ascii_content}'")
            ascii_content = ""
    
    if ascii_content and len(ascii_content) > 2:
        print(f"📝 ASCII string at end: '{ascii_content}'")
    
    # Look for specific patterns
    if b"diff.service.online" in data:
        print("✅ Contains: diff.service.online")
    if b"Star Citizen Game Client" in data:
        print("✅ Contains: Star Citizen Game Client")
    if b"sc_client" in data:
        print("✅ Contains: sc_client")
    
    # Try to find protobuf-like structures
    print("\n🔬 Protobuf analysis:")
    for i in range(len(data) - 1):
        if data[i] == 0x0a:  # Protobuf string field marker
            length = data[i + 1] if i + 1 < len(data) else 0
            if length > 0 and i + 2 + length <= len(data):
                string_data = data[i + 2:i + 2 + length]
                if all(32 <= b <= 126 for b in string_data):  # All printable
                    print(f"  📄 Field at {i}: '{string_data.decode()}'")
    
    print("=" * 60)

# Analyze the real Star Citizen client message
sc_message = "54000000efbeadde0a13646966662e736572766963652e6f6e6c696e65123b0a185374617220436974697a656e2047616d6520436c69656e74120973635f636c69656e741a1408d29bc7d38daebafb43109bddf0e1ada4f3a0181800"

print("🎮 STAR CITIZEN CLIENT MESSAGE ANALYSIS")
print("=" * 60)
analyze_binary_message(sc_message)

# Create a proper binary response
def create_star_citizen_response():
    """Create a proper binary response for Star Citizen client"""
    
    print("🛠️ Creating Star Citizen compatible response...")
    
    # Response data structure
    response_json = {
        "service_available": True,
        "status": "ONLINE",
        "service_version": "4.1.149.3486",
        "timestamp": 1754160000000,
        "auth_endpoint": "https://127.0.0.1:8443",
        "session_token": "sc_session_12345"
    }
    
    import json
    json_data = json.dumps(response_json).encode('utf-8')
    
    # Create binary response with proper header
    length = len(json_data)
    header = struct.pack('<I', length)  # 4-byte little-endian length
    magic = b'\xef\xbe\xad\xde'  # Magic bytes from client
    
    full_response = header + magic + json_data
    
    print(f"📤 Response length: {len(full_response)} bytes")
    print(f"📤 Response hex: {full_response.hex()}")
    print(f"📤 Response JSON: {response_json}")
    
    return full_response

create_star_citizen_response()

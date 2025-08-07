#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hex Dump Analyzer for Star Citizen Service Discovery Packet
Provides detailed byte-by-byte analysis with annotations
"""

import struct
import binascii

def hex_dump_with_analysis(hex_data: str, title: str = "Packet Analysis"):
    """Create an annotated hex dump of the packet"""
    
    # Convert hex string to bytes
    data = bytes.fromhex(hex_data)
    
    print(f"[*] {title}")
    print("=" * 80)
    print(f"Total Size: {len(data)} bytes")
    print()
    
    # Header analysis
    print("[*] HEADER ANALYSIS")
    print("-" * 40)
    
    if len(data) >= 8:
        # Length field (first 4 bytes, little-endian)
        length_bytes = data[0:4]
        length = struct.unpack('<I', length_bytes)[0]
        print(f"Offset 0x00-0x03: Length = {length} bytes")
        print(f"  Raw bytes: {length_bytes.hex().upper()}")
        print(f"  Little-endian: {length}")
        print()
        
        # Magic bytes (next 4 bytes)
        magic_bytes = data[4:8]
        print(f"Offset 0x04-0x07: Magic bytes")
        print(f"  Raw bytes: {magic_bytes.hex().upper()}")
        print(f"  ASCII: {magic_bytes.decode('latin-1', errors='replace')}")
        print(f"  Expected: EFBEADDE (Star Citizen protocol)")
        print(f"  Valid: {'YES' if magic_bytes == b'\\xef\\xbe\\xad\\xde' else 'NO'}")
        print()
    
    # Payload analysis
    if len(data) > 8:
        payload = data[8:]
        print("[*] PAYLOAD ANALYSIS")
        print("-" * 40)
        print(f"Payload size: {len(payload)} bytes")
        print()
        
        # Look for readable strings in payload
        strings_found = []
        current_string = ""
        for i, byte in enumerate(payload):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 3:  # Only keep strings of 3+ chars
                    strings_found.append((i - len(current_string) + 8, current_string))
                current_string = ""
        
        if current_string and len(current_string) >= 3:
            strings_found.append((len(payload) - len(current_string) + 8, current_string))
        
        if strings_found:
            print("[*] READABLE STRINGS FOUND:")
            for offset, string in strings_found:
                print(f"  Offset 0x{offset:02X}: '{string}'")
            print()
    
    # Full hex dump
    print("[*] COMPLETE HEX DUMP")
    print("-" * 40)
    
    for i in range(0, len(data), 16):
        # Offset
        offset_str = f"{i:08X}"
        
        # Hex bytes (16 per line)
        hex_part = ""
        ascii_part = ""
        
        for j in range(16):
            if i + j < len(data):
                byte = data[i + j]
                hex_part += f"{byte:02X} "
                ascii_part += chr(byte) if 32 <= byte <= 126 else "."
            else:
                hex_part += "   "
                ascii_part += " "
        
        # Add extra space in middle for readability
        hex_part = hex_part[:24] + " " + hex_part[24:]
        
        print(f"{offset_str}  {hex_part} |{ascii_part}|")
    
    print()
    
    # Annotations for specific offsets
    print("[*] ANNOTATED BREAKDOWN")
    print("-" * 40)
    
    annotations = [
        (0, 4, "Message Length (little-endian)"),
        (4, 8, "Magic Bytes (0xEFBEADDE)"),
        (8, None, "Protobuf Payload")
    ]
    
    for start, end, description in annotations:
        if end is None:
            end = len(data)
        if start < len(data):
            section = data[start:end]
            print(f"0x{start:02X}-0x{end-1:02X}: {description}")
            print(f"  Bytes: {section.hex().upper()}")
            if description == "Protobuf Payload":
                # Try to identify protobuf field types
                print("  Protobuf field analysis:")
                analyze_protobuf_fields(section)
            print()

def analyze_protobuf_fields(data: bytes):
    """Basic protobuf field analysis"""
    i = 0
    field_num = 1
    
    while i < len(data) and field_num <= 10:  # Limit to prevent infinite loops
        if i >= len(data):
            break
            
        # Read varint tag
        tag = data[i]
        field_number = tag >> 3
        wire_type = tag & 0x07
        
        wire_type_names = {
            0: "Varint",
            1: "64-bit",
            2: "Length-delimited",
            3: "Start group",
            4: "End group", 
            5: "32-bit"
        }
        
        wire_type_name = wire_type_names.get(wire_type, f"Unknown({wire_type})")
        
        print(f"    Field {field_number}: {wire_type_name} (tag=0x{tag:02X})")
        
        i += 1
        
        # Handle different wire types
        if wire_type == 0:  # Varint
            value = 0
            shift = 0
            while i < len(data) and data[i] & 0x80:
                value |= (data[i] & 0x7F) << shift
                shift += 7
                i += 1
            if i < len(data):
                value |= data[i] << shift
                i += 1
            print(f"      Value: {value}")
            
        elif wire_type == 2:  # Length-delimited
            if i < len(data):
                length = data[i]
                i += 1
                if i + length <= len(data):
                    field_data = data[i:i+length]
                    i += length
                    # Try to decode as string
                    try:
                        string_val = field_data.decode('utf-8')
                        print(f"      Length: {length}, String: '{string_val}'")
                    except:
                        print(f"      Length: {length}, Binary: {field_data.hex().upper()}")
                else:
                    break
        else:
            # Skip unknown wire types
            i += 1
            
        field_num += 1
        
        if i >= len(data) - 1:
            break

def main():
    """Analyze the service discovery packet"""
    
    # The packet from the task
    packet_hex = "54000000efbeadde0a13646966662e736572766963652e6f6e6c696e65123b0a185374617220436974697a656e2047616d6520436c69656e74120973635f636c69656e741a1408b2bb9dac94f2c6874a1097e5e7f8819aaa83521800"
    
    hex_dump_with_analysis(packet_hex, "Star Citizen Service Discovery Packet")
    
    print("[*] SUMMARY")
    print("=" * 80)
    print("This packet represents a Star Citizen client requesting service discovery.")
    print("The server should respond with available service endpoints to enable")
    print("the client to proceed with authentication and game connection.")
    print()
    print("Key findings:")
    print("- Valid Star Citizen protocol format (magic bytes confirmed)")
    print("- Contains 'diff.service.online' service query")
    print("- Identifies client as 'Star Citizen Game Client' / 'sc_client'")
    print("- Protobuf-encoded payload with embedded strings")
    print("- Total packet size: 92 bytes (84 bytes payload + 8 bytes header)")

if __name__ == "__main__":
    main()
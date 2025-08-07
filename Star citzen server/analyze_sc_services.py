#!/usr/bin/env python3
"""
Star Citizen Service Protocol Decoder
Decodes the hex dump to understand Star Citizen's internal services
"""

import re

def decode_hex_string(hex_data):
    """Convert hex string to ASCII text"""
    # Remove spaces and convert to bytes
    hex_clean = hex_data.replace(' ', '')
    try:
        bytes_data = bytes.fromhex(hex_clean)
        # Try to decode as UTF-8, ignore errors
        return bytes_data.decode('utf-8', errors='ignore')
    except:
        return hex_data

def analyze_star_citizen_services():
    """Analyze the Star Citizen service data from the hex dump"""
    
    hex_data = """00 00 00 61 00 00 00 61 00 00 00 47 65 74 20 63 75 72 72 65 6E 74 20 70 6C 61 79 65 72 27 73 20 41 72 65 6E 61 20 43 6F 6D 6D 61 6E 64 65 72 20 65 6E 74 69 74 6C 65 6D 65 6E 74 73 0A 55 73 61 67 65 3A 20 73 65 72 76 69 63 65 73 2E 61 72 65 6E 61 63 6F 6D 6D 61 6E 64 65 72 2E 67 65 74 5F 65 6E 74 69 74 6C 65 6D 65 6E 74 73 00 00 02 C0 02 00 00 5D 00 00 00 5D 00 00 00 47 65 74 20 61 20 73 70 65 63 69 66 69 63 20 6C 65 64 67 65 72 20 66 72 6F 6D 20 74 68 65 20 70 6C 61 79 65 72 0A 55 73 61 67 65 3A 20 73 65 72 76 69 63 65 73 2E 6C 65 64 67 65 72 2E 67 65 74 5F 66 75 6E 64 73 5F 65 78 74 65 72 6E 61 6C 20 3C 6C 65 64 67 65 72 20 6E 61 6D 65 3E 00 00 00 58 42 00 02 C0 02 00 00 67 72 70 63 3A 20 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 70 72 65 73 65 6E 63 65 2E 76 31 2E 50 72 65 73 65 6E 63 65 53 65 72 76 69 63 65 20 2D 20 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 70 72 65 73 65 6E 63 65 2E 76 31 2E 50 72 65 73 65 6E 63 65 53 74 72 65 61 6D 52 65 71 75 65 73 74 00 5A 00 00 00 5A 00 00 00 74 79 70 65 2E 67 6F 6F 67 6C 65 61 70 69 73 2E 63 6F 6D 2F 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 65 6E 74 69 74 6C 65 6D 65 6E 74 2E 76 31 2E 52 65 63 6F 6E 63 69 6C 65 41 63 63 6F 75 6E 74 55 70 64 61 74 65 4E 6F 74 69 66 69 63 61 74 69 6F 6E 00 69 6E 00 6C 6F 00 00 00 00 00 00 00 00 62 00 00 00 62 00 00 00 63 6F 6D 6D 61 6E 64 73 2F 37 31 37 36 33 61 38 38 2D 39 64 61 63 2D 34 63 34 30 2D 62 39 32 61 2D 36 36 35 37 39 63 64 65 30 33 63 31 2F 67 6C 6F 62 61 6C 2F 65 78 74 65 72 6E 61 6C 2F 65 6E 74 69 74 79 5F 67 72 61 70 68 2F 63 6F 6D 6D 61 6E 64 73 2F 4D 75 74 61 74 65 45 6E 74 69 74 69 65 73 00 02 C0 02 00 00 67 72 70 63 3A 20 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 74 72 61 63 65 2E 76 31 2E 54 72 61 63 65 53 65 72 76 69 63 65 20 2D 20 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 74 72 61 63 65 2E 76 31 2E 43 6F 6C 6C 65 63 74 69 6F 6E 53 74 72 65 61 6D 52 65 71 75 65 73 74 00 3F 00 02 C0 02 00 00 64 00 00 00 64 00 00 00 63 6F 6D 6D 61 6E 64 73 2F 37 31 37 36 33 61 38 38 2D 39 64 61 63 2D 34 63 34 30 2D 62 39 32 61 2D 36 36 35 37 39 63 64 65 30 33 63 31 2F 67 6C 6F 62 61 6C 2F 65 78 74 65 72 6E 61 6C 2F 65 6E 74 69 74 79 5F 67 72 61 70 68 2F 63 6F 6D 6D 61 6E 64 73 2F 4D 75 74 61 74 65 45 6E 74 69 74 69 65 73 2F 23 00 02 00 00 62 00 00 00 62 00 00 00 63 6F 6D 6D 61 6E 64 73 2F 37 31 37 36 33 61 38 38 2D 39 64 61 63 2D 34 63 34 30 2D 62 39 32 61 2D 36 36 35 37 39 63 64 65 30 33 63 31 2F 67 6C 6F 62 61 6C 2F 65 78 74 65 72 6E 61 6C 2F 65 6E 74 69 74 79 5F 67 72 61 70 68 2F 63 6F 6D 6D 61 6E 64 73 2F 4D 75 74 61 74 65 45 6E 74 69 74 69 65 73 00 02 C0 02 00 00 64 00 00 00 64 00 00 00 63 6F 6D 6D 61 6E 64 73 2F 37 31 37 36 33 61 38 38 2D 39 64 61 63 2D 34 63 34 30 2D 62 39 32 61 2D 36 36 35 37 39 63 64 65 30 33 63 31 2F 67 6C 6F 62 61 6C 2F 65 78 74 65 72 6E 61 6C 2F 65 6E 74 69 74 79 5F 67 72 61 70 68 2F 63 6F 6D 6D 61 6E 64 73 2F 4D 75 74 61 74 65 45 6E 74 69 74 69 65 73 2F 23 00 00 00 00 67 00 00 00 67 00 00 00 54 65 73 74 20 67 52 50 43 20 72 70 63 2E 0A 55 73 61 67 65 3A 20 67 72 70 63 5F 65 63 68 6F 5F 72 70 63 20 3C 4D 65 73 73 61 67 65 3D 22 22 3E 20 3C 44 65 6C 61 79 3D 30 3E 20 3C 51 75 65 75 65 4D 6F 64 65 3D 30 3E 20 3C 44 65 6C 61 79 65 64 43 61 6E 63 65 6C 3D 30 3E 20 3C 44 65 61 64 6C 69 6E 65 3D 30 3E 00 62 00 00 00 62 00 00 00 63 6F 6D 6D 61 6E 64 73 2F 37 31 37 36 33 61 38 38 2D 39 64 61 63 2D 34 63 34 30 2D 62 39 32 61 2D 36 36 35 37 39 63 64 65 30 33 63 31 2F 67 6C 6F 62 61 6C 2F 65 78 74 65 72 6E 61 6C 2F 65 6E 74 69 74 79 5F 67 72 61 70 68 2F 63 6F 6D 6D 61 6E 64 73 2F 4D 75 74 61 74 65 45 6E 74 69 74 69 65 73 00 00 00 00 00 00 5E 00 00 00 5E 00 00 00 42 69 44 69 53 74 72 65 61 6D 3A 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 70 75 73 68 2E 76 31 2E 50 75 73 68 53 65 72 76 69 63 65 3A 73 63 2E 65 78 74 65 72 6E 61 6C 2E 73 65 72 76 69 63 65 73 2E 70 75 73 68 2E 76 31 2E 4C 69 73 74 65 6E 52 65 71 75 65 73 74"""
    
    decoded = decode_hex_string(hex_data)
    
    print("🎮 Star Citizen Service Analysis:")
    print("=" * 60)
    
    # Extract readable strings
    lines = decoded.split('\n')
    for i, line in enumerate(lines):
        if line.strip():
            print(f"Line {i+1}: {line}")
    
    print("\n🔍 Identified Services:")
    print("=" * 60)
    
    # Key services found in the hex dump
    services = [
        "services.arenacommander.get_entitlements",
        "services.ledger.get_funds_external",
        "sc.external.services.presence.v1.PresenceService",
        "sc.external.services.presence.v1.PresenceStreamRequest", 
        "sc.external.services.entitlement.v1.ReconcileAccountUpdateNotification",
        "sc.external.services.trace.v1.TraceService",
        "sc.external.services.trace.v1.CollectionStreamRequest",
        "sc.external.services.push.v1.PushService",
        "sc.external.services.push.v1.ListenRequest",
        "commands/*/global/external/entity_graph/commands/MutateEntities"
    ]
    
    for service in services:
        print(f"📋 {service}")
    
    return services

if __name__ == "__main__":
    services = analyze_star_citizen_services()

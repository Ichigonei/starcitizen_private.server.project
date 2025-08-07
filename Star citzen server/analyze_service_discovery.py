#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Star Citizen Service Discovery Packet Analyzer
Analyzes the captured service discovery packet and provides detailed breakdown
"""

import struct
import binascii
import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

# Set UTF-8 encoding for Windows console
if sys.platform == "win32":
    os.system("chcp 65001 > nul")

# Import protobuf classes if available
try:
    import star_network_pb2
    PROTOBUF_AVAILABLE = True
    print("[+] Protobuf classes loaded successfully")
except ImportError as e:
    PROTOBUF_AVAILABLE = False
    print(f"[!] Protobuf classes not available: {e}")

class ServiceDiscoveryAnalyzer:
    """Analyzer for Star Citizen service discovery packets"""
    
    def __init__(self):
        self.packet_data = None
        self.analysis_results = {}
    
    def analyze_packet(self, hex_data: str, ascii_data: str, timestamp: str, connection: str) -> Dict[str, Any]:
        """Analyze a service discovery packet"""
        print("[*] STAR CITIZEN SERVICE DISCOVERY PACKET ANALYSIS")
        print("=" * 80)
        
        # Convert hex to bytes
        packet_bytes = bytes.fromhex(hex_data)
        
        analysis = {
            "timestamp": timestamp,
            "connection": connection,
            "packet_size": len(packet_bytes),
            "hex_data": hex_data,
            "ascii_data": ascii_data,
            "protocol_analysis": {},
            "protobuf_analysis": {},
            "client_info": {},
            "server_response_analysis": {}
        }
        
        # Basic packet structure analysis
        print(f"[i] Packet Size: {len(packet_bytes)} bytes")
        print(f"[i] Timestamp: {timestamp}")
        print(f"[i] Connection: {connection}")
        print(f"[i] ASCII Data: {ascii_data}")
        print()
        
        # Analyze packet structure
        analysis["protocol_analysis"] = self._analyze_protocol_structure(packet_bytes)
        
        # Extract client information
        analysis["client_info"] = self._extract_client_info(packet_bytes, ascii_data)
        
        # Try protobuf parsing
        if PROTOBUF_AVAILABLE:
            analysis["protobuf_analysis"] = self._analyze_protobuf_content(packet_bytes)
        
        # Analyze what the server should respond with
        analysis["server_response_analysis"] = self._analyze_expected_response()
        
        return analysis
    
    def _analyze_protocol_structure(self, packet_bytes: bytes) -> Dict[str, Any]:
        """Analyze the Star Citizen protocol structure"""
        print("[*] PROTOCOL STRUCTURE ANALYSIS")
        print("-" * 40)
        
        structure = {}
        
        if len(packet_bytes) >= 8:
            # Extract header information
            length = struct.unpack('<I', packet_bytes[0:4])[0]
            magic = packet_bytes[4:8]
            
            structure["header"] = {
                "length": length,
                "length_hex": packet_bytes[0:4].hex(),
                "magic_bytes": magic.hex(),
                "magic_ascii": magic.decode('latin-1', errors='ignore')
            }
            
            print(f"[i] Message Length: {length} bytes")
            print(f"[i] Magic Bytes: {magic.hex()} ({magic.decode('latin-1', errors='ignore')})")
            
            # Check if magic bytes match expected Star Citizen protocol
            if magic == b'\xef\xbe\xad\xde':
                structure["protocol_valid"] = True
                print("[+] Valid Star Citizen protocol magic bytes detected")
            else:
                structure["protocol_valid"] = False
                print("[-] Unexpected magic bytes - may not be standard SC protocol")
            
            # Extract payload
            if len(packet_bytes) > 8:
                payload = packet_bytes[8:]
                structure["payload"] = {
                    "size": len(payload),
                    "hex": payload.hex(),
                    "ascii": payload.decode('latin-1', errors='ignore')
                }
                print(f"[i] Payload Size: {len(payload)} bytes")
        
        print()
        return structure
    
    def _extract_client_info(self, packet_bytes: bytes, ascii_data: str) -> Dict[str, Any]:
        """Extract client information from the packet"""
        print("[*] CLIENT INFORMATION EXTRACTION")
        print("-" * 40)
        
        client_info = {}
        
        # Look for known strings in ASCII data
        if "Star Citizen Game Client" in ascii_data:
            client_info["client_type"] = "Star Citizen Game Client"
            print("[+] Confirmed: Star Citizen Game Client")
        
        if "sc_client" in ascii_data:
            client_info["client_identifier"] = "sc_client"
            print("[+] Client Identifier: sc_client")
        
        if "diff.service.online" in ascii_data:
            client_info["service_query"] = "diff.service.online"
            print("[+] Service Query: diff.service.online")
        
        # Try to extract version or build information
        # Look for patterns that might indicate version numbers
        hex_str = packet_bytes.hex()
        
        # Look for timestamp-like patterns (common in SC protocol)
        potential_timestamps = []
        for i in range(0, len(packet_bytes) - 7, 1):
            chunk = packet_bytes[i:i+8]
            if len(chunk) == 8:
                try:
                    # Try as little-endian 64-bit timestamp
                    timestamp = struct.unpack('<Q', chunk)[0]
                    if 1600000000000 < timestamp < 2000000000000:  # Reasonable timestamp range
                        potential_timestamps.append({
                            "offset": i,
                            "timestamp": timestamp,
                            "datetime": datetime.fromtimestamp(timestamp / 1000).isoformat()
                        })
                except:
                    pass
        
        if potential_timestamps:
            client_info["potential_timestamps"] = potential_timestamps
            print(f"[i] Found {len(potential_timestamps)} potential timestamps")
        
        print()
        return client_info
    
    def _analyze_protobuf_content(self, packet_bytes: bytes) -> Dict[str, Any]:
        """Try to parse protobuf content from the packet"""
        print("[*] PROTOBUF ANALYSIS")
        print("-" * 40)
        
        protobuf_analysis = {}
        
        # Skip header and try to parse payload as protobuf
        if len(packet_bytes) > 8:
            payload = packet_bytes[8:]
            
            # Try parsing as ServiceDiscoveryRequest
            try:
                service_request = star_network_pb2.ServiceDiscoveryRequest()
                service_request.ParseFromString(payload)
                
                protobuf_analysis["service_discovery_request"] = {
                    "service_query": service_request.service_query,
                    "client_version": service_request.client_version,
                    "capabilities": list(service_request.capabilities)
                }
                
                print("[+] Successfully parsed as ServiceDiscoveryRequest:")
                print(f"   Service Query: {service_request.service_query}")
                print(f"   Client Version: {service_request.client_version}")
                print(f"   Capabilities: {list(service_request.capabilities)}")
                
            except Exception as e:
                print(f"[-] Failed to parse as ServiceDiscoveryRequest: {e}")
            
            # Try parsing as generic StarCitizenMessage
            try:
                star_message = star_network_pb2.StarCitizenMessage()
                star_message.ParseFromString(payload)
                
                protobuf_analysis["star_citizen_message"] = {
                    "message_id": star_message.message_id,
                    "timestamp": star_message.timestamp,
                    "sequence_number": star_message.sequence_number,
                    "session_id": star_message.session_id,
                    "message_type": star_message.WhichOneof("message_type")
                }
                
                print("[+] Successfully parsed as StarCitizenMessage:")
                print(f"   Message ID: {star_message.message_id}")
                print(f"   Timestamp: {star_message.timestamp}")
                print(f"   Sequence: {star_message.sequence_number}")
                print(f"   Session: {star_message.session_id}")
                print(f"   Type: {star_message.WhichOneof('message_type')}")
                
            except Exception as e:
                print(f"[-] Failed to parse as StarCitizenMessage: {e}")
        
        print()
        return protobuf_analysis
    
    def _analyze_expected_response(self) -> Dict[str, Any]:
        """Analyze what the server should respond with"""
        print("[*] EXPECTED SERVER RESPONSE ANALYSIS")
        print("-" * 40)
        
        response_analysis = {
            "response_type": "ServiceDiscoveryResponse",
            "required_fields": [
                "service_online: true",
                "server_version",
                "server_time",
                "endpoints[]"
            ],
            "critical_endpoints": [
                {
                    "service_name": "authentication_service",
                    "host": "127.0.0.1",
                    "port": 8443,
                    "ssl_enabled": True,
                    "protocols": ["https", "websocket"]
                },
                {
                    "service_name": "diffusion_service", 
                    "host": "127.0.0.1",
                    "port": 8001,
                    "ssl_enabled": False,
                    "protocols": ["http", "websocket"]
                },
                {
                    "service_name": "game_server",
                    "host": "127.0.0.1", 
                    "port": 5678,
                    "ssl_enabled": False,
                    "protocols": ["grpc", "http2"]
                }
            ],
            "protocol_format": {
                "header": "4-byte length (little-endian)",
                "magic": "0xefbeadde",
                "payload": "protobuf ServiceDiscoveryResponse"
            }
        }
        
        print("[+] Server should respond with ServiceDiscoveryResponse containing:")
        print("   - service_online: true")
        print("   - server_version: '1.0.0'")
        print("   - server_time: current timestamp")
        print("   - endpoints: authentication_service, diffusion_service, game_server")
        print()
        print("[*] Critical endpoints for client progression:")
        for endpoint in response_analysis["critical_endpoints"]:
            print(f"   - {endpoint['service_name']}: {endpoint['host']}:{endpoint['port']}")
        
        print()
        return response_analysis
    
    def generate_report(self, analysis: Dict[str, Any]) -> str:
        """Generate a comprehensive analysis report"""
        report = []
        report.append("STAR CITIZEN SERVICE DISCOVERY PACKET ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {analysis['timestamp']}")
        report.append(f"Connection: {analysis['connection']}")
        report.append(f"Packet Size: {analysis['packet_size']} bytes")
        report.append("")
        
        # Protocol Analysis
        if analysis["protocol_analysis"]:
            report.append("PROTOCOL STRUCTURE:")
            protocol = analysis["protocol_analysis"]
            if "header" in protocol:
                header = protocol["header"]
                report.append(f"  Length: {header['length']} bytes")
                report.append(f"  Magic: {header['magic_bytes']} ({header['magic_ascii']})")
                report.append(f"  Valid Protocol: {protocol.get('protocol_valid', False)}")
            report.append("")
        
        # Client Information
        if analysis["client_info"]:
            report.append("CLIENT INFORMATION:")
            client = analysis["client_info"]
            for key, value in client.items():
                if key != "potential_timestamps":
                    report.append(f"  {key}: {value}")
            report.append("")
        
        # Protobuf Analysis
        if analysis["protobuf_analysis"]:
            report.append("PROTOBUF ANALYSIS:")
            for key, value in analysis["protobuf_analysis"].items():
                report.append(f"  {key}: {value}")
            report.append("")
        
        # Server Response Analysis
        if analysis["server_response_analysis"]:
            report.append("EXPECTED SERVER RESPONSE:")
            response = analysis["server_response_analysis"]
            report.append(f"  Type: {response['response_type']}")
            report.append("  Required Fields:")
            for field in response["required_fields"]:
                report.append(f"    - {field}")
            report.append("  Critical Endpoints:")
            for endpoint in response["critical_endpoints"]:
                report.append(f"    - {endpoint['service_name']}: {endpoint['host']}:{endpoint['port']}")
            report.append("")
        
        return "\n".join(report)

def main():
    """Main analysis function"""
    analyzer = ServiceDiscoveryAnalyzer()
    
    # Analyze the packet from the task
    packet_data = {
        "timestamp": "2025-08-05T02:44:02.319981",
        "hex_data": "54000000efbeadde0a13646966662e736572766963652e6f6e6c696e65123b0a185374617220436974697a656e2047616d6520436c69656e74120973635f636c69656e741a1408b2bb9dac94f2c6874a1097e5e7f8819aaa83521800",
        "ascii_data": "T.........diff.service.online.;..Star Citizen Game Client..sc_client...........J.........R..",
        "connection": "127.0.0.1:59380"
    }
    
    # Perform analysis
    analysis = analyzer.analyze_packet(
        packet_data["hex_data"],
        packet_data["ascii_data"], 
        packet_data["timestamp"],
        packet_data["connection"]
    )
    
    # Generate and save report
    report = analyzer.generate_report(analysis)
    
    # Save analysis results
    with open("service_discovery_analysis.json", "w") as f:
        json.dump(analysis, f, indent=2, default=str)
    
    with open("service_discovery_report.txt", "w") as f:
        f.write(report)
    
    print("[*] ANALYSIS COMPLETE")
    print("=" * 80)
    print("[*] Results saved to:")
    print("   - service_discovery_analysis.json (detailed data)")
    print("   - service_discovery_report.txt (human-readable report)")
    print()
    print("[*] KEY FINDINGS:")
    print("   - Valid Star Citizen protocol packet detected")
    print("   - Client requesting 'diff.service.online' service discovery")
    print("   - Client identifies as 'Star Citizen Game Client' / 'sc_client'")
    print("   - Server should respond with ServiceDiscoveryResponse containing service endpoints")
    print("   - Critical for client authentication and game server connection flow")

if __name__ == "__main__":
    main()
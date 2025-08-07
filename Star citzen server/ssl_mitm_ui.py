#!/usr/bin/env python3
"""
SSL MITM Proxy UI for Star Citizen Protocol Analysis
Real-time monitoring with graphical interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
import json
import struct
import time
import random
from datetime import datetime
import ssl
from typing import Dict, Any, Optional, List
import queue

class SSLMITMProxyUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Star Citizen SSL MITM Proxy")
        self.root.geometry("1400x900")
        
        # Proxy configuration
        self.listen_port = 8000
        self.target_port = 8001
        self.proxy_running = False
        self.proxy_server = None
        self.captured_messages = []
        
        # UI communication
        self.message_queue = queue.Queue()
        self.status_queue = queue.Queue()
        
        self.setup_ui()
        self.start_queue_processing()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        self.setup_control_panel(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Setup tabs
        self.setup_live_monitor_tab()
        self.setup_message_analysis_tab()
        self.setup_protocol_stats_tab()
        self.setup_hex_viewer_tab()
        self.setup_custom_injection_tab()  # New tab for custom data injection
        
    def setup_control_panel(self, parent):
        """Setup the control panel"""
        control_frame = ttk.LabelFrame(parent, text="Proxy Control")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Configuration frame
        config_frame = ttk.Frame(control_frame)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Listen Port:").pack(side=tk.LEFT)
        self.listen_port_var = tk.StringVar(value=str(self.listen_port))
        ttk.Entry(config_frame, textvariable=self.listen_port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(config_frame, text="Target Port:").pack(side=tk.LEFT, padx=(20, 0))
        self.target_port_var = tk.StringVar(value=str(self.target_port))
        ttk.Entry(config_frame, textvariable=self.target_port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_btn = ttk.Button(button_frame, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Proxy", command=self.stop_proxy, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear Messages", command=self.clear_messages)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(button_frame, text="Export JSON", command=self.export_messages)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Status and stats
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_var = tk.StringVar(value="Ready to start SSL MITM proxy")
        status_label = ttk.Label(stats_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        self.stats_var = tk.StringVar(value="Messages: 0 | Clients: 0")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_var)
        stats_label.pack(side=tk.RIGHT)
        
    def setup_live_monitor_tab(self):
        """Setup the live monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Live Monitor")
        
        # Message list
        list_frame = ttk.LabelFrame(monitor_frame, text="Message Stream")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for messages
        columns = ("Time", "Direction", "Type", "Size", "Summary")
        self.message_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.message_tree.heading("Time", text="Timestamp")
        self.message_tree.heading("Direction", text="Direction")
        self.message_tree.heading("Type", text="Message Type")
        self.message_tree.heading("Size", text="Size")
        self.message_tree.heading("Summary", text="Content Summary")
        
        self.message_tree.column("Time", width=100)
        self.message_tree.column("Direction", width=100)
        self.message_tree.column("Type", width=150)
        self.message_tree.column("Size", width=80)
        self.message_tree.column("Summary", width=400)
        
        # Scrollbars
        tree_v_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.message_tree.yview)
        tree_h_scroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.message_tree.xview)
        self.message_tree.configure(yscrollcommand=tree_v_scroll.set, xscrollcommand=tree_h_scroll.set)
        
        # Pack treeview
        self.message_tree.grid(row=0, column=0, sticky="nsew")
        tree_v_scroll.grid(row=0, column=1, sticky="ns")
        tree_h_scroll.grid(row=1, column=0, sticky="ew")
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Bind selection
        self.message_tree.bind("<<TreeviewSelect>>", self.on_message_select)
        
        # Live log frame
        log_frame = ttk.LabelFrame(monitor_frame, text="Live Log")
        log_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_message_analysis_tab(self):
        """Setup the message analysis tab"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Message Analysis")
        
        # Message details frame
        details_frame = ttk.LabelFrame(analysis_frame, text="Message Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, font=("Consolas", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_protocol_stats_tab(self):
        """Setup the protocol statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Protocol Stats")
        
        # Statistics display
        stats_display_frame = ttk.LabelFrame(stats_frame, text="Protocol Statistics")
        stats_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(stats_display_frame, font=("Consolas", 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Update stats button
        update_btn = ttk.Button(stats_frame, text="Update Statistics", command=self.update_statistics)
        update_btn.pack(pady=5)
        
    def setup_hex_viewer_tab(self):
        """Setup the hex viewer tab"""
        hex_frame = ttk.Frame(self.notebook)
        self.notebook.add(hex_frame, text="Hex Viewer")
        
        # Message info
        info_frame = ttk.LabelFrame(hex_frame, text="Message Info")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.hex_info_text = tk.Text(info_frame, height=3, font=("Consolas", 10))
        self.hex_info_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Hex dump
        dump_frame = ttk.LabelFrame(hex_frame, text="Hex Dump")
        dump_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.hex_dump_text = scrolledtext.ScrolledText(dump_frame, font=("Consolas", 9))
        self.hex_dump_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_custom_injection_tab(self):
        """Setup the custom data injection tab"""
        injection_frame = ttk.Frame(self.notebook)
        self.notebook.add(injection_frame, text="Custom Injection")
        
        # Data type selection
        type_frame = ttk.LabelFrame(injection_frame, text="Injection Type")
        type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.injection_type_var = tk.StringVar(value="Console Command")
        type_combo = ttk.Combobox(type_frame, textvariable=self.injection_type_var, state="readonly")
        type_combo['values'] = (
            "Console Command",
            "Debug Flag",
            "Config Override", 
            "UI Injection",
            "Network Override",
            "Game State",
            "Custom Payload",
            "gRPC Command",
            "Raw Hex Data"
        )
        type_combo.pack(fill=tk.X, padx=5, pady=5)
        
        # Direction selection
        direction_frame = ttk.LabelFrame(injection_frame, text="Injection Direction")
        direction_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.injection_direction_var = tk.StringVar(value="server->client")
        direction_combo = ttk.Combobox(direction_frame, textvariable=self.injection_direction_var, state="readonly")
        direction_combo['values'] = ("server->client", "client->server")
        direction_combo.pack(fill=tk.X, padx=5, pady=5)
        
        # Custom data input
        data_frame = ttk.LabelFrame(injection_frame, text="Custom Data/Code")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.custom_data_text = scrolledtext.ScrolledText(data_frame, height=10, font=("Consolas", 10))
        self.custom_data_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quick presets frame
        presets_frame = ttk.LabelFrame(injection_frame, text="Quick Presets")
        presets_frame.pack(fill=tk.X, padx=5, pady=5)
        
        presets_button_frame = ttk.Frame(presets_frame)
        presets_button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Preset buttons (first row - normal presets)
        ttk.Button(presets_button_frame, text="Dev Login Dialog", 
                  command=lambda: self.load_preset("dev_login")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_button_frame, text="Debug Mode", 
                  command=lambda: self.load_preset("debug_mode")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_button_frame, text="Heartbeat", 
                  command=lambda: self.load_preset("heartbeat")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_button_frame, text="Console Cmd", 
                  command=lambda: self.load_preset("console")).pack(side=tk.LEFT, padx=2)
        
        # Second row - gRPC/Proto command presets
        presets_grpc_frame = ttk.Frame(presets_frame)
        presets_grpc_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(presets_grpc_frame, text="gRPC Commands:", 
                 foreground="blue", font=("TkDefaultFont", 8, "bold")).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(presets_grpc_frame, text="gRPC Connect", 
                  command=lambda: self.load_preset("grpc_connect")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_grpc_frame, text="Login Service", 
                  command=lambda: self.load_preset("grpc_login")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_grpc_frame, text="Character Service", 
                  command=lambda: self.load_preset("grpc_character")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_grpc_frame, text="Proto Handshake", 
                  command=lambda: self.load_preset("grpc_handshake")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_grpc_frame, text="Service Discovery", 
                  command=lambda: self.load_preset("grpc_discovery")).pack(side=tk.LEFT, padx=2)
        
        # Third row - aggressive fuzzing presets
        presets_fuzz_frame = ttk.Frame(presets_frame)
        presets_fuzz_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(presets_fuzz_frame, text="Aggressive Fuzzing:", 
                 foreground="red", font=("TkDefaultFont", 8, "bold")).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(presets_fuzz_frame, text="Fuzz Data", 
                  command=lambda: self.load_preset("fuzz_data")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_fuzz_frame, text="Crash Test", 
                  command=lambda: self.load_preset("crash_test")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_fuzz_frame, text="Buffer Overflow", 
                  command=lambda: self.load_preset("buffer_overflow")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_fuzz_frame, text="Null Flood", 
                  command=lambda: self.load_preset("null_flood")).pack(side=tk.LEFT, padx=2)
        ttk.Button(presets_fuzz_frame, text="Random Chaos", 
                  command=lambda: self.load_preset("random_chaos")).pack(side=tk.LEFT, padx=2)
        
        # Injection controls
        control_frame = ttk.Frame(injection_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.inject_btn = ttk.Button(control_frame, text="Inject Data", command=self.inject_custom_data)
        self.inject_btn.pack(side=tk.LEFT, padx=5)
        
        # Add "Send Direct" button for aggressive testing
        self.send_direct_btn = ttk.Button(control_frame, text="Send Direct", 
                                         command=self.send_direct, 
                                         style="Accent.TButton")
        self.send_direct_btn.pack(side=tk.LEFT, padx=5)
        
        # Add tooltip for Send Direct button
        def create_tooltip(widget, text):
            def on_enter(event):
                tooltip = tk.Toplevel()
                tooltip.wm_overrideredirect(True)
                tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
                label = ttk.Label(tooltip, text=text, background="lightyellow", 
                                relief="solid", borderwidth=1)
                label.pack()
                widget.tooltip = tooltip
            def on_leave(event):
                if hasattr(widget, 'tooltip'):
                    widget.tooltip.destroy()
                    del widget.tooltip
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
        
        create_tooltip(self.send_direct_btn, 
                      "AGGRESSIVE MODE: Sends raw data directly to client,\nbypassing all protocol structure. May crash client!")
        
        
        ttk.Button(control_frame, text="Clear", command=self.clear_injection).pack(side=tk.LEFT, padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(injection_frame, text="Injection Options")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        options_inner = ttk.Frame(options_frame)
        options_inner.pack(fill=tk.X, padx=5, pady=5)
        
        self.inject_immediate_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_inner, text="Execute Immediately", 
                       variable=self.inject_immediate_var).pack(side=tk.LEFT)
        
        self.inject_priority_var = tk.StringVar(value="5")
        ttk.Label(options_inner, text="Priority:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(options_inner, textvariable=self.inject_priority_var, width=5).pack(side=tk.LEFT)
        
        # Injection log
        log_frame = ttk.LabelFrame(injection_frame, text="Injection Log")
        log_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.injection_log_text = scrolledtext.ScrolledText(log_frame, height=6, font=("Consolas", 9))
        self.injection_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def start_queue_processing(self):
        """Start processing message and status queues"""
        def process_queues():
            try:
                # Process status updates
                while not self.status_queue.empty():
                    status = self.status_queue.get_nowait()
                    
                    # Check if this is a direct injection message
                    try:
                        status_data = json.loads(status)
                        if status_data.get("type") == "DIRECT_INJECTION":
                            self.handle_direct_injection(status_data)
                            continue
                    except (json.JSONDecodeError, AttributeError):
                        pass
                    
                    self.status_var.set(status)
                    
                    # Also log injection-related status messages to injection log
                    if any(keyword in status.lower() for keyword in ['injection', 'sent to client', 'sent to target']):
                        if hasattr(self, 'injection_log_text'):
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            log_entry = f"[{timestamp}] {status}\n"
                            self.injection_log_text.insert(tk.END, log_entry)
                            self.injection_log_text.see(tk.END)
                    
                # Process new messages
                while not self.message_queue.empty():
                    message_data = self.message_queue.get_nowait()
                    self.add_message_to_ui(message_data)
                    
            except queue.Empty:
                pass
            
            # Schedule next check
            self.root.after(100, process_queues)
            
        process_queues()
        
    def add_message_to_ui(self, message_data):
        """Add a message to the UI with improved logging and copy support"""
        self.captured_messages.append(message_data)
        # Add to treeview
        timestamp = datetime.fromisoformat(message_data["timestamp"])
        time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        summary = message_data["ascii_data"][:80].replace('\n', ' ')
        if len(message_data["ascii_data"]) > 80:
            summary += "..."
        # Add full message data as a tag for copy
        item_id = self.message_tree.insert("", tk.END, values=(
            time_str,
            message_data["direction"],
            message_data["type"],
            f"{message_data['size']} B",
            summary
        ))
        self.message_tree.set(item_id, "Summary", summary)
        # Store full message for copy
        self.message_tree.item(item_id, tags=(item_id,))
        # Auto-scroll to bottom
        self.message_tree.see(item_id)
        # Add to log with more details
        log_entry = (
            f"[{time_str}] {message_data['direction']} | {message_data['type']} | Size: {message_data['size']} bytes\n"
            f"Summary: {summary}\n"
            f"Hex: {message_data['hex_data'][:96]}{'...' if len(message_data['hex_data']) > 96 else ''}\n"
        )
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        # Update stats
        self.stats_var.set(f"Messages: {len(self.captured_messages)} | Active")
        # Bind right-click for copy
        self.message_tree.tag_bind(item_id, '<Button-3>', lambda e, iid=item_id: self.copy_message_details(iid))

    def copy_message_details(self, item_id):
        """Copy full message details to clipboard"""
        idx = self.message_tree.index(item_id)
        if idx < len(self.captured_messages):
            msg = self.captured_messages[idx]
            details = (
                f"Timestamp: {msg['timestamp']}\n"
                f"Direction: {msg['direction']}\n"
                f"Type: {msg['type']}\n"
                f"Size: {msg['size']} bytes\n"
                f"Hex: {msg['hex_data']}\n"
                f"ASCII: {msg['ascii_data']}\n"
                f"Connection: {msg.get('connection', '')}\n"
            )
            self.root.clipboard_clear()
            self.root.clipboard_append(details)
            self.root.update()  # Ensure clipboard is updated
        
    def on_message_select(self, event):
        """Handle message selection"""
        selection = self.message_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        index = self.message_tree.index(item)
        
        if index < len(self.captured_messages):
            message = self.captured_messages[index]
            self.display_message_details(message)
            
    def display_message_details(self, message):
        """Display detailed message information"""
        # Update details tab
        self.details_text.delete(1.0, tk.END)
        
        details = f"=== MESSAGE DETAILS ===\n\n"
        details += f"Timestamp: {message['timestamp']}\n"
        details += f"Direction: {message['direction']}\n"
        details += f"Type: {message['type']}\n"
        details += f"Size: {message['size']} bytes\n\n"
        
        details += f"ASCII Content:\n{message['ascii_data']}\n\n"
        
        # Try to parse protocol structure
        data = bytes.fromhex(message['hex_data'])
        if data.startswith(b'\\xef\\xbe\\xad\\xde'):
            details += f"Star Citizen Protocol Detected:\n"
            details += f"Magic: {data[:4].hex()}\n"
            if len(data) > 8:
                length = struct.unpack('<I', data[4:8])[0]
                details += f"Length: {length}\n"
                payload = data[8:]
                details += f"Payload: {payload.decode('utf-8', errors='replace')}\n"
        
        self.details_text.insert(1.0, details)
        
        # Update hex viewer
        self.hex_info_text.delete(1.0, tk.END)
        info = f"Message: {message['type']} | Size: {message['size']} bytes | {message['direction']}\n"
        info += f"Time: {message['timestamp']}\n"
        self.hex_info_text.insert(1.0, info)
        
        self.hex_dump_text.delete(1.0, tk.END)
        hex_dump = self.format_hex_dump(data)
        self.hex_dump_text.insert(1.0, hex_dump)
        
    def format_hex_dump(self, data: bytes) -> str:
        """Format binary data as hex dump"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:08x}: "
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{offset}{hex_part} |{ascii_part}|")
        return "\n".join(lines)
        
    def update_statistics(self):
        """Update protocol statistics"""
        self.stats_text.delete(1.0, tk.END)
        
        if not self.captured_messages:
            self.stats_text.insert(1.0, "No messages captured yet.")
            return
            
        # Count message types
        type_counts = {}
        direction_counts = {"client->server": 0, "server->client": 0}
        total_bytes = {"client->server": 0, "server->client": 0}
        
        for msg in self.captured_messages:
            msg_type = msg['type']
            direction = msg['direction']
            size = msg['size']
            
            type_counts[msg_type] = type_counts.get(msg_type, 0) + 1
            direction_counts[direction] += 1
            total_bytes[direction] += size
            
        stats = "=== PROTOCOL STATISTICS ===\n\n"
        stats += f"Total Messages: {len(self.captured_messages)}\n\n"
        
        stats += "Message Types:\n"
        for msg_type, count in sorted(type_counts.items()):
            stats += f"  {msg_type}: {count}\n"
        
        stats += f"\nTraffic Direction:\n"
        stats += f"  Client -> Server: {direction_counts['client->server']} messages ({total_bytes['client->server']} bytes)\n"
        stats += f"  Server -> Client: {direction_counts['server->client']} messages ({total_bytes['server->client']} bytes)\n"
        
        # Calculate rates if we have heartbeats
        heartbeat_count = type_counts.get('Heartbeat', 0)
        if heartbeat_count > 0:
            stats += f"\nHeartbeat Analysis:\n"
            stats += f"  Total Heartbeats: {heartbeat_count}\n"
            if len(self.captured_messages) > 1:
                first_time = datetime.fromisoformat(self.captured_messages[0]['timestamp'])
                last_time = datetime.fromisoformat(self.captured_messages[-1]['timestamp'])
                duration = (last_time - first_time).total_seconds()
                if duration > 0:
                    rate = heartbeat_count / duration * 60
                    stats += f"  Rate: {rate:.1f} heartbeats/minute\n"
        
        self.stats_text.insert(1.0, stats)
        
    def load_preset(self, preset_type):
        """Load predefined injection presets"""
        presets = {
            "dev_login": {
                "type": "Config Override",
                "data": '{"show_dev_login_dialog": 1, "enable_debug_mode": true, "debug_flags": ["dev_login", "offline_mode"]}'
            },
            "debug_mode": {
                "type": "Debug Flag", 
                "data": '{"enable_debug_mode": true, "debug_flags": ["network_debug", "protocol_debug", "ui_debug"]}'
            },
            "heartbeat": {
                "type": "Custom Payload",
                "data": '{"type": "heartbeat", "timestamp": "' + datetime.now().isoformat() + '", "client_id": "mitm_proxy"}'
            },
            "console": {
                "type": "Console Command",
                "data": 'r_displayinfo 1\ncon_restricted 0\nnet_debug 1'
            },
            "fuzz_data": {
                "type": "Raw Hex Data",
                "data": 'DEADBEEF' + 'FF' * 100 + '41414141' + '00' * 50
            },
            "crash_test": {
                "type": "Raw Hex Data", 
                "data": 'FFFFFFFF' * 50 + '00000000' * 25 + 'AAAAAAAA' * 25
            },
            "buffer_overflow": {
                "type": "Raw Hex Data",
                "data": '41' * 2000  # 'A' characters in hex
            },
            "null_flood": {
                "type": "Raw Hex Data", 
                "data": '00' * 500
            },
            "random_chaos": {
                "type": "Raw Hex Data",
                "data": ''.join([f'{random.randint(0,255):02X}' for _ in range(200)])
            },
            "grpc_connect": {
                "type": "Custom Payload",
                "data": '{"service": "LoginService", "method": "Connect", "request_id": "conn_001", "client_version": "3.23.0", "protocol_version": "1.0", "connection_type": "grpc", "timestamp": "' + datetime.now().isoformat() + '"}'
            },
            "grpc_login": {
                "type": "Custom Payload",
                "data": '{"service": "LoginService", "method": "AuthenticateUser", "debug_mode": true, "force_dev_login": true, "bypass_validation": true, "test_credentials": {"username": "dev_user", "password": "dev_pass", "session_token": "debug_session_001"}, "connection_flags": ["ALLOW_DEV_MODE", "SKIP_AUTH_CHECKS"]}'
            },
            "grpc_character": {
                "type": "Custom Payload", 
                "data": '{"service": "CharacterService", "method": "GetCharacterList", "request_id": "char_conn_001", "auth_token": "dev_token_12345", "player_id": "test_player_001", "connection_params": {"timeout": 30000, "retry_count": 3}}'
            },
            "grpc_handshake": {
                "type": "Raw Hex Data",
                "data": "504F5354202F4C6F67696E536572766963652F436F6E6E656374204854545020312E310D0A436F6E74656E742D547970653A206170706C69636174696F6E2F677270632B70726F746F0D0A0D0A"
            },
            "grpc_discovery": {
                "type": "Custom Payload",
                "data": '{"method": "DiscoverServices", "services": ["LoginService", "CharacterService", "PresenceService"], "client_capabilities": ["SSL", "COMPRESSION", "STREAMING"]}'
            }
        }
        
        if preset_type in presets:
            preset = presets[preset_type]
            self.injection_type_var.set(preset["type"])
            self.custom_data_text.delete(1.0, tk.END)
            self.custom_data_text.insert(1.0, preset["data"])
            self.log_injection(f"Loaded preset: {preset_type}")
        
    def clear_injection(self):
        """Clear the injection input"""
        self.custom_data_text.delete(1.0, tk.END)
        self.log_injection("Cleared injection input")
        
    def inject_custom_data(self):
        """Inject custom data into the stream"""
        if not self.proxy_running:
            messagebox.showwarning("Warning", "Proxy must be running to inject data")
            return
            
        injection_type = self.injection_type_var.get()
        direction = self.injection_direction_var.get()
        custom_data = self.custom_data_text.get(1.0, tk.END).strip()
        
        if not custom_data:
            messagebox.showwarning("Warning", "Please enter data to inject")
            return
            
        try:
            # Create injection message
            if injection_type == "Raw Hex Data":
                # Handle hex data
                try:
                    data_bytes = bytes.fromhex(custom_data.replace(" ", "").replace("\n", ""))
                except ValueError:
                    messagebox.showerror("Error", "Invalid hex data format")
                    return
            else:
                # Create structured data based on our protobuf definitions
                injection_data = self.create_injection_payload(injection_type, custom_data)
                data_bytes = injection_data.encode('utf-8')
            
            # Queue the injection
            self.queue_injection(data_bytes, direction, injection_type)
            
            self.log_injection(f"Injected {injection_type} ({len(data_bytes)} bytes) -> {direction}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Injection failed: {str(e)}")
            self.log_injection(f"Injection failed: {str(e)}")
            
    def create_injection_payload(self, injection_type, custom_data):
        """Create structured injection payload"""
        timestamp = datetime.now().isoformat()
        
        # Create payload based on our protobuf SendCustomDataRequest structure
        payload = {
            "mitm_injection": True,
            "timestamp": timestamp,
            "injection_type": injection_type,
            "priority": int(self.inject_priority_var.get()),
            "execute_immediately": self.inject_immediate_var.get()
        }
        
        if injection_type == "Console Command":
            payload["console_commands"] = custom_data
            payload["data_type"] = "CUSTOM_DATA_CONSOLE_COMMAND"
        elif injection_type == "Debug Flag":
            try:
                debug_data = json.loads(custom_data)
                payload["debug_commands"] = [custom_data]
                payload["force_dev_mode"] = debug_data.get("enable_debug_mode", False)
                payload["data_type"] = "CUSTOM_DATA_DEBUG_FLAG"
            except json.JSONDecodeError:
                payload["debug_commands"] = [custom_data]
                payload["data_type"] = "CUSTOM_DATA_DEBUG_FLAG"
        elif injection_type == "Config Override":
            try:
                config_data = json.loads(custom_data)
                payload["config_override"] = config_data
                payload["data_type"] = "CUSTOM_DATA_CONFIG_OVERRIDE"
            except json.JSONDecodeError:
                payload["custom_response_data"] = custom_data
                payload["data_type"] = "CUSTOM_DATA_CONFIG_OVERRIDE"
        elif injection_type == "UI Injection":
            payload["ui_injection"] = custom_data
            payload["data_type"] = "CUSTOM_DATA_UI_INJECTION"
        elif injection_type == "Network Override":
            payload["network_override"] = custom_data
            payload["data_type"] = "CUSTOM_DATA_NETWORK_OVERRIDE"
        elif injection_type == "Game State":
            payload["game_state"] = custom_data
            payload["data_type"] = "CUSTOM_DATA_GAME_STATE"
        elif injection_type == "gRPC Command":
            try:
                grpc_data = json.loads(custom_data)
                payload["grpc_service"] = grpc_data.get("service", "LoginService")
                payload["grpc_method"] = grpc_data.get("method", "Connect")
                payload["grpc_request_data"] = grpc_data
                payload["data_type"] = "CUSTOM_DATA_GRPC_COMMAND"
            except json.JSONDecodeError:
                payload["custom_response_data"] = custom_data
                payload["data_type"] = "CUSTOM_DATA_GRPC_COMMAND"
        else:  # Custom Payload
            payload["custom_response_data"] = custom_data
            payload["data_type"] = "CUSTOM_DATA_UNKNOWN"
            
        return json.dumps(payload, indent=2)
        
    def queue_injection(self, data_bytes, direction, injection_type):
        """Queue data for injection into the stream"""
        # Store injection for when connections are active
        if not hasattr(self, 'pending_injections'):
            self.pending_injections = []
            
        injection = {
            "data": data_bytes,
            "direction": direction,
            "type": injection_type,
            "timestamp": datetime.now().isoformat()
        }
        
        self.pending_injections.append(injection)
        
        # Try to inject immediately if we have active connections
        if hasattr(self, 'active_connections') and self.active_connections and hasattr(self, 'proxy_loop'):
            injected = False
            for conn_id, conn_info in self.active_connections.items():
                if direction == "server->client" and "client_writer" in conn_info:
                    # Schedule the coroutine in the proxy thread's event loop
                    asyncio.run_coroutine_threadsafe(
                        self.send_injection_to_client(conn_info["client_writer"], injection),
                        self.proxy_loop
                    )
                    injected = True
                    break
                elif direction == "client->server" and "target_writer" in conn_info:
                    # Schedule the coroutine in the proxy thread's event loop
                    asyncio.run_coroutine_threadsafe(
                        self.send_injection_to_target(conn_info["target_writer"], injection),
                        self.proxy_loop
                    )
                    injected = True
                    break
            
            if injected:
                # Remove from pending since we injected it
                self.pending_injections.remove(injection)
            else:
                self.log_injection(f"Queued for injection: {injection_type} (no active connections)")
        else:
            self.log_injection(f"Queued for injection: {injection_type} (proxy not running or no connections)")
        
    async def send_injection_to_client(self, writer, injection):
        """Send injection data to client"""
        try:
            writer.write(injection["data"])
            await writer.drain()
            # Use status queue for cross-thread logging
            self.status_queue.put(f"Injection sent to client: {injection['type']}")
        except Exception as e:
            # Use status queue for cross-thread logging
            self.status_queue.put(f"Failed to send injection to client: {str(e)}")
            
    async def send_injection_to_target(self, writer, injection):
        """Send injection data to target server"""
        try:
            writer.write(injection["data"])
            await writer.drain()
            # Use status queue for cross-thread logging
            self.status_queue.put(f"Injection sent to target: {injection['type']}")
        except Exception as e:
            # Use status queue for cross-thread logging
            self.status_queue.put(f"Failed to send injection to target: {str(e)}")
            
    def log_injection(self, message):
        """Log injection activity"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.injection_log_text.insert(tk.END, log_entry)
        self.injection_log_text.see(tk.END)
        
    def start_proxy(self):
        """Start the SSL MITM proxy"""
        try:
            self.listen_port = int(self.listen_port_var.get())
            self.target_port = int(self.target_port_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port numbers")
            return
            
        if self.proxy_running:
            return
            
        self.proxy_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start proxy in separate thread
        self.proxy_thread = threading.Thread(target=self.run_proxy_thread, daemon=True)
        self.proxy_thread.start()
        
        self.status_queue.put(f"SSL MITM Proxy starting on port {self.listen_port} -> {self.target_port}")
        
    def stop_proxy(self):
        """Stop the SSL MITM proxy"""
        self.proxy_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_queue.put("Proxy stopped")
        
    def run_proxy_thread(self):
        """Run proxy in separate thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Store loop reference for cross-thread task scheduling
        self.proxy_loop = loop
        
        try:
            loop.run_until_complete(self.run_proxy())
        except Exception as e:
            self.status_queue.put(f"Proxy error: {str(e)}")
        finally:
            # Clean up loop reference
            self.proxy_loop = None
            loop.close()
            
    async def run_proxy(self):
        """Main proxy logic"""
        # Create SSL context
        ssl_context = await self.create_ssl_context_async()
        if not ssl_context:
            self.status_queue.put("Failed to create SSL context")
            return
            
        server = await asyncio.start_server(
            self.handle_client,
            "127.0.0.1",
            self.listen_port,
            ssl=ssl_context
        )
        
        self.status_queue.put(f"SSL MITM Proxy running on port {self.listen_port}")
        
        async with server:
            await server.serve_forever()
            
    async def create_ssl_context_async(self):
        """Create SSL context asynchronously"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        try:
            context.load_cert_chain('server.crt', 'server.key')
            return context
        except FileNotFoundError:
            # Create certificate if needed
            await self.create_certificate_async()
            try:
                context.load_cert_chain('server.crt', 'server.key')
                return context
            except Exception as e:
                self.status_queue.put(f"SSL certificate error: {str(e)}")
                return None
                
    async def create_certificate_async(self):
        """Create self-signed certificate"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            from datetime import datetime, timedelta
            
            # Generate key and certificate (same as before)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Star Citizen MITM"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                private_key.public_key()
            ).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]), critical=False
            ).sign(private_key, hashes.SHA256())
            
            # Write files
            with open("server.crt", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open("server.key", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
        except Exception as e:
            self.status_queue.put(f"Certificate creation failed: {str(e)}")
            
    async def handle_client(self, reader, writer):
        """Handle client connection"""
        client_addr = writer.get_extra_info('peername')
        self.status_queue.put(f"Client connected: {client_addr[0]}:{client_addr[1]}")
        
        # Track active connections for injection
        if not hasattr(self, 'active_connections'):
            self.active_connections = {}
        
        conn_id = f"{client_addr[0]}:{client_addr[1]}"
        
        try:
            # Connect to target
            target_reader, target_writer = await asyncio.open_connection('127.0.0.1', self.target_port)
            
            # Store connection info for injections
            self.active_connections[conn_id] = {
                "client_writer": writer,
                "target_writer": target_writer,
                "client_addr": client_addr
            }
            
            # Process any pending injections
            if hasattr(self, 'pending_injections'):
                for injection in self.pending_injections[:]:  # Copy list to avoid modification during iteration
                    if injection["direction"] == "server->client":
                        await self.send_injection_to_client(writer, injection)
                    elif injection["direction"] == "client->server":
                        await self.send_injection_to_target(target_writer, injection)
                    self.pending_injections.remove(injection)
            
            # Process any pending direct injections (aggressive mode)
            if hasattr(self, 'pending_direct_injections'):
                for data_bytes in self.pending_direct_injections[:]:
                    try:
                        writer.write(data_bytes)
                        await writer.drain()
                        self.log_injection(f"DIRECT INJECTION sent to new client: {len(data_bytes)} bytes")
                    except Exception as e:
                        self.log_injection(f"Failed to send pending direct injection: {str(e)}")
                    self.pending_direct_injections.remove(data_bytes)
            
            # Start forwarding
            await asyncio.gather(
                self.forward_data(reader, target_writer, "client->server", conn_id),
                self.forward_data(target_reader, writer, "server->client", conn_id),
                return_exceptions=True
            )
        except Exception as e:
            self.status_queue.put(f"Client error: {str(e)}")
        finally:
            # Clean up connection tracking
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]
            
            writer.close()
            try:
                target_writer.close()
            except:
                pass
                
    async def forward_data(self, reader, writer, direction, conn_id=None):
        """Forward data and capture it"""
        try:
            while self.proxy_running:
                data = await reader.read(4096)
                if not data:
                    break
                    
                # Create message data
                message_data = {
                    "timestamp": datetime.now().isoformat(),
                    "direction": direction,
                    "size": len(data),
                    "type": self.detect_message_type(data),
                    "hex_data": data.hex(),
                    "ascii_data": ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data]),
                    "connection": conn_id or "unknown"
                }
                
                # Check if this looks like an injection
                try:
                    data_str = data.decode('utf-8', errors='ignore')
                    if '"mitm_injection": true' in data_str:
                        message_data["type"] = "MITM Injection"
                        message_data["injected"] = True
                except:
                    pass
                
                # Queue for UI update
                self.message_queue.put(message_data)
                
                # Forward data
                writer.write(data)
                await writer.drain()
                
        except Exception as e:
            self.status_queue.put(f"Forward error ({direction}): {str(e)}")
            
    def detect_message_type(self, data: bytes) -> str:
        """Detect message type"""
        # Check for injected data first
        try:
            data_str = data.decode('utf-8', errors='ignore')
            if '"mitm_injection": true' in data_str:
                return "MITM Injection"
        except:
            pass
            
        if b"heartbeat" in data:
            return "Heartbeat"
        elif b"diff.service.online" in data:
            return "Service Discovery"
        elif b"cmsg_ls_req_dests" in data:
            return "Lobby Destinations"
        elif b"cmsg_set_region_id" in data:
            return "Region Setup"
        elif b"SendCustomData" in data:
            return "Custom Data Request"
        elif b"console_commands" in data:
            return "Console Command"
        elif b"debug_commands" in data:
            return "Debug Command"
        elif b"force_dev_mode" in data:
            return "Dev Mode Toggle"
        elif b"grpc_service" in data or b"grpc_method" in data:
            return "gRPC Command"
        elif b"LoginService" in data or b"CharacterService" in data:
            return "gRPC Service Call"
        elif data.startswith(b'\\xef\\xbe\\xad\\xde'):
            return "SC Protocol Response"
        elif len(data) >= 4:
            try:
                length = struct.unpack('<I', data[:4])[0]
                if 0 < length < 10000:
                    return "SC Binary Protocol"
            except:
                pass
        return "Unknown"
        
    def clear_messages(self):
        """Clear all captured messages"""
        self.captured_messages.clear()
        self.message_tree.delete(*self.message_tree.get_children())
        self.log_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        self.hex_info_text.delete(1.0, tk.END)
        self.hex_dump_text.delete(1.0, tk.END)
        self.stats_var.set("Messages: 0 | Cleared")
        
    def export_messages(self):
        """Export captured messages"""
        if not self.captured_messages:
            messagebox.showwarning("Warning", "No messages to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.captured_messages, f, indent=2)
                messagebox.showinfo("Success", f"Exported {len(self.captured_messages)} messages to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                
    def send_custom_data(self):
        """Send custom data to target"""
        target_ip = self.target_ip_var.get()
        target_port = self.target_port_injection_var.get()
        data = self.data_var.get()
        
        if not target_ip or not target_port or not data:
            messagebox.showerror("Error", "All fields are required")
            return
        
        try:
            target_port = int(target_port)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        # Convert data to bytes
        try:
            data_bytes = bytes.fromhex(data)
        except ValueError:
            messagebox.showerror("Error", "Data must be in hex format")
            return
        
        # Send data
        loop = asyncio.get_event_loop()
        loop.create_task(self.send_data_to_target(target_ip, target_port, data_bytes))
        
    async def send_data_to_target(self, ip, port, data):
        """Send data to target IP and port"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            
            # Send data
            writer.write(data)
            await writer.drain()
            
            # Receive response
            response = await reader.read(4096)
            
            # Display response
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, response.hex())
            
            writer.close()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send data: {str(e)}")
            
    def run(self):
        """Run the UI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
        
    def on_closing(self):
        """Handle window closing"""
        if self.proxy_running:
            self.stop_proxy()
        self.root.destroy()

    def send_direct(self):
        """Send raw data directly to client connection for aggressive testing"""
        if not self.proxy_running:
            messagebox.showwarning("Warning", "Proxy must be running to send direct data")
            return
            
        custom_data = self.custom_data_text.get(1.0, tk.END).strip()
        
        if not custom_data:
            messagebox.showwarning("Warning", "Please enter data to send")
            return
            
        # Show warning about aggressive testing
        result = messagebox.askyesno(
            "Aggressive Testing Warning", 
            "This will send raw data directly to the client, bypassing all protocol structure.\n\n"
            "This may crash the client or cause unexpected behavior.\n\n"
            "Continue with aggressive testing?",
            icon='warning'
        )
        
        if not result:
            return
            
        try:
            injection_type = self.injection_type_var.get()
            
            # Parse data based on type
            if injection_type == "Raw Hex Data":
                try:
                    data_bytes = bytes.fromhex(custom_data.replace(" ", "").replace("\n", ""))
                except ValueError:
                    messagebox.showerror("Error", "Invalid hex data format")
                    return
            else:
                # For non-hex data, convert to bytes
                data_bytes = custom_data.encode('utf-8')
            
            # Create direct injection message (bypasses normal protocol)
            direct_message = {
                "type": "DIRECT_INJECTION",
                "timestamp": time.time(),
                "data": data_bytes.hex(),  # Send as hex string
                "length": len(data_bytes),
                "direction": "to_client",
                "bypass_protocol": True,
                "aggressive_mode": True,
                "original_type": injection_type
            }
            
            # Send through status queue for immediate processing
            if hasattr(self, 'status_queue'):
                self.status_queue.put(json.dumps(direct_message))
                
            self.log_injection(f"DIRECT SEND: {len(data_bytes)} bytes sent directly to client (AGGRESSIVE MODE)")
            self.log_injection(f"Data preview: {data_bytes[:50].hex()}{'...' if len(data_bytes) > 50 else ''}")
            
            # Also add to injection log with warning
            self.injection_log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] AGGRESSIVE DIRECT SEND:\n")
            self.injection_log_text.insert(tk.END, f"  Type: {injection_type}\n")
            self.injection_log_text.insert(tk.END, f"  Size: {len(data_bytes)} bytes\n")
            self.injection_log_text.insert(tk.END, f"  Hex: {data_bytes.hex()}\n")
            self.injection_log_text.insert(tk.END, f"  WARNING: Protocol bypassed, may crash client!\n\n")
            self.injection_log_text.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send direct data: {str(e)}")
            self.log_injection(f"DIRECT SEND ERROR: {str(e)}")
    
    def handle_direct_injection(self, injection_data):
        """Handle direct injection messages by sending raw data to client connections"""
        try:
            data_hex = injection_data.get("data", "")
            data_bytes = bytes.fromhex(data_hex)
            
            # Find active client connections and send data directly
            sent_count = 0
            if hasattr(self, 'active_connections') and self.active_connections:
                for conn_id, conn_info in self.active_connections.items():
                    try:
                        client_writer = conn_info.get("client_writer")
                        if client_writer and not client_writer.is_closing():
                            # Send raw data directly to client
                            client_writer.write(data_bytes)
                            # Try to drain the buffer (non-blocking)
                            try:
                                asyncio.create_task(client_writer.drain())
                            except:
                                pass
                            sent_count += 1
                    except Exception as e:
                        self.log_injection(f"Failed to send direct data to client {conn_id}: {str(e)}")
            
            # If no active connections, try to store for when connection is established
            if sent_count == 0:
                if not hasattr(self, 'pending_direct_injections'):
                    self.pending_direct_injections = []
                self.pending_direct_injections.append(data_bytes)
                self.log_injection(f"DIRECT INJECTION queued: {len(data_bytes)} bytes (no active connections)")
            else:
                self.log_injection(f"DIRECT INJECTION sent to {sent_count} client(s): {len(data_bytes)} bytes")
            
            # Update status
            self.status_var.set(f"Direct injection sent to {sent_count} client(s)")
            
        except Exception as e:
            self.log_injection(f"DIRECT INJECTION ERROR: {str(e)}")
            self.status_var.set(f"Direct injection failed: {str(e)}")


def main():
    """Main entry point"""
    app = SSLMITMProxyUI()
    
    # Show welcome message
    welcome = """
🎮 STAR CITIZEN SSL MITM PROXY UI

This tool provides a graphical interface for monitoring Star Citizen protocol traffic.

Features:
• Real-time message monitoring
• Protocol analysis and statistics  
• Hex dump viewer
• Message export capabilities
• SSL termination for clear protocol visibility
• Custom data injection for testing and development

NEW: Custom Injection Tab
• Send custom commands, debug flags, and data to client
• Test development login dialog controls
• Inject console commands and configuration overrides
• Real-time injection with structured payloads

🔴 AGGRESSIVE TESTING MODE:
• "Send Direct" button bypasses ALL protocol structure
• Raw data injection directly to client socket
• Fuzzing presets: Buffer overflow, null flood, random chaos
• Trial-and-error approach - client crashes are expected
• No safety checks - aggressive protocol testing

Setup:
1. Ensure your diffusion server runs on port 8001 (no SSL)
2. Click 'Start Proxy' to begin listening on port 8000
3. Connect Star Citizen to 127.0.0.1:8000
4. Monitor traffic in real-time!
5. Use Custom Injection tab for normal testing
6. Use "Send Direct" for aggressive fuzzing (may crash client)

Ready for aggressive testing!
"""
    
    messagebox.showinfo("Welcome", welcome)
    app.run()

if __name__ == "__main__":
    main()

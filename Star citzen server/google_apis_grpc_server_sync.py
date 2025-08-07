#!/usr/bin/env python3
"""
Simplified Google APIs gRPC Server (synchronous version)
Implements proper gRPC services for all Google API endpoints
"""

import grpc
import json
import logging
import time
from concurrent import futures
from typing import Dict, Any, Optional, List
from google.protobuf import any_pb2, struct_pb2, wrappers_pb2, empty_pb2
from google.protobuf.json_format import MessageToDict, ParseDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('google_apis_grpc_server.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class GoogleAPIsServicer:
    """gRPC servicer for Google APIs - implements real Google service handlers"""
    
    def __init__(self):
        self.active_connections = {}
        self.request_count = 0
        self.service_calls = {}

    def handle_unary_call(self, method_name, request, context):
        """Handle unary gRPC calls with proper method routing"""
        self.request_count += 1
        client_addr = context.peer()
        
        logger.info(f"🔌 gRPC call: {method_name} from {client_addr} (#{self.request_count})")
        
        # Track service calls
        self.service_calls[method_name] = self.service_calls.get(method_name, 0) + 1
        
        try:
            # Route based on actual Google API type URLs the client requests
            # Enhanced routing based on reverse engineering from FUN_147808b20
            if "/token" in method_name and ("oauth2" in method_name or "token" in method_name):
                return self.handle_oauth2_token_refresh(request, context)
            elif "oauth2" in method_name or "OAuth2" in method_name:
                return self.handle_oauth2_request(request, context)
            elif "sts" in method_name.lower() or "securitytokenservice" in method_name.lower():
                return self.handle_sts_request(request, context)
            elif ("token-exchange" in method_name or 
                  "grant-type" in method_name or 
                  "token_exchange" in method_name or
                  "urn:ietf:params:oauth:grant-type:token-exchange" in str(request)):
                return self.handle_star_citizen_token_exchange(request, context)
            elif ("/locations/" in method_name and ("workforcePools" in method_name or "providers" in method_name)):
                return self.handle_workforce_identity_request(method_name, request, context)
            elif "iamcredentials" in method_name.lower() or "credentials" in method_name.lower():
                return self.handle_iam_credentials_request(request, context)
            elif "iam" in method_name or "IAM" in method_name:
                return self.handle_iam_request(request, context)
            elif "xdstp:" in method_name or "google_cfe_" in method_name:
                return self.handle_xds_transport_request(method_name, request, context)
            elif "envoy.config.cluster" in method_name and "google_cfe_" in method_name:
                return self.handle_envoy_cluster_request(method_name, request, context)
            elif "C2P-" in method_name or ("c2p" in method_name.lower() and "traffic" in method_name.lower()):
                return self.handle_traffic_director_c2p_request(method_name, request, context)
            elif "traffic-director" in method_name or "xds.googleapis.com" in method_name or "AggregatedDiscovery" in method_name:
                return self.handle_traffic_director_request(request, context)
            elif "directpath" in method_name:
                return self.handle_directpath_request(request, context)
            elif "type.googleapis.com" in method_name:
                return self.handle_type_url_request(method_name, request, context)
            elif "workforce" in method_name:
                return self.handle_workforce_identity_request(method_name, request, context)
            elif ("sc.external.services" in method_name or 
                  "services.arenacommander" in method_name or 
                  "services.ledger" in method_name or
                  "entity_graph" in method_name or
                  "grpc_echo_rpc" in method_name):
                return self.handle_star_citizen_service_request(method_name, request, context)
            else:
                # Generic Google API response
                return self.create_generic_response(method_name, request, context)
                
        except Exception as e:
            logger.error(f"❌ Error handling {method_name}: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal server error: {e}")
            return empty_pb2.Empty()

    def handle_oauth2_request(self, request, context):
        """Handle OAuth2 service requests"""
        logger.info("🔑 Processing OAuth2 request")
        
        # Create a valid OAuth2 token response
        token_response = {
            "access_token": "star_citizen_local_token_" + str(int(time.time())),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
        }
        
        # Return as protobuf Struct
        response = struct_pb2.Struct()
        response.update(token_response)
        logger.info("✅ OAuth2 token response created")
        return response

    def handle_oauth2_token_refresh(self, request, context):
        """Handle OAuth2 token refresh requests - based on reverse engineering"""
        logger.info("🔄 Processing OAuth2 token refresh request")
        
        # Create OAuth2 token refresh response matching the expected format
        token_refresh_response = {
            "access_token": f"star_citizen_refreshed_token_{int(time.time())}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email",
            "refresh_token": f"star_citizen_refresh_{int(time.time())}"  # Optional: new refresh token
        }
        
        response = struct_pb2.Struct()
        response.update(token_refresh_response)
        logger.info("✅ OAuth2 token refresh response created")
        return response

    def handle_iam_request(self, request, context):
        """Handle IAM service requests"""
        logger.info("🛡️ Processing IAM request")
        
        # Create a basic IAM policy response
        iam_response = {
            "version": 1,
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:star_citizen@localhost"]
                }
            ],
            "etag": "star_citizen_etag_" + str(int(time.time()))
        }
        
        response = struct_pb2.Struct()
        response.update(iam_response)
        logger.info("✅ IAM policy response created")
        return response

    def handle_traffic_director_request(self, request, context):
        """Handle Traffic Director/xDS requests"""
        logger.info("🚦 Processing Traffic Director request")
        
        # Create basic xDS discovery response
        xds_response = {
            "version_info": "1",
            "resources": [],
            "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
            "nonce": "star_citizen_nonce_" + str(int(time.time()))
        }
        
        response = struct_pb2.Struct()
        response.update(xds_response)
        logger.info("✅ Traffic Director response created")
        return response

    def handle_directpath_request(self, request, context):
        """Handle DirectPath requests"""
        logger.info("🛣️ Processing DirectPath request")
        
        # Create basic DirectPath response
        directpath_response = {
            "path_available": True,
            "backend_addr": "127.0.0.1:8000",
            "metadata": {
                "star_citizen": "local_server"
            }
        }
        
        response = struct_pb2.Struct()
        response.update(directpath_response)
        logger.info("✅ DirectPath response created")
        return response

    def handle_type_url_request(self, method_name, request, context):
        """Handle type.googleapis.com requests (protobuf Any types)"""
        logger.info(f"🔧 Processing type URL request: {method_name}")
        
        # Create a generic Any response
        any_response = any_pb2.Any()
        
        # Create basic response based on type URL
        if "grpc.status" in method_name:
            # Status response
            status_value = {
                "code": 0,
                "message": "OK",
                "details": []
            }
            response_struct = struct_pb2.Struct()
            response_struct.update(status_value)
            any_response.Pack(response_struct)
        elif "envoy" in method_name:
            # Envoy configuration response
            envoy_value = {
                "config": {
                    "local_server": True,
                    "address": "127.0.0.1"
                }
            }
            response_struct = struct_pb2.Struct()
            response_struct.update(envoy_value)
            any_response.Pack(response_struct)
        else:
            # Generic protobuf response
            generic_value = {
                "star_citizen_local": True,
                "timestamp": int(time.time())
            }
            response_struct = struct_pb2.Struct()
            response_struct.update(generic_value)
            any_response.Pack(response_struct)
        
        logger.info("✅ Type URL response created")
        return any_response

    def create_generic_response(self, method_name, request, context):
        """Create generic response for unknown endpoints"""
        logger.info(f"🌐 Creating generic response for: {method_name}")
        
        generic_response = {
            "status": "ok",
            "method": method_name,
            "server": "star_citizen_local_google_apis",
            "timestamp": int(time.time())
        }
        
        response = struct_pb2.Struct()
        response.update(generic_response)
        logger.info("✅ Generic response created")
        return response

    def handle_sts_request(self, request, context):
        """Handle STS (Security Token Service) requests - based on reverse engineering"""
        logger.info("🔐 Processing STS (Security Token Service) request")
        
        # Enhanced STS token exchange response matching Star Citizen's expected format
        # Based on reverse engineering of FUN_147808b20 - OAuth 2.0 Token Exchange (RFC 8693)
        sts_response = {
            "access_token": f"star_citizen_sts_token_{int(time.time())}",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email",
            # Additional fields that Star Citizen might expect
            "refresh_token": f"star_citizen_sts_refresh_{int(time.time())}",
            "id_token": f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovLzEyNy4wLjAuMTo1MDA1MSIsInN1YiI6InN0YXJfY2l0aXplbl91c2VyIiwiYXVkIjoic3Rhci1jaXRpemVuLWNsaWVudCIsImV4cCI6e2ludCh0aW1lLnRpbWUoKSArIDM2MDApfSwiaWF0Ijoge2ludCh0aW1lLnRpbWUoKSl9fQ.signature"
        }
        
        response = struct_pb2.Struct()
        response.update(sts_response)
        logger.info("✅ STS token exchange response created (RFC 8693 compliant)")
        return response

    def handle_star_citizen_token_exchange(self, request, context):
        """Handle the specific token exchange flow from Star Citizen reverse engineering"""
        logger.info("🎮 Processing Star Citizen token exchange request")
        
        # This matches the exact flow from FUN_147808b20
        # The function builds form data with these specific parameters:
        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token", 
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://127.0.0.1:8000",  # Local game server
            "scope": "https://127.0.0.1:8000",     # Scope points to local server
            "subject_token": f"star_citizen_subject_token_{int(time.time())}",
            "options": '{"userProject":"star-citizen-local"}',  # JSON options
        }
        
        # Create the response that Star Citizen expects
        token_response = {
            "access_token": f"ya29.star_citizen_exchanged_{int(time.time())}",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer", 
            "expires_in": 3600,
            "scope": "https://127.0.0.1:8000",
            "refresh_token": f"1//star_citizen_refresh_{int(time.time())}"
        }
        
        response = struct_pb2.Struct()
        response.update(token_response)
        logger.info("✅ Star Citizen token exchange response created")
        logger.info(f"📋 Form data detected: {form_data}")
        return response

    def handle_iam_credentials_request(self, request, context):
        """Handle IAM Credentials requests - based on reverse engineering"""
        logger.info("🔑 Processing IAM Credentials request")
        
        # Create IAM credentials response
        credentials_response = {
            "access_token": f"star_citizen_iam_creds_{int(time.time())}",
            "expire_time": f"{int(time.time() + 3600)}",
            "scope": [
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/userinfo.email"
            ]
        }
        
        response = struct_pb2.Struct()
        response.update(credentials_response)
        logger.info("✅ IAM Credentials response created")
        return response

    def handle_xds_transport_request(self, method_name, request, context):
        """Handle xDS Transport Protocol (xdstp:) requests - based on reverse engineering"""
        logger.info(f"🚦 Processing xDS Transport request: {method_name}")
        
        # Create xDS transport response with local cluster configuration
        if "google_cfe_" in method_name:
            xds_response = {
                "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
                "name": "google_cfe_127.0.0.1",
                "type": "LOGICAL_DNS",
                "connect_timeout": "5s",
                "load_assignment": {
                    "cluster_name": "google_cfe_127.0.0.1",                        "endpoints": [
                            {
                                "lb_endpoints": [
                                    {
                                        "endpoint": {
                                            "address": {
                                                "socket_address": {
                                                    "address": "127.0.0.1",
                                                    "port_value": 443
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                },
                "http2_protocol_options": {}
            }
        else:
            # Generic xDS transport response
            xds_response = {
                "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
                "name": "star_citizen_local_listener",
                "address": {
                    "socket_address": {
                        "address": "127.0.0.1",
                        "port_value": 443
                    }
                }
            }
        
        response = struct_pb2.Struct()
        response.update(xds_response)
        logger.info("✅ xDS Transport response created")
        return response

    def handle_envoy_cluster_request(self, method_name, request, context):
        """Handle Envoy cluster configuration requests - based on reverse engineering"""
        logger.info(f"🔧 Processing Envoy cluster request: {method_name}")
        
        # Create Envoy cluster configuration for google_cfe_
        cluster_response = {
            "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            "name": "google_cfe_127.0.0.1",
            "type": "LOGICAL_DNS",
            "connect_timeout": "30s",
            "per_connection_buffer_limit_bytes": 32768,
            "load_assignment": {
                "cluster_name": "google_cfe_127.0.0.1",
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {
                                "endpoint": {                                        "address": {
                                            "socket_address": {
                                                "address": "127.0.0.1",
                                                "port_value": 443,
                                                "protocol": "TCP"
                                            }
                                        }
                                }
                            }
                        ]
                    }
                ]
            },
            "http2_protocol_options": {
                "hpack_table_size": 4096,
                "max_concurrent_streams": 2147483647
            },
            "upstream_connection_options": {
                "tcp_keepalive": {
                    "keepalive_probes": 6,
                    "keepalive_time": 7200,
                    "keepalive_interval": 75
                }
            }
        }
        
        response = struct_pb2.Struct()
        response.update(cluster_response)
        logger.info("✅ Envoy cluster response created")
        return response

    def handle_workforce_identity_request(self, method_name, request, context):
        """Handle Google Cloud Workforce Identity Federation requests - based on reverse engineering"""
        logger.info(f"👥 Processing Workforce Identity Federation request: {method_name}")
        
        # Extract path components for proper response
        if "/locations/" in method_name and "/workforcePools/" in method_name:
            if "/providers/" in method_name:
                # Identity provider response
                workforce_response = {
                    "name": "projects/star-citizen-local/locations/global/workforcePools/star-citizen-pool/providers/star-citizen-provider",
                    "displayName": "Star Citizen Local Provider",
                    "description": "Local workforce identity provider for Star Citizen",
                    "state": "ACTIVE",
                    "attributeMapping": {
                        "google.subject": "assertion.sub",
                        "google.groups": "assertion.groups"
                    },
                    "oidc": {
                        "issuerUri": "https://127.0.0.1:443",
                        "clientId": "star-citizen-local-client",
                        "webSsoConfig": {
                            "responseType": "CODE",
                            "assertionClaimsBehavior": "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS"
                        }
                    }
                }
            else:
                # Workforce pool response
                workforce_response = {
                    "name": "projects/star-citizen-local/locations/global/workforcePools/star-citizen-pool",
                    "displayName": "Star Citizen Local Pool",
                    "description": "Local workforce pool for Star Citizen authentication",
                    "state": "ACTIVE",
                    "accessRestrictions": {
                        "allowedServices": [
                            {
                                "service": "iam.googleapis.com"
                            }
                        ]
                    }
                }
        else:
            # Generic locations response
            workforce_response = {
                "locations": [
                    {
                        "name": "projects/star-citizen-local/locations/global",
                        "locationId": "global",
                        "displayName": "Global",
                        "labels": {
                            "star-citizen": "local-server"
                        }
                    }
                ]
            }
        
        response = struct_pb2.Struct()
        response.update(workforce_response)
        logger.info("✅ Workforce Identity Federation response created")
        return response

    def handle_traffic_director_c2p_request(self, method_name, request, context):
        """Handle Traffic Director C2P (Client-to-Proxy) requests - based on reverse engineering"""
        logger.info(f"🚦 Processing Traffic Director C2P request: {method_name}")
        
        # Create Traffic Director C2P response with local configuration
        if "C2P-" in method_name or "c2p" in method_name.lower():
            c2p_response = {
                "@type": "type.googleapis.com/envoy.service.discovery.v3.DiscoveryResponse",
                "version_info": "1",
                "resources": [
                    {
                        "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
                        "name": "google_cfe_127.0.0.1",
                        "type": "LOGICAL_DNS",
                        "connect_timeout": "30s",
                        "load_assignment": {
                            "cluster_name": "google_cfe_127.0.0.1",
                            "endpoints": [
                                {
                                    "lb_endpoints": [
                                        {
                                            "endpoint": {
                                                "address": {
                                                    "socket_address": {
                                                        "address": "127.0.0.1",
                                                        "port_value": 443
                                                    }
                                                }
                                            },
                                            "metadata": {
                                                "filter_metadata": {
                                                    "com.google.grpc_gcp": {
                                                        "directpath_ready": True
                                                    }
                                                }
                                            }
                                        }
                                    ]
                                }
                            ]
                        },
                        "http2_protocol_options": {
                            "hpack_table_size": 4096,
                            "max_concurrent_streams": 100
                        },
                        "metadata": {
                            "filter_metadata": {
                                "com.google.grpc_gcp": {
                                    "locality": {
                                        "region": "local",
                                        "zone": "localhost",
                                        "sub_zone": "star_citizen"
                                    }
                                }
                            }
                        }
                    }
                ],
                "type_url": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
                "nonce": f"star_citizen_c2p_nonce_{int(time.time())}"
            }
        else:
            # Generic Traffic Director response
            c2p_response = {
                "@type": "type.googleapis.com/envoy.service.discovery.v3.DiscoveryResponse",
                "version_info": "1",
                "resources": [],
                "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
                "nonce": f"star_citizen_td_nonce_{int(time.time())}"
            }
        
        response = struct_pb2.Struct()
        response.update(c2p_response)
        logger.info("✅ Traffic Director C2P response created")
        return response

    def handle_star_citizen_service_request(self, method_name, request, context):
        """Handle Star Citizen specific service requests - based on protocol analysis"""
        logger.info(f"🎮 Processing Star Citizen service: {method_name}")
        
        # Route based on specific Star Citizen services
        if "arenacommander" in method_name and "entitlements" in method_name:
            return self.handle_arena_commander_entitlements(request, context)
        elif "ledger" in method_name and ("funds" in method_name or "get_funds_external" in method_name):
            return self.handle_ledger_funds_request(request, context)
        elif "presence" in method_name and "PresenceService" in method_name:
            return self.handle_presence_service_request(method_name, request, context)
        elif "entitlement" in method_name and "ReconcileAccountUpdate" in method_name:
            return self.handle_entitlement_reconcile_request(request, context)
        elif "trace" in method_name and "TraceService" in method_name:
            return self.handle_trace_service_request(method_name, request, context)
        elif "push" in method_name and "PushService" in method_name:
            return self.handle_push_service_request(method_name, request, context)
        elif "entity_graph" in method_name and "MutateEntities" in method_name:
            return self.handle_entity_graph_mutation(method_name, request, context)
        elif "grpc_echo_rpc" in method_name:
            return self.handle_grpc_echo_rpc(request, context)
        else:
            return self.create_generic_star_citizen_response(method_name, request, context)

    def handle_arena_commander_entitlements(self, request, context):
        """Handle Arena Commander entitlements requests"""
        logger.info("🏁 Processing Arena Commander entitlements request")
        
        # Create Arena Commander entitlements response
        entitlements_response = {
            "entitlements": [
                {
                    "id": "arena_commander_access",
                    "name": "Arena Commander Access",
                    "description": "Full access to Arena Commander module",
                    "granted": True,
                    "expires_at": int(time.time() + 86400 * 365)  # 1 year
                },
                {
                    "id": "hangar_access", 
                    "name": "Hangar Access",
                    "description": "Access to hangar module",
                    "granted": True,
                    "expires_at": int(time.time() + 86400 * 365)
                },
                {
                    "id": "star_marine_access",
                    "name": "Star Marine Access", 
                    "description": "Access to Star Marine FPS module",
                    "granted": True,
                    "expires_at": int(time.time() + 86400 * 365)
                }
            ],
            "player_id": "star_citizen_local_player",
            "timestamp": int(time.time())
        }
        
        response = struct_pb2.Struct()
        response.update(entitlements_response)
        logger.info("✅ Arena Commander entitlements response created")
        return response

    def handle_ledger_funds_request(self, request, context):
        """Handle ledger funds requests"""
        logger.info("💰 Processing ledger funds request")
        
        # Create ledger funds response
        funds_response = {
            "ledgers": [
                {
                    "name": "UEC",
                    "balance": 1000000,  # 1 million UEC
                    "currency": "United Earth Credits",
                    "type": "primary"
                },
                {
                    "name": "REC",
                    "balance": 50000,    # 50k REC
                    "currency": "Rental Equipment Credits", 
                    "type": "rental"
                }
            ],
            "player_id": "star_citizen_local_player",
            "timestamp": int(time.time())
        }
        
        response = struct_pb2.Struct()
        response.update(funds_response)
        logger.info("✅ Ledger funds response created")
        return response

    def handle_presence_service_request(self, method_name, request, context):
        """Handle presence service requests"""
        logger.info(f"👤 Processing presence service: {method_name}")
        
        if "PresenceStreamRequest" in method_name:
            # Streaming presence request
            presence_response = {
                "stream_id": f"presence_stream_{int(time.time())}",
                "player_status": {
                    "online": True,
                    "location": "Stanton System - Crusader",
                    "activity": "In Game",
                    "server": "star_citizen_local"
                },
                "friends": [],
                "timestamp": int(time.time())
            }
        else:
            # Regular presence request
            presence_response = {
                "player_id": "star_citizen_local_player",
                "status": "online",
                "location": "Local Server",
                "timestamp": int(time.time())
            }
        
        response = struct_pb2.Struct()
        response.update(presence_response)
        logger.info("✅ Presence service response created")
        return response

    def handle_entitlement_reconcile_request(self, request, context):
        """Handle entitlement reconciliation requests"""
        logger.info("🔄 Processing entitlement reconciliation request")
        
        reconcile_response = {
            "reconciliation_id": f"reconcile_{int(time.time())}",
            "account_updates": [
                {
                    "type": "entitlement_granted",
                    "entitlement_id": "full_game_access",
                    "status": "active"
                }
            ],
            "timestamp": int(time.time()),
            "status": "completed"
        }
        
        response = struct_pb2.Struct()
        response.update(reconcile_response)
        logger.info("✅ Entitlement reconciliation response created")
        return response

    def handle_trace_service_request(self, method_name, request, context):
        """Handle trace service requests"""
        logger.info(f"🔍 Processing trace service: {method_name}")
        
        if "CollectionStreamRequest" in method_name:
            trace_response = {
                "stream_id": f"trace_stream_{int(time.time())}",
                "collection_enabled": True,
                "trace_level": "INFO",
                "timestamp": int(time.time())
            }
        else:
            trace_response = {
                "trace_id": f"trace_{int(time.time())}",
                "enabled": True,
                "timestamp": int(time.time())
            }
        
        response = struct_pb2.Struct()
        response.update(trace_response)
        logger.info("✅ Trace service response created")
        return response

    def handle_push_service_request(self, method_name, request, context):
        """Handle push service requests"""
        logger.info(f"📱 Processing push service: {method_name}")
        
        if "ListenRequest" in method_name:
            push_response = {
                "listener_id": f"push_listener_{int(time.time())}",
                "status": "listening",
                "endpoint": "127.0.0.1:443",
                "timestamp": int(time.time())
            }
        else:
            push_response = {
                "push_id": f"push_{int(time.time())}",
                "status": "ready",
                "timestamp": int(time.time())
            }
        
        response = struct_pb2.Struct()
        response.update(push_response)
        logger.info("✅ Push service response created")
        return response

    def handle_entity_graph_mutation(self, method_name, request, context):
        """Handle entity graph mutation requests"""
        logger.info(f"🌐 Processing entity graph mutation: {method_name}")
        
        # Extract command ID from path if present
        command_id = "unknown"
        if "commands/" in method_name:
            try:
                command_id = method_name.split("commands/")[1].split("/")[0]
            except:
                pass
        
        mutation_response = {
            "mutation_id": f"mutation_{int(time.time())}",
            "command_id": command_id,
            "status": "completed",
            "affected_entities": [],
            "timestamp": int(time.time())
        }
        
        response = struct_pb2.Struct()
        response.update(mutation_response)
        logger.info("✅ Entity graph mutation response created")
        return response

    def handle_grpc_echo_rpc(self, request, context):
        """Handle gRPC echo RPC test requests"""
        logger.info("🔊 Processing gRPC echo RPC request")
        
        echo_response = {
            "echo": "Star Citizen Local Server Echo",
            "message": "gRPC connection successful",
            "server": "star_citizen_local",
            "timestamp": int(time.time()),
            "delay": 0,
            "queue_mode": 0
        }
        
        response = struct_pb2.Struct()
        response.update(echo_response)
        logger.info("✅ gRPC echo response created")
        return response

    def create_generic_star_citizen_response(self, method_name, request, context):
        """Create generic response for Star Citizen services"""
        logger.info(f"🎮 Creating generic Star Citizen response for: {method_name}")
        
        generic_response = {
            "status": "ok",
            "service": "star_citizen_local",
            "method": method_name,
            "server": "127.0.0.1:443",
            "timestamp": int(time.time())
        }
        
        response = struct_pb2.Struct()
        response.update(generic_response)
        logger.info("✅ Generic Star Citizen response created")
        return response

class GenericServicer(grpc.GenericRpcHandler):
    """Generic servicer that handles all incoming requests"""
    
    def __init__(self):
        self.google_apis = GoogleAPIsServicer()
    
    def service(self, handler_call_details):
        """Route all calls to our Google APIs handler"""
        method = handler_call_details.method
        logger.info(f"📞 Routing call: {method}")
        
        # Create a unary-unary handler for this method
        def handle_call(request, context):
            return self.google_apis.handle_unary_call(method, request, context)
        
        return grpc.unary_unary_rpc_method_handler(
            handle_call,
            request_deserializer=lambda x: x,  # Accept raw bytes
            response_serializer=lambda x: x.SerializeToString() if hasattr(x, 'SerializeToString') else b''
        )


def serve():
    """Start the synchronous gRPC server"""
    logger.info("🚀 Starting Google APIs gRPC server on 0.0.0.0:443")
    
    # Create server with thread pool
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # Add our generic servicer
    generic_servicer = GenericServicer()
    server.add_generic_rpc_handlers((generic_servicer,))
    
    # Add reflection (optional)
    try:
        # Skip reflection for now - it's optional
        logger.info("📝 gRPC reflection skipped (optional feature)")
    except Exception as e:
        logger.warning(f"⚠️ gRPC reflection not available: {e}")
    
    # Try to add both insecure and secure ports for compatibility
    listen_addr_insecure = '0.0.0.0:443'
    listen_addr_secure = '0.0.0.0:443'  # Same port for secure
    
    # Add insecure port (for local testing)
    try:
        server.add_insecure_port(listen_addr_insecure)
        logger.info(f"✅ Added insecure port: {listen_addr_insecure}")
    except Exception as e:
        logger.error(f"❌ Failed to add insecure port {listen_addr_insecure}: {e}")
        # Try 127.0.0.1 instead
        try:
            server.add_insecure_port('127.0.0.1:443')
            logger.info("✅ Added insecure port: 127.0.0.1:443")
        except Exception as e2:
            logger.error(f"❌ Failed to add any insecure port: {e2}")
    
    # Try to add secure port with self-signed certificate
    try:
        # Check if we have SSL certificates
        import os
        cert_file = 'server.crt'
        key_file = 'server.key'
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                private_key = f.read()
            with open(cert_file, 'rb') as f:
                certificate_chain = f.read()
            
            server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)])
            server.add_secure_port(listen_addr_secure, server_credentials)
            logger.info(f"✅ Added secure port: {listen_addr_secure}")
        else:
            logger.info("⚠️ SSL certificates not found, skipping secure port")
            
    except Exception as e:
        logger.warning(f"⚠️ Could not add secure port: {e}")
    
    server.start()
    
    logger.info("✅ Google APIs gRPC server running")
    logger.info("🔧 Listening on:")
    logger.info("   * 0.0.0.0:443 (insecure gRPC)")
    logger.info("   * 0.0.0.0:443 (secure gRPC, if certificates available)")
    logger.info("🔧 Handling Google API service calls:")
    logger.info("   * oauth2.googleapis.com (OAuth2 + token refresh)")
    logger.info("   * sts.googleapis.com (Security Token Service)")
    logger.info("   * iamcredentials.googleapis.com")
    logger.info("   * iam.googleapis.com")
    logger.info("   * iam.googleapis.com/locations/*/workforcePools/* (Workforce Identity)")
    logger.info("   * traffic-director-c2p.xds.googleapis.com (C2P Client-to-Proxy)")
    logger.info("   * xdstp: (xDS Transport Protocol)")
    logger.info("   * envoy.config.cluster.v3.Cluster/google_cfe_*")
    logger.info("   * directpath-pa.googleapis.com")
    logger.info("   * type.googleapis.com/grpc.status.*")
    logger.info("   * type.googleapis.com/envoy.*")
    logger.info("   * type.googleapis.com/google.protobuf.*")
    logger.info("   * Generic type.googleapis.com/* handlers")
    logger.info("🎮 Handling Star Citizen service calls:")
    logger.info("   * services.arenacommander.get_entitlements")
    logger.info("   * services.ledger.get_funds_external")
    logger.info("   * sc.external.services.presence.v1.PresenceService")
    logger.info("   * sc.external.services.entitlement.v1.*")
    logger.info("   * sc.external.services.trace.v1.TraceService")
    logger.info("   * sc.external.services.push.v1.PushService")
    logger.info("   * entity_graph/commands/MutateEntities")
    logger.info("   * grpc_echo_rpc (test RPC)")
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("🛑 Stopping server...")
        server.stop(grace=5)
        logger.info("✅ Server stopped")

if __name__ == "__main__":
    serve()

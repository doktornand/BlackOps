"""Elasticsearch module with anomaly detection"""
import aiohttp
import asyncio
import json
from typing import Tuple, Dict, Any

from blackops.modules.base import BaseModule

class ElasticsearchModule(BaseModule):
    """Module Elasticsearch avec détection d'anomalies"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe Elasticsearch et retourne (banner, metadata)"""
        metadata = {
            'has_default_creds': False,
            'is_dev_version': False,
            'index_count': 0,
            'node_count': 0,
            'cluster_name': 'unknown',
            'version': 'unknown',
            'shards': 0,
            'health': 'unknown'
        }
        banner = "Elasticsearch"
        
        base_url = f"http://{ip}:{port}"
        
        async with aiohttp.ClientSession() as session:
            # Tentative 1: Accès sans auth
            try:
                # Cluster health
                async with session.get(f"{base_url}/_cluster/health", timeout=5) as resp:
                    if resp.status == 200:
                        health_data = await resp.json()
                        metadata['cluster_name'] = health_data.get('cluster_name', 'unknown')
                        metadata['node_count'] = health_data.get('number_of_nodes', 0)
                        metadata['shards'] = health_data.get('active_shards', 0)
                        metadata['health'] = health_data.get('status', 'unknown')
                        metadata['has_default_creds'] = True
                        banner += " | NO AUTHENTICATION REQUIRED ⚠️"
                        
                        # Version
                        async with session.get(f"{base_url}/") as root_resp:
                            if root_resp.status == 200:
                                root_data = await root_resp.json()
                                version_info = root_data.get('version', {})
                                metadata['version'] = version_info.get('number', 'unknown')
                                banner = f"Elasticsearch v{metadata['version']}"
                                
                        # Indices
                        async with session.get(f"{base_url}/_cat/indices?format=json", timeout=5) as indices_resp:
                            if indices_resp.status == 200:
                                indices = await indices_resp.json()
                                metadata['index_count'] = len(indices)
                                banner += f" | {metadata['index_count']} indices"
                                
                                # Lister les indices sensibles
                                sensitive_indices = [idx.get('index') for idx in indices 
                                                    if any(x in idx.get('index', '').lower() 
                                                           for x in ['log', 'audit', 'security', 'user', 'payment', 'credit'])]
                                if sensitive_indices:
                                    metadata['sensitive_indices'] = sensitive_indices[:10]
                                    banner += f" | ⚠️ SENSITIVE DATA: {', '.join(sensitive_indices[:3])}"
                                    
                                # Statistiques sur les docs
                                if indices:
                                    total_docs = sum(int(idx.get('docs.count', 0)) for idx in indices)
                                    metadata['total_documents'] = total_docs
                                    if total_docs > 100000:
                                        banner += f" | {total_docs:,} documents"
                                        
                    elif resp.status == 401:
                        banner += " | Authentication required (basic auth or API key)"
                        metadata['auth_required'] = True
                        
                    else:
                        banner += f" | HTTP {resp.status}"
                        
            except asyncio.TimeoutError:
                banner += " | Timeout"
            except aiohttp.ClientError as e:
                banner += f" | Connection error: {str(e)[:50]}"
            except Exception as e:
                banner += f" | Error: {str(e)[:50]}"
                
            # Détection de version vulnérable
            if metadata['version'] != 'unknown':
                try:
                    version_parts = metadata['version'].split('.')
                    major = int(version_parts[0])
                    minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                    
                    # Versions vulnérables connues (Log4Shell, etc.)
                    if (major == 7 and minor < 17) or (major == 6 and minor < 8):
                        metadata['is_dev_version'] = True
                        banner += " | VULNERABLE VERSION (Log4Shell, CVE-2021-44228) ⚠️"
                except:
                    pass
                    
            # Détection de cluster ouvert
            if metadata.get('has_default_creds'):
                try:
                    # Tester si on peut créer un index (danger)
                    test_index = f"blackops_test_{asyncio.get_event_loop().time()}"
                    async with session.put(f"{base_url}/{test_index}", timeout=3) as create_resp:
                        if create_resp.status in [200, 201]:
                            metadata['can_create_indices'] = True
                            banner += " | CAN CREATE/DELETE INDICES (HIGH RISK) ⚠️"
                            # Nettoyer
                            await session.delete(f"{base_url}/{test_index}")
                except:
                    pass
                    
        return banner, metadata
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si Elasticsearch requiert auth"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://{ip}:{port}/", timeout=3) as resp:
                    return resp.status == 401
            except:
                return True  # Assume auth required
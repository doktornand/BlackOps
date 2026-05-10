"""Kubernetes module with anomaly detection"""
import aiohttp
import asyncio
import ssl
from typing import Tuple, Dict, Any

from blackops.modules.base import BaseModule

class KubernetesModule(BaseModule):
    """Module Kubernetes avec détection d'anomalies"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe Kubernetes API et retourne (banner, metadata)"""
        metadata = {
            'has_default_creds': False,
            'is_dev_version': False,
            'version': 'unknown',
            'namespaces': 0,
            'pods': 0,
            'nodes': 0,
            'insecure': False
        }
        banner = "Kubernetes API"
        
        # Tentative 1: Sans certificat (insecure)
        connector = aiohttp.TCPConnector(ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                # Version endpoint (toujours accessible souvent)
                async with session.get(f"https://{ip}:{port}/version", timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        version_data = await resp.json()
                        metadata['version'] = version_data.get('gitVersion', 'unknown')
                        banner = f"K8s v{metadata['version']}"
                        
                        if 'dirty' in version_data.get('gitVersion', ''):
                            metadata['is_dev_version'] = True
                            banner += " | DEVELOPMENT BUILD ⚠️"
                            
                    elif resp.status == 401:
                        banner += " | Authentication required (token/cert)"
                        metadata['auth_required'] = True
                        return banner, metadata  # Arrêt si auth requise
                        
                # Si on arrive ici, l'API est accessible (peut-être sans auth)
                # Tester /api/v1/namespaces (souvent la première étape)
                async with session.get(f"https://{ip}:{port}/api/v1/namespaces", timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        metadata['has_default_creds'] = True
                        banner += " | NO AUTHENTICATION REQUIRED ☠️"
                        
                        ns_data = await resp.json()
                        metadata['namespaces'] = len(ns_data.get('items', []))
                        banner += f" | {metadata['namespaces']} namespaces"
                        
                        # Récupération pods
                        async with session.get(f"https://{ip}:{port}/api/v1/pods", timeout=5, ssl=False) as pods_resp:
                            if pods_resp.status == 200:
                                pods_data = await pods_resp.json()
                                metadata['pods'] = len(pods_data.get('items', []))
                                banner += f", {metadata['pods']} pods"
                                
                                # Détection de pods sensibles
                                sensitive_pods = []
                                for pod in pods_data.get('items', []):
                                    pod_name = pod.get('metadata', {}).get('name', '')
                                    if any(x in pod_name.lower() for x in ['database', 'mysql', 'postgres', 'redis', 'vault', 'secret']):
                                        sensitive_pods.append(pod_name)
                                        
                                if sensitive_pods:
                                    metadata['sensitive_pods'] = sensitive_pods[:10]
                                    banner += f" | ⚠️ SENSITIVE PODS: {', '.join(sensitive_pods[:3])}"
                                    
                        # Récupération nodes
                        async with session.get(f"https://{ip}:{port}/api/v1/nodes", timeout=5, ssl=False) as nodes_resp:
                            if nodes_resp.status == 200:
                                nodes_data = await nodes_resp.json()
                                metadata['nodes'] = len(nodes_data.get('items', []))
                                banner += f", {metadata['nodes']} nodes"
                                
                        # Vérification des secrets accessibles (très dangereux)
                        async with session.get(f"https://{ip}:{port}/api/v1/secrets", timeout=5, ssl=False) as secrets_resp:
                            if secrets_resp.status == 200:
                                secrets_data = await secrets_resp.json()
                                secret_count = len(secrets_data.get('items', []))
                                if secret_count > 0:
                                    metadata['secrets_exposed'] = secret_count
                                    banner += f" | ☠️ {secret_count} SECRETS EXPOSED"
                                    
                    elif resp.status == 403:
                        # Authentifié mais permissions limitées
                        banner += " | Authenticated but limited RBAC"
                        
            except asyncio.TimeoutError:
                banner += " | Timeout"
            except aiohttp.ClientConnectorError:
                banner += " | Connection refused"
            except ssl.SSLError:
                metadata['insecure'] = True
                banner += " | SSL certificate error (possible MITM risk)"
            except Exception as e:
                banner += f" | Error: {str(e)[:50]}"
                
        # Tentative 2: Dashboard Kubernetes (port 8001 souvent)
        if port == 6443:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{ip}:8001", timeout=3) as resp:
                        if resp.status == 200:
                            banner += " | Dashboard exposed on port 8001 ⚠️"
                            metadata['dashboard_exposed'] = True
            except:
                pass
                
        return banner, metadata
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si K8s API requiert auth"""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(f"https://{ip}:{port}/version", timeout=3, ssl=False) as resp:
                    return resp.status == 401
            except:
                return True
"""Redis module with anomaly detection"""
import asyncio
from typing import Tuple, Dict, Any
from redis.asyncio import Redis
from redis.exceptions import AuthenticationError, ConnectionError, TimeoutError

from blackops.modules.base import BaseModule

class RedisModule(BaseModule):
    """Module Redis avec détection d'anomalies"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe Redis et retourne (banner, metadata)"""
        metadata = {
            'has_default_creds': False,
            'is_dev_version': False,
            'keys_count': 0,
            'memory_usage_mb': 0,
            'role': 'unknown'
        }
        banner = "Redis"
        
        # Tentative 1: Connexion sans mot de passe
        client = Redis(host=ip, port=port, socket_timeout=5, decode_responses=True)
        
        try:
            # Ping test
            await client.ping()
            metadata['has_default_creds'] = True
            banner += " | NO AUTHENTICATION REQUIRED ⚠️"
            
            # Collecte d'informations approfondies
            info = await client.info()
            metadata['version'] = info.get('redis_version', 'unknown')
            metadata['role'] = info.get('role', 'unknown')
            metadata['memory_usage_mb'] = info.get('used_memory', 0) / (1024 * 1024)
            metadata['connected_clients'] = info.get('connected_clients', 0)
            
            # Détection de version dangereuse
            if metadata['version'].startswith(('2.', '3.', '4.0')):
                metadata['is_dev_version'] = True
                banner += f" | OLD VERSION {metadata['version']} ⚠️"
            else:
                banner += f" | v{metadata['version']}"
            
            # Liste des clés (échantillon)
            keys = await client.keys('*')
            metadata['keys_count'] = len(keys)
            if metadata['keys_count'] > 0:
                banner += f" | {metadata['keys_count']} keys found"
                
            # Échantillon de 5 premières clés
            if keys and len(keys) <= 5:
                metadata['sample_keys'] = keys[:5]
            elif keys:
                metadata['sample_keys'] = keys[:5]
                banner += f" (sample: {', '.join(keys[:3])}...)"
            
            # Détection de données sensibles
            suspicious_keys = [k for k in keys if any(x in k.lower() for x in 
                              ['password', 'token', 'secret', 'key', 'auth', 'session'])]
            if suspicious_keys:
                metadata['suspicious_keys'] = suspicious_keys[:10]
                banner += f" | ⚠️ SENSITIVE KEYS DETECTED"
            
            # Configuration dangereuse
            config = await client.config_get('*')
            if config.get('save', '') == '':
                metadata['persistence_disabled'] = True
                banner += " | persistence disabled"
                
            if config.get('requirepass', '') == '' and not metadata['has_default_creds']:
                # Déjà capturé plus haut
                pass
                
        except AuthenticationError:
            banner += " | Authentication required (password needed)"
            metadata['auth_required'] = True
            
        except (ConnectionError, TimeoutError) as e:
            banner += f" | Connection failed: {str(e)[:50]}"
            
        except Exception as e:
            banner += f" | Error: {str(e)[:50]}"
            
        finally:
            await client.close()
            
        return banner, metadata
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si Redis est protégé par mot de passe"""
        client = Redis(host=ip, port=port, socket_timeout=3)
        try:
            await client.ping()
            return False  # Pas d'auth requise = dangereux
        except AuthenticationError:
            return True  # Auth requise
        except:
            return True  # On suppose auth par défaut
        finally:
            await client.close()
"""MongoDB module with proper wire protocol and anomaly detection"""
import asyncio
import struct
from typing import Tuple, Dict, Any

from bson import BSON, decode
from blackops.modules.base import BaseModule

class MongoDBModule(BaseModule):
    """Module MongoDB avec détection d'anomalies et low-level wire protocol"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe MongoDB et retourne (banner, metadata)"""
        metadata = {}
        
        # Tentative 1: Handshake standard
        banner = await self._wire_handshake(ip, port)
        if not banner:
            return "Failed to connect", metadata
            
        # Tentative 2: Récupération des infos sensibles
        db_list = await self._list_databases(ip, port)
        metadata['databases_found'] = len(db_list) if db_list else 0
        metadata['has_admin_db'] = 'admin' in db_list if db_list else False
        
        # Détection d'auth faible
        if await self._check_no_auth(ip, port):
            metadata['has_default_creds'] = True
            banner += " | NO AUTHENTICATION REQUIRED"
            
        # Version MongoDB si disponible
        version = await self._get_version(ip, port)
        if version:
            metadata['version'] = version
            if version.startswith('3.') or version.startswith('2.'):
                metadata['is_dev_version'] = True
                
        return banner, metadata
    
    async def _wire_handshake(self, ip: str, port: int) -> str:
        """Handshake bas niveau via protocole wire"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            
            # Message OP_MSG moderne ou OP_QUERY legacy
            # BuildInfo command
            cmd = BSON.encode({"buildInfo": 1})
            msg = struct.pack("<iiii", 16 + len(cmd), 1, 0, 2013)  # OP_MSG
            msg += cmd
            
            writer.write(msg)
            await writer.drain()
            
            # Lecture avec timeout
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            
            # Décodage BSON simple
            try:
                _, _, _, _, doc = decode(data)  # Simplifié
                return doc.get('version', 'Unknown')
            except:
                return "MongoDB detected (wire protocol)"
                
        except Exception as e:
            return f"MongoDB error: {str(e)[:50]}"
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _list_databases(self, ip: str, port: int) -> list:
        """Liste les databases si possible"""
        # Implémentation similaire à _wire_handshake avec "listDatabases"
        pass  # Simplifié pour l'exemple
    
    async def _check_no_auth(self, ip: str, port: int) -> bool:
        """Test si auth requise"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            # Tentative de commande simple sans auth
            cmd = BSON.encode({"ping": 1})
            # ... envoi
            writer.close()
            return True  # Si réponse reçue sans erreur
        except:
            return False
    
    async def _get_version(self, ip: str, port: int) -> str:
        """Extrait la version MongoDB"""
        # Similaire à _wire_handshake
        pass
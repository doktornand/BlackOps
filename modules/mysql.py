"""MySQL module with anomaly detection"""
import asyncio
import aiomysql
from typing import Tuple, Dict, Any

from blackops.modules.base import BaseModule

class MySQLModule(BaseModule):
    """Module MySQL avec détection d'anomalies"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe MySQL et retourne (banner, metadata)"""
        metadata = {
            'has_default_creds': False,
            'is_dev_version': False,
            'database_count': 0,
            'table_count': 0,
            'version': 'unknown',
            'ssl_enabled': False
        }
        banner = "MySQL"
        
        # Tentatives d'auth (root sans mdp d'abord)
        credentials_to_try = [
            ('root', ''),
            ('root', 'root'),
            ('mysql', ''),
            ('admin', ''),
            ('test', 'test')
        ]
        
        connected = False
        for user, password in credentials_to_try:
            try:
                conn = await aiomysql.connect(
                    host=ip, port=port,
                    user=user, password=password,
                    connect_timeout=5,
                    autocommit=True
                )
                
                async with conn.cursor() as cursor:
                    # Version
                    await cursor.execute("SELECT VERSION()")
                    version_row = await cursor.fetchone()
                    metadata['version'] = version_row[0] if version_row else 'unknown'
                    
                    # SSL
                    await cursor.execute("SHOW VARIABLES LIKE 'have_ssl'")
                    ssl_row = await cursor.fetchone()
                    metadata['ssl_enabled'] = ssl_row and ssl_row[1] == 'YES'
                    
                    # Base de données
                    await cursor.execute("SHOW DATABASES")
                    dbs = await cursor.fetchall()
                    metadata['database_count'] = len(dbs)
                    metadata['databases'] = [db[0] for db in dbs if db[0] not in 
                                            ['information_schema', 'performance_schema', 'mysql', 'sys']]
                    
                    # Comptage des tables
                    total_tables = 0
                    for db in metadata['databases'][:10]:  # Limite à 10 DBs
                        await cursor.execute(f"USE `{db}`")
                        await cursor.execute("SHOW TABLES")
                        tables = await cursor.fetchall()
                        total_tables += len(tables)
                    metadata['table_count'] = total_tables
                    
                # Connexion réussie
                connected = True
                metadata['has_default_creds'] = True
                banner = f"MySQL v{metadata['version']} | accessible as '{user}' (default credentials) ⚠️"
                
                # Détection de version dangereuse
                if metadata['version'].startswith(('5.', '5.1', '5.5')):
                    metadata['is_dev_version'] = True
                    banner += " | OBSOLETE VERSION ⚠️"
                
                if metadata['database_count'] > 0:
                    banner += f" | {metadata['database_count']} databases, {metadata['table_count']} tables"
                    
                if not metadata['ssl_enabled']:
                    banner += " | SSL DISABLED ⚠️"
                    
                break  # Sortie si connexion réussie
                
            except aiomysql.Error as e:
                # Erreur MySQL normale (auth refusée généralement)
                if "Access denied" in str(e):
                    continue  # Essayer autre creds
                else:
                    # Autre erreur (connexion refusée, timeout)
                    if not connected:
                        banner = f"MySQL | Error: {str(e)[:50]}"
                    break
                    
            except Exception as e:
                if not connected:
                    banner = f"MySQL | Connection failed: {str(e)[:50]}"
                break
                
            finally:
                if 'conn' in locals() and conn:
                    conn.close()
                    
        if not connected and metadata['version'] == 'unknown':
            # Dernier essai: grab banner sans auth
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                # MySQL envoie un greeting packet initial
                data = await asyncio.wait_for(reader.read(255), timeout=3)
                if data and data[0:4] == b'\x0a\x00\x00\x00':  # MySQL packet header
                    # Extraire version approximative (position 5+)
                    version_end = data.find(b'\x00', 5)
                    if version_end > 5:
                        version = data[5:version_end].decode('utf-8', errors='ignore')
                        metadata['version'] = version
                        banner = f"MySQL (likely v{version}) | authentication required"
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
        # Si on a une version mais pas de connexion
        if not connected and metadata['version'] != 'unknown':
            banner = f"MySQL v{metadata['version']} | authentication required"
            
        return banner, metadata
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si MySQL nécessite une authentification"""
        try:
            conn = await aiomysql.connect(
                host=ip, port=port,
                user='root', password='',
                connect_timeout=3
            )
            conn.close()
            return False  # Pas d'auth requise
        except:
            return True  # Auth requise
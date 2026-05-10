"""PostgreSQL module with anomaly detection"""
import asyncio
import asyncpg
from typing import Tuple, Dict, Any

from blackops.modules.base import BaseModule

class PostgreSQLModule(BaseModule):
    """Module PostgreSQL avec détection d'anomalies"""
    
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """Probe PostgreSQL et retourne (banner, metadata)"""
        metadata = {
            'has_default_creds': False,
            'is_dev_version': False,
            'database_count': 0,
            'table_count': 0,
            'version': 'unknown',
            'ssl_enabled': False,
            'extensions': []
        }
        banner = "PostgreSQL"
        
        # Tentatives d'auth (postgres sans mdp d'abord)
        credentials_to_try = [
            ('postgres', ''),
            ('postgres', 'postgres'),
            ('admin', ''),
            ('test', 'test')
        ]
        
        connected = False
        for user, password in credentials_to_try:
            try:
                conn = await asyncpg.connect(
                    host=ip, port=port,
                    user=user, password=password,
                    database='postgres',
                    timeout=5
                )
                
                # Version
                version_row = await conn.fetchrow("SELECT version()")
                metadata['version'] = version_row[0] if version_row else 'unknown'
                
                # SSL
                ssl_row = await conn.fetchrow("SELECT name, setting FROM pg_settings WHERE name = 'ssl'")
                metadata['ssl_enabled'] = ssl_row and ssl_row['setting'] == 'on'
                
                # Bases de données
                dbs = await conn.fetch("SELECT datname FROM pg_database WHERE datistemplate = false")
                metadata['database_count'] = len(dbs)
                metadata['databases'] = [db['datname'] for db in dbs]
                
                # Tables dans la base courante
                tables = await conn.fetch("""
                    SELECT table_schema, table_name 
                    FROM information_schema.tables 
                    WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
                """)
                metadata['table_count'] = len(tables)
                
                # Extensions
                extensions = await conn.fetch("SELECT extname FROM pg_extension")
                metadata['extensions'] = [ext['extname'] for ext in extensions]
                
                # Détection d'extensions dangereuses
                dangerous_extensions = ['dblink', 'file_fdw', 'adminpack']
                found_dangerous = [ext for ext in metadata['extensions'] if ext in dangerous_extensions]
                if found_dangerous:
                    metadata['dangerous_extensions'] = found_dangerous
                
                await conn.close()
                
                # Connexion réussie
                connected = True
                metadata['has_default_creds'] = True
                banner = f"PostgreSQL v{metadata['version']} | accessible as '{user}' (default credentials) ⚠️"
                
                # Détection de version dangereuse
                if metadata['version'].startswith(('8.', '9.0', '9.1', '9.2')):
                    metadata['is_dev_version'] = True
                    banner += " | OBSOLETE VERSION ⚠️"
                
                if metadata['database_count'] > 0:
                    banner += f" | {metadata['database_count']} databases, {metadata['table_count']} tables"
                    
                if not metadata['ssl_enabled']:
                    banner += " | SSL DISABLED ⚠️"
                    
                if found_dangerous:
                    banner += f" | DANGEROUS EXTENSIONS: {', '.join(found_dangerous)} ⚠️"
                    
                break  # Sortie si connexion réussie
                
            except (asyncpg.InvalidPasswordError, asyncpg.AuthenticationError):
                continue  # Essayer autre creds
                
            except Exception as e:
                if not connected:
                    banner = f"PostgreSQL | Error: {str(e)[:50]}"
                break
                
        if not connected and metadata['version'] == 'unknown':
            # Dernier essai: grab banner version sans auth
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                # PostgreSQL envoie un message d'accueil
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                if data and data[0:1] == b'E':  # Error message
                    # Extraire version du message d'erreur
                    banner_text = data.decode('utf-8', errors='ignore')
                    import re
                    version_match = re.search(r'PostgreSQL ([\d\.]+)', banner_text)
                    if version_match:
                        metadata['version'] = version_match.group(1)
                        banner = f"PostgreSQL v{metadata['version']} | authentication required"
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
        if not connected and metadata['version'] != 'unknown':
            banner = f"PostgreSQL v{metadata['version']} | authentication required"
            
        return banner, metadata
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si PostgreSQL nécessite une authentification"""
        try:
            conn = await asyncpg.connect(
                host=ip, port=port,
                user='postgres', password='',
                database='postgres',
                timeout=3
            )
            await conn.close()
            return False
        except:
            return True
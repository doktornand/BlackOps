"""Base module for all BlackOps scanners"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any

class BaseModule(ABC):
    """Classe de base pour tous les modules de scan"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.module_config = config['modules'].get(self.__class__.__name__.lower().replace('module', ''), {})
        
    @abstractmethod
    async def probe(self, ip: str, port: int) -> Tuple[str, Dict[str, Any]]:
        """
        Probe un service et retourne (banner, metadata)
        - banner: str (info service, version, warning)
        - metadata: dict (infos structurées pour anomalies)
        """
        pass
    
    async def check_auth(self, ip: str, port: int) -> bool:
        """Vérifie si l'authentification est requise (peut être overriden)"""
        return True  # Par défaut, on suppose auth requise
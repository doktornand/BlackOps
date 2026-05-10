"""Core scanning engine with anomaly detection"""
import asyncio
import time
import random
from typing import List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import statistics

from blackops.utils.logger import get_logger
from blackops.core.stealth import StealthEngine
from blackops.core.anomalies import AnomalyDetector

logger = get_logger(__name__)

@dataclass
class ScanResult:
    """Résultat avec métriques d'anomalie"""
    target_ip: str
    port: int
    service: str
    success: bool
    response_time_ms: float
    banner: str = ""
    error: str = ""
    anomaly_score: float = 0.0
    anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

class DeepScanner:
    """Scanner avec analyse d'anomalies"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.stealth = StealthEngine(config)
        self.anomaly_detector = AnomalyDetector(config)
        self.results: List[ScanResult] = []
        self._response_times: Dict[str, List[float]] = {}
        
    async def scan_target(self, ip: str, port: int, service: str, scan_func) -> ScanResult:
        """Scanne une cible unique avec métriques temporelles"""
        start_time = time.time()
        result = ScanResult(
            target_ip=ip,
            port=port,
            service=service,
            success=False,
            response_time_ms=0.0
        )
        
        # Jitter avant scan
        await self.stealth.apply_jitter()
        
        try:
            # Exécution avec timeout configurable
            banner, metadata = await asyncio.wait_for(
                scan_func(ip, port),
                timeout=self.config['scan']['timeout']
            )
            
            result.success = True
            result.banner = banner[:500]  # Troncature
            result.metadata = metadata
            
        except asyncio.TimeoutError:
            result.error = "Timeout"
            result.anomalies.append("timeout_unusual")
        except Exception as e:
            result.error = str(e)[:200]
            result.anomalies.append("connection_failed")
        
        finally:
            result.response_time_ms = (time.time() - start_time) * 1000
            
            # Détection d'anomalies
            result.anomaly_score, detected = self.anomaly_detector.analyze(
                ip, port, service, result
            )
            result.anomalies.extend(detected)
            
            # Log des anomalies graves
            if result.anomaly_score > 0.7:
                logger.warning(f"High anomaly score {result.anomaly_score} for {ip}:{port}",
                              extra={'anomalies': result.anomalies})
            
            return result
    
    async def scan_batch(self, targets: List[tuple], scan_func) -> List[ScanResult]:
        """Scan batch avec rate limiting et parallélisme contrôlé"""
        semaphore = asyncio.Semaphore(self.config['scan']['parallel'])
        
        async def bounded_scan(ip, port, service):
            async with semaphore:
                # Rate limiting global
                await self.stealth.rate_limit()
                return await self.scan_target(ip, port, service, scan_func)
        
        tasks = [bounded_scan(ip, port, service) for (ip, port, service) in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrer les exceptions
        valid_results = [r for r in results if isinstance(r, ScanResult)]
        self.results.extend(valid_results)
        return valid_results
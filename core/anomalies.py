"""Advanced anomaly detection - baseline, z-score, patterns"""
import statistics
from collections import defaultdict
from typing import List, Dict, Tuple
import re

class AnomalyDetector:
    """Détecte des anomalies basées sur :
    - Temps de réponse anormal (vs baseline)
    - Pattern d'erreur
    - Banner inhabituel
    - Métadonnées inattendues
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.baselines: Dict[str, List[float]] = defaultdict(list)  # service: [response_times]
        self.STD_MULT = config['anomaly_detection']['baseline_std_multiplier']
        self.SLOW_MS = config['anomaly_detection']['slow_threshold_ms']
        self.ERROR_BURST = config['anomaly_detection']['error_burst_threshold']
        
        # Patterns suspects
        self.suspicious_banner_patterns = [
            r'default\s+password', r'弱口令', r'test|demo|example',
            r'development\s+mode', r'debug\s*=true', r'backdoor'
        ]
        
    def update_baseline(self, service: str, response_time: float):
        """Met à jour la baseline statistique pour ce service"""
        self.baselines[service].append(response_time)
        # Garder seulement les 100 dernières mesures
        if len(self.baselines[service]) > 100:
            self.baselines[service] = self.baselines[service][-100:]
    
    def is_time_anomaly(self, service: str, response_time: float) -> Tuple[bool, float]:
        """Anomalie temporelle via écart-type"""
        if len(self.baselines[service]) < 5:
            return False, 0.0
            
        mean = statistics.mean(self.baselines[service])
        stdev = statistics.stdev(self.baselines[service]) if len(self.baselines[service]) > 1 else 1.0
        
        z_score = abs(response_time - mean) / stdev if stdev > 0 else 0
        is_anomaly = z_score > self.STD_MULT
        
        # Seuil absolu pour latence excessive
        if response_time > self.SLOW_MS:
            is_anomaly = True
            z_score = max(z_score, 1.5)
            
        return is_anomaly, z_score
    
    def is_banner_anomaly(self, banner: str) -> Tuple[bool, List[str]]:
        """Détecte des bannières suspectes"""
        detected = []
        banner_lower = banner.lower()
        
        for pattern in self.suspicious_banner_patterns:
            if re.search(pattern, banner_lower):
                detected.append(f"suspicious_banner:{pattern}")
                
        # Version anormalement ancienne
        if re.search(r'version\s+[01]\.', banner_lower):
            detected.append("deprecated_version")
            
        # Indice de développement/test
        if 'snapshot' in banner_lower or 'beta' in banner_lower:
            detected.append("non_production_build")
            
        return len(detected) > 0, detected
    
    def analyze(self, ip: str, port: int, service: str, result) -> Tuple[float, List[str]]:
        """Score global d'anomalie (0-1)"""
        score = 0.0
        anomalies = []
        
        # 1. Anomalie temporelle (poids 0.4)
        time_anomaly, z_score = self.is_time_anomaly(service, result.response_time_ms)
        if time_anomaly:
            score += min(0.4, z_score * 0.1)
            anomalies.append(f"temporal_anomaly:z={z_score:.2f}")
        
        # 2. Banner suspect (poids 0.3)
        banner_suspect, banner_issues = self.is_banner_anomaly(result.banner)
        if banner_suspect:
            score += 0.3
            anomalies.extend(banner_issues)
        
        # 3. Pattern d'erreur (poids 0.2)
        if result.error:
            if "Authentication" in result.error or "Access denied" in result.error:
                score += 0.1  # Normal, faible
                anomalies.append("auth_required")
            elif "timeout" in result.error.lower():
                score += 0.15
                anomalies.append("timeout_anomaly")
            elif "refused" in result.error.lower():
                score += 0.2  # Port fermé mais attendu ouvert
                anomalies.append("port_unexpectedly_closed")
        
        # 4. Métadonnées inattendues (poids 0.1)
        if result.metadata.get('is_dev_version'):
            score += 0.1
            anomalies.append("development_version")
            
        if result.metadata.get('has_default_creds'):
            score += 0.2  # Grave
            anomalies.append("default_credentials_exposed")
        
        # Mise à jour baseline pour les succès
        if result.success and not time_anomaly:
            self.update_baseline(service, result.response_time_ms)
        
        return min(1.0, score), anomalies
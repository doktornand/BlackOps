#!/usr/bin/env python3
"""BlackOps CLI - Deep Server Anomaly Searcher"""
import asyncio
import argparse
import sys
from pathlib import Path

from blackops.utils.config import load_config
from blackops.utils.logger import setup_logging, get_logger
from blackops.core.scanner import DeepScanner
from blackops.utils.reporter import Reporter

logger = get_logger(__name__)

async def main():
    parser = argparse.ArgumentParser(description="BlackOps - Advanced Server Anomaly Detection")
    parser.add_argument('-c', '--config', default='config.yaml', help='Config file')
    parser.add_argument('-i', '--ip-list', help='File with IPs (one per line)')
    parser.add_argument('-m', '--module', help='Specific module (mongodb, mysql, etc.)')
    parser.add_argument('-o', '--output', help='Output prefix for reports')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy')
    parser.add_argument('--deep', action='store_true', help='Enable deep anomaly detection (slower)')
    
    args = parser.parse_args()
    
    # Chargement config
    config = load_config(args.config)
    if args.no_proxy:
        config['proxy']['socks5']['enabled'] = False
        config['proxy']['http']['enabled'] = False
    
    # Setup logging
    setup_logging(config)
    
    logger.info("BlackOps starting", extra={'deep_mode': args.deep})
    
    # Lecture IPs
    if not args.ip_list:
        logger.error("No IP list provided")
        sys.exit(1)
    
    with open(args.ip_list) as f:
        ips = [line.strip() for line in f if line.strip()]
    
    logger.info(f"Loaded {len(ips)} targets")
    
    # Scanner
    scanner = DeepScanner(config)
    
    # Construction targets (simplifié)
    targets = []
    for ip in ips:
        for port, service in config['modules'].items():
            if config['modules'][service]['enabled']:
                for p in config['modules'][service]['ports']:
                    targets.append((ip, p, service))
    
    logger.info(f"Scanning {len(targets)} service endpoints")
    
    # Scan
    results = await scanner.scan_batch(targets, mock_scan_func)  # À remplacer par vraie fonction
    
    # Rapport
    reporter = Reporter(config)
    report_files = reporter.generate(results, args.output or 'blackops_scan')
    
    logger.info(f"Reports saved: {report_files}")
    
    # Résumé anomalies
    high_risk = [r for r in results if r.anomaly_score > 0.7]
    if high_risk:
        logger.warning(f"Found {len(high_risk)} high-risk anomalies")
        for r in high_risk[:5]:
            print(f"⚠️  {r.target_ip}:{r.port} - score {r.anomaly_score:.2f} - {', '.join(r.anomalies)}")

if __name__ == "__main__":
    asyncio.run(main())
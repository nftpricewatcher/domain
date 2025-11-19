#!/usr/bin/env python3
"""
Proxy Scraper Module - Continuously finds and tests fresh proxies
"""
import requests
import re
import time
import threading
import socket
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ProxyScraper:
    """Continuously scrapes, tests, and maintains a pool of working proxies"""
    
    def __init__(self, max_proxies=100):
        self.working_proxies = []
        self.tested_proxies = {}  # proxy -> last_test_time
        self.proxy_lock = threading.Lock()
        self.max_proxies = max_proxies
        self.running = True
        
        # Start background threads
        self.scraper_thread = threading.Thread(target=self._scraper_loop, daemon=True)
        self.tester_thread = threading.Thread(target=self._tester_loop, daemon=True)
        
        self.scraper_thread.start()
        self.tester_thread.start()
        
        logger.info("Proxy scraper initialized and running in background")
    
    def get_proxy(self):
        """Get a random working proxy or None"""
        with self.proxy_lock:
            if self.working_proxies:
                return random.choice(self.working_proxies)
        return None
    
    def _scraper_loop(self):
        """Main scraper loop that continuously finds new proxies"""
        while self.running:
            try:
                logger.info("Starting proxy scraping round...")
                new_proxies = self._scrape_all_sources()
                logger.info(f"Found {len(new_proxies)} potential proxies")
                
                # Add to testing queue
                for proxy in new_proxies:
                    if proxy not in self.tested_proxies:
                        self.tested_proxies[proxy] = 0
                
                # Wait before next scraping round
                time.sleep(300)  # Scrape every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in scraper loop: {e}")
                time.sleep(60)
    
    def _tester_loop(self):
        """Continuously test proxies"""
        while self.running:
            try:
                current_time = time.time()
                
                # Get proxies that need testing
                to_test = []
                for proxy, last_test in self.tested_proxies.items():
                    if current_time - last_test > 300:  # Test every 5 minutes
                        to_test.append(proxy)
                
                if to_test:
                    logger.debug(f"Testing {len(to_test)} proxies...")
                    
                    # Test in parallel
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = {executor.submit(self._test_proxy, proxy): proxy for proxy in to_test[:50]}
                        
                        for future in as_completed(futures):
                            proxy = futures[future]
                            try:
                                if future.result():
                                    with self.proxy_lock:
                                        if proxy not in self.working_proxies:
                                            self.working_proxies.append(proxy)
                                            logger.info(f"Added working proxy: {proxy}")
                                else:
                                    with self.proxy_lock:
                                        if proxy in self.working_proxies:
                                            self.working_proxies.remove(proxy)
                            except:
                                pass
                            
                            self.tested_proxies[proxy] = current_time
                    
                    # Limit pool size
                    with self.proxy_lock:
                        if len(self.working_proxies) > self.max_proxies:
                            self.working_proxies = self.working_proxies[-self.max_proxies:]
                    
                    logger.info(f"Currently have {len(self.working_proxies)} working proxies")
                
                time.sleep(30)  # Test cycle every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in tester loop: {e}")
                time.sleep(30)
    
    def _test_proxy(self, proxy):
        """Test if a proxy works"""
        try:
            proxies = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            
            # Quick test against a reliable endpoint
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=5,
                verify=False
            )
            
            if response.status_code == 200:
                return True
                
        except:
            pass
        
        return False
    
    def _scrape_all_sources(self):
        """Scrape proxies from all available sources"""
        all_proxies = set()
        
        # Source 1: free-proxy-list.net
        try:
            proxies = self._scrape_free_proxy_list()
            all_proxies.update(proxies)
        except Exception as e:
            logger.debug(f"Error scraping free-proxy-list: {e}")
        
        # Source 2: sslproxies.org
        try:
            proxies = self._scrape_ssl_proxies()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 3: proxy-list.download
        try:
            proxies = self._scrape_proxy_list_download()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 4: proxyscrape.com
        try:
            proxies = self._scrape_proxyscrape()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 5: proxylist.geonode.com
        try:
            proxies = self._scrape_geonode()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 6: free-proxy-list.com
        try:
            proxies = self._scrape_free_proxy_list_com()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 7: hidemy.name
        try:
            proxies = self._scrape_hidemy()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 8: proxynova.com
        try:
            proxies = self._scrape_proxynova()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 9: spys.one
        try:
            proxies = self._scrape_spys()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 10: openproxy.space
        try:
            proxies = self._scrape_openproxy()
            all_proxies.update(proxies)
        except:
            pass
        
        # Source 11-25: Various API endpoints
        api_urls = [
            'https://www.proxy-list.download/api/v1/get?type=http',
            'https://www.proxyscan.io/download?type=http',
            'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
            'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
            'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
            'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
            'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
            'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
            'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
            'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
            'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt',
            'https://api.proxyscrape.com/v2/?request=get&protocol=http',
            'https://api.openproxylist.xyz/http.txt',
            'http://worm.rip/http.txt',
            'https://proxyspace.pro/http.txt'
        ]
        
        for url in api_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    # Extract IP:PORT patterns
                    proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
                    all_proxies.update(proxies)
            except:
                continue
        
        return list(all_proxies)
    
    def _scrape_free_proxy_list(self):
        """Scrape from free-proxy-list.net"""
        try:
            response = requests.get(
                'https://free-proxy-list.net/',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            # Extract from HTML table
            proxies = []
            lines = response.text.split('\n')
            for line in lines:
                if '<td>' in line and '.' in line:
                    # Try to extract IP and port
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and i + 1 < len(lines):
                        port_match = re.search(r'<td>(\d+)</td>', lines[i + 1])
                        if port_match:
                            proxies.append(f"{ip_match.group(1)}:{port_match.group(1)}")
            
            return proxies
        except:
            return []
    
    def _scrape_ssl_proxies(self):
        """Scrape from sslproxies.org"""
        try:
            response = requests.get(
                'https://www.sslproxies.org/',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _scrape_proxy_list_download(self):
        """Scrape from proxy-list.download"""
        try:
            response = requests.get(
                'https://www.proxy-list.download/api/v1/get?type=http',
                timeout=10
            )
            
            proxies = []
            for line in response.text.split('\n'):
                if ':' in line:
                    proxies.append(line.strip())
            
            return proxies
        except:
            return []
    
    def _scrape_proxyscrape(self):
        """Scrape from proxyscrape.com"""
        try:
            response = requests.get(
                'https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all',
                timeout=10
            )
            
            proxies = []
            for line in response.text.split('\n'):
                if ':' in line:
                    proxies.append(line.strip())
            
            return proxies
        except:
            return []
    
    def _scrape_geonode(self):
        """Scrape from geonode.com"""
        try:
            response = requests.get(
                'https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc',
                timeout=10
            )
            
            proxies = []
            data = response.json()
            if 'data' in data:
                for proxy in data['data']:
                    if 'ip' in proxy and 'port' in proxy:
                        proxies.append(f"{proxy['ip']}:{proxy['port']}")
            
            return proxies
        except:
            return []
    
    def _scrape_free_proxy_list_com(self):
        """Scrape from free-proxy-list.com"""
        try:
            response = requests.get(
                'https://free-proxy-list.com/?page=1',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _scrape_hidemy(self):
        """Scrape from hidemy.name"""
        try:
            response = requests.get(
                'https://hidemy.name/en/proxy-list/',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _scrape_proxynova(self):
        """Scrape from proxynova.com"""
        try:
            response = requests.get(
                'https://www.proxynova.com/proxy-server-list/',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _scrape_spys(self):
        """Scrape from spys.one"""
        try:
            response = requests.get(
                'https://spys.one/en/http-proxy-list/',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _scrape_openproxy(self):
        """Scrape from openproxy.space"""
        try:
            response = requests.get(
                'https://openproxy.space/list/http',
                headers={'User-Agent': self._get_random_ua()},
                timeout=10
            )
            
            proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
            return proxies
        except:
            return []
    
    def _get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        return random.choice(user_agents)
    
    def get_stats(self):
        """Get current proxy stats"""
        with self.proxy_lock:
            return {
                'working': len(self.working_proxies),
                'total_tested': len(self.tested_proxies),
                'proxies': self.working_proxies[:10]  # Sample
            }

#!/usr/bin/env python3
import os
import json
import time
import string
import itertools
import socket
import random
import logging
from datetime import datetime
import signal
import sys
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

warnings.filterwarnings('ignore')

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("ERROR: requests module required. Install with: pip install requests")
    sys.exit(1)

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Priority TLDs (shortest and most valuable first)
PRIORITY_TLDS = [
    'io', 'ai', 'me', 'co', 'to', 'so', 'sh', 'gg', 'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot'
]

class ProxyScraper:
    """Continuously scrapes, tests, and maintains a pool of working proxies"""
    
    def __init__(self, max_proxies=100):
        self.working_proxies = []
        self.tested_proxies = {}
        self.proxy_lock = threading.Lock()
        self.max_proxies = max_proxies
        self.running = True
        
        self.scraper_thread = threading.Thread(target=self._scraper_loop, daemon=True)
        self.tester_thread = threading.Thread(target=self._tester_loop, daemon=True)
        
        self.scraper_thread.start()
        self.tester_thread.start()
        
        logger.info("Proxy scraper initialized and running in background")
    
    def get_proxy(self):
        with self.proxy_lock:
            if self.working_proxies:
                return random.choice(self.working_proxies)
        return None
    
    def _scraper_loop(self):
        while self.running:
            try:
                logger.info("Starting proxy scraping round...")
                new_proxies = self._scrape_all_sources()
                logger.info(f"Found {len(new_proxies)} potential proxies")
                
                for proxy in new_proxies:
                    if proxy not in self.tested_proxies:
                        self.tested_proxies[proxy] = 0
                
                time.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in scraper loop: {e}")
                time.sleep(60)
    
    def _tester_loop(self):
        while self.running:
            try:
                current_time = time.time()
                
                to_test = []
                for proxy, last_test in self.tested_proxies.items():
                    if current_time - last_test > 300:
                        to_test.append(proxy)
                
                if to_test:
                    logger.debug(f"Testing {len(to_test)} proxies...")
                    
                    with ThreadPoolExecutor(max_workers=20) as executor:
                        futures = {executor.submit(self._test_proxy, proxy): proxy for proxy in to_test[:50]}
                        
                        for future in futures:
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
                    
                    with self.proxy_lock:
                        if len(self.working_proxies) > self.max_proxies:
                            self.working_proxies = self.working_proxies[-self.max_proxies:]
                    
                    logger.info(f"Currently have {len(self.working_proxies)} working proxies")
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in tester loop: {e}")
                time.sleep(30)
    
    def _test_proxy(self, proxy):
        try:
            proxies = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            
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
        all_proxies = set()
        
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
                    proxies = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
                    all_proxies.update(proxies)
            except:
                continue
        
        return list(all_proxies)
    
    def get_stats(self):
        with self.proxy_lock:
            return {
                'working': len(self.working_proxies),
                'total_tested': len(self.tested_proxies),
                'proxies': self.working_proxies[:10]
            }

class WhoisProxyRotator:
    """Rotates through multiple WHOIS services to avoid rate limits"""
    
    def __init__(self):
        # Initialize proxy scraper
        self.proxy_scraper = ProxyScraper(max_proxies=50)
        logger.info("Proxy scraper initialized - will continuously find new proxies")
        
        self.services = [
            # Primary services (higher weights)
            {'name': 'godaddy', 'func': self.check_godaddy, 'weight': 15},
            {'name': 'namecheap', 'func': self.check_namecheap, 'weight': 15},
            {'name': 'porkbun', 'func': self.check_porkbun, 'weight': 12},
            {'name': 'whois.com', 'func': self.check_whois_com, 'weight': 12},
            {'name': 'who.is', 'func': self.check_who_is, 'weight': 12},
            
            # Secondary services
            {'name': 'mxtoolbox', 'func': self.check_mxtoolbox, 'weight': 10},
            {'name': 'hostinger', 'func': self.check_hostinger, 'weight': 10},
            {'name': 'name.com', 'func': self.check_namecom, 'weight': 9},
            {'name': 'gandi', 'func': self.check_gandi, 'weight': 9},
            {'name': 'namesilo', 'func': self.check_namesilo, 'weight': 8},
            {'name': 'dynadot', 'func': self.check_dynadot, 'weight': 8},
            {'name': 'hover', 'func': self.check_hover, 'weight': 7},
            {'name': 'domain.com', 'func': self.check_domaincom, 'weight': 7},
            {'name': 'networksolutions', 'func': self.check_networksolutions, 'weight': 7},
            {'name': 'bluehost', 'func': self.check_bluehost, 'weight': 6},
            {'name': 'register.com', 'func': self.check_registercom, 'weight': 6},
            {'name': 'enom', 'func': self.check_enom, 'weight': 5},
            {'name': 'dreamhost', 'func': self.check_dreamhost, 'weight': 5},
        ]
        
        # Track service health
        self.service_health = {s['name']: {'failures': 0, 'last_used': 0, 'successes': 0} for s in self.services}
        self.recovery_lock = threading.Lock()
        
        # Start service recovery thread
        self.recovery_thread = threading.Thread(target=self._service_recovery_loop, daemon=True)
        self.recovery_thread.start()
        logger.info(f"Service recovery thread started - monitoring {len(self.services)} services")
    
    def _service_recovery_loop(self):
        """Continuously test and recover failed services"""
        test_domains = ['google.com', 'facebook.com', 'amazon.com']  # Known taken domains
        
        while True:
            try:
                time.sleep(120)  # Check every 2 minutes
                
                with self.recovery_lock:
                    services_to_test = []
                    for service in self.services:
                        name = service['name']
                        health = self.service_health[name]
                        
                        # Test services with high failure rates
                        if health['failures'] > 5:
                            services_to_test.append((service, name))
                
                if services_to_test:
                    logger.info(f"Testing {len(services_to_test)} potentially failed services...")
                    
                    for service, name in services_to_test:
                        try:
                            # Test with a known domain
                            test_domain = random.choice(test_domains)
                            result = service['func'](test_domain)
                            
                            if result == False:  # Correctly identified as taken
                                with self.recovery_lock:
                                    old_failures = self.service_health[name]['failures']
                                    self.service_health[name]['failures'] = 0
                                    self.service_health[name]['successes'] += 1
                                logger.info(f"✓ Recovered service {name} (was {old_failures} failures)")
                            else:
                                # Still not working properly
                                with self.recovery_lock:
                                    self.service_health[name]['failures'] += 1
                        except Exception as e:
                            logger.debug(f"Recovery test failed for {name}: {e}")
                            with self.recovery_lock:
                                self.service_health[name]['failures'] += 1
                
                # Also decay failures over time for passive recovery
                with self.recovery_lock:
                    for name in self.service_health:
                        if self.service_health[name]['failures'] > 0:
                            self.service_health[name]['failures'] *= 0.9  # Gradual decay
                
                # Log current health status
                healthy_count = sum(1 for h in self.service_health.values() if h['failures'] < 5)
                logger.debug(f"Service health: {healthy_count}/{len(self.services)} healthy")
                
            except Exception as e:
                logger.error(f"Error in service recovery loop: {e}")
                time.sleep(60)
    
    def get_next_service(self):
        """Get next healthy service using weighted rotation"""
        current_time = time.time()
        
        with self.recovery_lock:
            available = []
            for service in self.services:
                name = service['name']
                health = self.service_health[name]
                
                # Skip heavily failed services
                if health['failures'] > 10:
                    continue
                
                # Rate limit per service
                if current_time - health['last_used'] < 2:
                    continue
                
                # Add based on weight (more weight = more likely to be selected)
                weight = max(1, service['weight'] - int(health['failures']))
                available.extend([service] * weight)
        
        if not available:
            logger.warning("All services exhausted, forcing cooldown...")
            time.sleep(10)
            # Force reset some services
            with self.recovery_lock:
                for name in self.service_health:
                    self.service_health[name]['failures'] = max(0, self.service_health[name]['failures'] - 5)
            return random.choice(self.services)
        
        selected = random.choice(available)
        with self.recovery_lock:
            self.service_health[selected['name']]['last_used'] = current_time
        
        return selected
    
    def query_once(self, domain):
        """Query a single service with optional proxy"""
        service = self.get_next_service()
        name = service['name']
        
        try:
            logger.debug(f"Checking {domain} with {name}")
            result = service['func'](domain)
            
            if result is not None:
                with self.recovery_lock:
                    self.service_health[name]['successes'] += 1
                    # Reduce failures on success
                    if self.service_health[name]['failures'] > 0:
                        self.service_health[name]['failures'] -= 0.5
                return result, name
            else:
                with self.recovery_lock:
                    self.service_health[name]['failures'] += 0.5
                    
        except Exception as e:
            logger.debug(f"Error with {name}: {e}")
            with self.recovery_lock:
                self.service_health[name]['failures'] += 1
                
        return None, name
    
    def _make_request(self, url, headers=None, timeout=5):
        """Make HTTP request with optional proxy"""
        if headers is None:
            headers = {'User-Agent': self._get_random_ua()}
        
        # Try with proxy first
        proxy = self.proxy_scraper.get_proxy()
        if proxy:
            try:
                proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
                response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
                if response.status_code == 200:
                    return response
            except:
                pass
        
        # Fallback to direct connection
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            return response
        except:
            return None
    
    # Service implementations
    
    def check_godaddy(self, domain):
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            headers = {'User-Agent': self._get_random_ua(), 'Accept': 'application/json'}
            response = self._make_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                if 'ExactMatchDomain' in data:
                    return data['ExactMatchDomain'].get('IsAvailable', False)
            return None
        except:
            return None
    
    def check_namecheap(self, domain):
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'domain taken' in text or 'unavailable' in text or 'already registered' in text:
                    return False
                if 'add to cart' in text and domain.lower() in text:
                    return True
            return None
        except:
            return None
    
    def check_porkbun(self, domain):
        try:
            url = f"https://porkbun.com/products/domains/{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text or 'register this domain' in text:
                    return True
                if 'unavailable' in text or 'already registered' in text or 'is taken' in text:
                    return False
            return None
        except:
            return None
    
    def check_whois_com(self, domain):
        try:
            url = f"https://www.whois.com/whois/{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available for registration' in text or 'no match for' in text:
                    return True
                if any(x in text for x in ['registrar:', 'creation date:', 'registry expiry', 'domain name:']):
                    return False
            return None
        except:
            return None
    
    def check_who_is(self, domain):
        try:
            url = f"https://who.is/whois/{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text
                if 'No Data Found' in text or 'NOT FOUND' in text or 'No match for' in text:
                    return True
                if any(x in text for x in ['Registrar:', 'Created:', 'Expires:', 'Creation Date:', 'Domain Name:']):
                    return False
            return None
        except:
            return None
    
    def check_mxtoolbox(self, domain):
        try:
            url = f"https://mxtoolbox.com/SuperTool.aspx?action=whois%3a{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text
                if 'No Data Found' in text or 'No Match' in text:
                    return True
                if 'Registrar:' in text or 'Creation Date:' in text:
                    return False
            return None
        except:
            return None
    
    def check_hostinger(self, domain):
        try:
            url = f"https://www.hostinger.com/domain-name-search?domain={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text and 'not available' not in text:
                    return True
                if 'taken' in text or 'unavailable' in text or 'not available' in text:
                    return False
            return None
        except:
            return None
    
    def check_namecom(self, domain):
        try:
            url = f"https://www.name.com/domain/search/{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text or ('add to cart' in text and domain.lower() in text):
                    return True
                if 'is taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_gandi(self, domain):
        try:
            url = f"https://www.gandi.net/domain/suggest?search={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'not available' not in text:
                    return True
                if 'taken' in text or 'registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_namesilo(self, domain):
        try:
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'unavailable' not in text:
                    return True
                if 'unavailable' in text or 'taken' in text:
                    return False
            return None
        except:
            return None
    
    def check_dynadot(self, domain):
        try:
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text and domain.lower() in text:
                    return True
                if 'taken' in text or 'registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_hover(self, domain):
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'not available' not in text:
                    return True
                if 'taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_domaincom(self, domain):
        try:
            url = f"https://www.domain.com/domains/search/results/?q={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'not available' not in text:
                    return True
                if 'taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_networksolutions(self, domain):
        try:
            url = f"https://www.networksolutions.com/domain-name-registration/index.jsp"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                # Try searching for the domain
                search_url = f"https://www.networksolutions.com/whois-search/{domain}"
                search_response = self._make_request(search_url)
                if search_response:
                    text = search_response.text.lower()
                    if 'available' in text:
                        return True
                    if 'registered' in text:
                        return False
            return None
        except:
            return None
    
    def check_bluehost(self, domain):
        try:
            url = f"https://www.bluehost.com/domains?search={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'not available' not in text:
                    return True
                if 'taken' in text:
                    return False
            return None
        except:
            return None
    
    def check_registercom(self, domain):
        try:
            url = f"https://www.register.com/domain/search/wizard.rcmx?searchDomainName={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text:
                    return True
                if 'not available' in text or 'is taken' in text:
                    return False
            return None
        except:
            return None
    
    def check_enom(self, domain):
        try:
            url = f"https://www.enom.com/domains/search-results?query={domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and domain.lower() in text:
                    return True
                if 'taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_dreamhost(self, domain):
        try:
            url = f"https://www.dreamhost.com/domains/"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                # Try domain search
                search_url = f"https://www.dreamhost.com/domains/search/?domain={domain}"
                search_response = self._make_request(search_url)
                if search_response:
                    text = search_response.text.lower()
                    if 'is available' in text:
                        return True
                    if 'is taken' in text or 'unavailable' in text:
                        return False
            return None
        except:
            return None
    
    def _get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(user_agents)
    
    def get_service_health(self):
        """Get current service health stats"""
        with self.recovery_lock:
            healthy = sum(1 for h in self.service_health.values() if h['failures'] < 5)
            return {
                'healthy': healthy,
                'total': len(self.services),
                'proxy_stats': self.proxy_scraper.get_stats()
            }


class DomainHunter:
    def __init__(self):
        self.state_file = 'hunter_state.json'
        self.results_file = 'found_domains.json'
        self.state = self.load_state()
        self.found_domains = self.load_results()
        self.running = True
        self.check_count = 0
        self.last_save = time.time()
        
        # Initialize proxy rotator (includes proxy scraper)
        logger.info("Initializing WHOIS proxy rotator with continuous proxy scraping...")
        self.proxy = WhoisProxyRotator()
        
        # Setup graceful shutdown
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
        # Start status monitor thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_loop(self):
        """Monitor and log system health"""
        while self.running:
            try:
                time.sleep(300)  # Every 5 minutes
                
                health = self.proxy.get_service_health()
                logger.info(f"System Health Report:")
                logger.info(f"  Services: {health['healthy']}/{health['total']} healthy")
                logger.info(f"  Working Proxies: {health['proxy_stats']['working']}")
                logger.info(f"  Total Tested Proxies: {health['proxy_stats']['total_tested']}")
                logger.info(f"  Domains Checked: {self.state.get('total_checked', 0)}")
                logger.info(f"  Domains Found: {len(self.found_domains)}")
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
    
    def shutdown(self, signum, frame):
        logger.info("Shutting down gracefully...")
        self.running = False
        self.save_state()
        self.save_results()
        sys.exit(0)
    
    def load_state(self):
        """Load previous state"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    logger.info(f"Resumed from: {state.get('current_length')} chars, TLD: {state.get('current_tld_index')}")
                    return state
            except:
                pass
        
        return {
            'current_length': 3,
            'current_tld_index': 0,
            'current_combo_index': 0,
            'total_checked': 0,
            'total_found': 0,
            'last_update': str(datetime.now())
        }
    
    def save_state(self):
        """Save current state"""
        self.state['last_update'] = str(datetime.now())
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def load_results(self):
        """Load found domains"""
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        # Create empty file
        with open(self.results_file, 'w') as f:
            json.dump([], f)
        return []
    
    def save_results(self):
        """Save found domains"""
        with open(self.results_file, 'w') as f:
            json.dump(self.found_domains, f, indent=2)
    
    def quick_dns_check(self, domain):
        """Fast DNS check"""
        try:
            socket.gethostbyname(domain)
            return False  # Resolves = taken
        except socket.gaierror:
            return True  # Doesn't resolve = potentially available
        except:
            return True
    
    def comprehensive_check(self, domain):
        """Determine availability with high certainty"""
        positive = []
        negative = []
        attempts = 0
        max_attempts = 15
        
        # We need definitive answer - keep checking until certain
        while attempts < max_attempts:
            result, service = self.proxy.query_once(domain)
            attempts += 1
            
            if result is None:
                # Service failed, try another
                time.sleep(0.5)
                continue
            
            if result:
                positive.append(service)
                logger.debug(f"{domain} - {service} says AVAILABLE (P:{len(positive)} N:{len(negative)})")
            else:
                negative.append(service)
                logger.debug(f"{domain} - {service} says TAKEN (P:{len(positive)} N:{len(negative)})")
            
            # Decision logic - be conservative
            
            # If ANY reputable service says taken, it's taken
            if negative:
                logger.debug(f"{domain} marked as TAKEN by: {negative}")
                return 'taken'
            
            # Need strong consensus for available (at least 3 positive, 0 negative)
            if len(positive) >= 3:
                # Do one more verification check
                verify_result, verify_service = self.proxy.query_once(domain)
                
                if verify_result == True:
                    logger.info(f"✓ {domain} CONFIRMED AVAILABLE by {len(positive) + 1} services")
                    return 'available'
                elif verify_result == False:
                    logger.info(f"✗ {domain} verification failed, marking as TAKEN")
                    return 'taken'
                # If verify_result is None, continue checking
            
            # Add delay between checks
            time.sleep(random.uniform(0.3, 0.7))
        
        # If we exhausted attempts without certainty, default to taken (conservative)
        logger.debug(f"{domain} - No consensus after {attempts} attempts, defaulting to TAKEN")
        return 'taken'
    
    def generate_combinations(self, length, chars=string.ascii_lowercase):
        """Generate domain combinations"""
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        """Main search loop"""
        logger.info("Starting domain hunt with proxy rotation and continuous scraping...")
        
        consecutive_finds = 0
        last_find_time = 0
        
        while self.running:
            current_length = self.state['current_length']
            
            if current_length > 6:
                logger.info("Reached maximum length. Restarting from 3...")
                self.state['current_length'] = 3
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                continue
            
            if self.state['current_tld_index'] >= len(PRIORITY_TLDS):
                self.state['current_length'] += 1
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                logger.info(f"Moving to {self.state['current_length']} character domains")
                continue
            
            current_tld = PRIORITY_TLDS[self.state['current_tld_index']]
            
            if current_length <= 3:
                chars = string.ascii_lowercase
            else:
                chars = string.ascii_lowercase + string.digits
            
            all_combos = list(self.generate_combinations(current_length, chars))
            
            logger.info(f"Checking {current_length}-char .{current_tld} domains ({len(all_combos)} total)")
            
            for i in range(self.state['current_combo_index'], len(all_combos)):
                if not self.running:
                    break
                
                combo = all_combos[i]
                domain = f"{combo}.{current_tld}"
                
                # Quick DNS check first
                if not self.quick_dns_check(domain):
                    self.check_count += 1
                    if self.check_count % 100 == 0:
                        health = self.proxy.get_service_health()
                        logger.info(f"Progress: {self.check_count} checked | {len(self.found_domains)} found | Services: {health['healthy']}/{health['total']} | Proxies: {health['proxy_stats']['working']}")
                    continue
                
                # Comprehensive check
                status = self.comprehensive_check(domain)
                
                self.state['total_checked'] += 1
                self.check_count += 1
                
                if status == 'available':
                    # Check for rapid consecutive finds (might indicate false positives)
                    current_time = time.time()
                    if current_time - last_find_time < 60:
                        consecutive_finds += 1
                        if consecutive_finds >= 2:
                            logger.warning(f"Rapid find #{consecutive_finds} - extra verification for {domain}")
                            time.sleep(10)
                            
                            # Re-verify with fresh services
                            status = self.comprehensive_check(domain)
                            if status != 'available':
                                logger.warning(f"{domain} failed re-verification, skipping")
                                continue
                    else:
                        consecutive_finds = 0
                    
                    last_find_time = current_time
                    
                    # Save the find
                    result = {
                        'domain': domain,
                        'length': current_length,
                        'found_at': str(datetime.now()),
                        'status': 'available'
                    }
                    self.found_domains.append(result)
                    self.state['total_found'] += 1
                    
                    logger.info(f"🎯 FOUND AVAILABLE: {domain} ({current_length} chars)")
                    self.save_results()
                    self.send_notification(domain)
                    
                    # Cooldown after find
                    time.sleep(5)
                
                # Update progress
                self.state['current_combo_index'] = i
                
                # Save state periodically
                if time.time() - self.last_save > 300:
                    self.save_state()
                    self.last_save = time.time()
                
                # Minimal delay between checks
                time.sleep(random.uniform(0.1, 0.3))
            
            # Move to next TLD
            self.state['current_tld_index'] += 1
            self.state['current_combo_index'] = 0
            self.save_state()
    
    def send_notification(self, domain):
        """Send notification when domain found"""
        webhook_url = os.environ.get('DISCORD_WEBHOOK')
        if webhook_url:
            try:
                requests.post(webhook_url, json={
                    'content': f'🎯 Found available domain: **{domain}**'
                }, timeout=5)
            except:
                pass
    
    def run(self):
        """Main run method"""
        logger.info("="*60)
        logger.info("DOMAIN HUNTER V3 - Auto Proxy & Recovery Edition")
        logger.info("="*60)
        logger.info(f"Starting from: {self.state['current_length']} chars, TLD #{self.state['current_tld_index']}")
        logger.info(f"Previously found: {len(self.found_domains)} domains")
        logger.info("Features:")
        logger.info("  • Continuous proxy scraping from 25+ sources")
        logger.info("  • Automatic service recovery")
        logger.info("  • No uncertain status - only available or taken")
        logger.info("  • 18+ WHOIS services in rotation")
        logger.info("="*60)
        
        try:
            self.search_domains()
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.save_state()
            self.save_results()
            raise
        finally:
            self.save_state()
            self.save_results()
            logger.info("Hunter stopped.")

if __name__ == "__main__":
    hunter = DomainHunter()
    hunter.run()

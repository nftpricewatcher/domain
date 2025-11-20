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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeoutError
import re
import gc
from collections import deque
from queue import Queue, Empty

warnings.filterwarnings('ignore')

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("ERROR: requests module required. Install with: pip install requests")
    sys.exit(1)

# Setup logging with /data path
log_level = os.environ.get('LOG_LEVEL', 'INFO')
os.makedirs('/data', exist_ok=True)
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/data/domain_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Priority TLDs
PRIORITY_TLDS = [
    'gg', 'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot'
]

class SmartProxyManager:
    """Simple proxy manager - get proxies when needed"""
    
    def __init__(self):
        self.working_proxies = deque(maxlen=50)
        self.proxy_queue = Queue()
        self.last_scrape = 0
        self.scrape_interval = 3600
        self.running = True
        self.currently_scraping = False
        
        self.tester_thread = threading.Thread(target=self._tester, daemon=True)
        self.tester_thread.start()
        
        logger.info("Proxy manager initialized")
    
    def get_proxy(self):
        """Get a proxy or None"""
        if self.working_proxies:
            proxy = self.working_proxies.popleft()
            self.working_proxies.append(proxy)
            return proxy
        return None
    
    def trigger_scrape(self):
        """Trigger scraping if needed"""
        current_time = time.time()
        if (current_time - self.last_scrape > self.scrape_interval and 
            not self.currently_scraping and len(self.working_proxies) < 15):
            self.currently_scraping = True
            threading.Thread(target=self._scrape_once, daemon=True).start()
    
    def _scrape_once(self):
        """Scrape proxies"""
        try:
            logger.info("Scraping proxies...")
            
            urls = [
                'https://www.proxy-list.download/api/v1/get?type=http&anon=elite',
                'https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&simplified=true',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
                'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
            ]
            
            proxies = set()
            for url in urls:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        found = re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
                        proxies.update(found[:200])
                        if len(proxies) > 300:
                            break
                except:
                    continue
            
            logger.info(f"Found {len(proxies)} proxies to test")
            
            for proxy in proxies:
                self.proxy_queue.put(proxy)
            
            self.last_scrape = time.time()
            
        finally:
            self.currently_scraping = False
    
    def _tester(self):
        """Test proxies from queue"""
        while self.running:
            try:
                if len(self.working_proxies) >= 30:
                    time.sleep(30)
                    continue
                
                try:
                    proxy = self.proxy_queue.get(timeout=1)
                except Empty:
                    if len(self.working_proxies) < 10:
                        self.trigger_scrape()
                    time.sleep(10)
                    continue
                
                if self._test_proxy(proxy):
                    if proxy not in self.working_proxies:
                        self.working_proxies.append(proxy)
                        logger.debug(f"Added proxy (total: {len(self.working_proxies)})")
                
            except Exception as e:
                logger.debug(f"Proxy tester error: {e}")
                time.sleep(5)
    
    def _test_proxy(self, proxy):
        """Test if proxy works"""
        try:
            proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5, verify=False)
            return response.status_code == 200
        except:
            return False
    
    def get_stats(self):
        return {
            'working': len(self.working_proxies),
            'queued': self.proxy_queue.qsize()
        }

class SimpleServiceRotator:
    """SIMPLE service rotation - main IP until rate limited, then proxy"""
    
    def __init__(self, proxy_manager):
        self.proxy_manager = proxy_manager
        self.services = self._init_services()
        self.service_status = {}
        self._init_status()
        
        # Recovery thread
        self.recovery_thread = threading.Thread(target=self._recovery_loop, daemon=True)
        self.recovery_thread.start()
        
        logger.info("Service rotator initialized")
    
    def _init_services(self):
        """Initialize service endpoints"""
        services = []
        
        # 5 copies of best services
        for i in range(5):
            services.extend([
                {'name': f'godaddy_{i}', 'func': self.check_godaddy},
                {'name': f'namecheap_{i}', 'func': self.check_namecheap},
                {'name': f'porkbun_{i}', 'func': self.check_porkbun},
            ])
        
        # 3 copies of WHOIS
        for i in range(3):
            services.extend([
                {'name': f'whois_com_{i}', 'func': self.check_whois_com},
                {'name': f'who_is_{i}', 'func': self.check_who_is},
            ])
        
        # Other services
        services.extend([
            {'name': 'mxtoolbox', 'func': self.check_mxtoolbox},
            {'name': 'hostinger', 'func': self.check_hostinger},
            {'name': 'name_com', 'func': self.check_namecom},
            {'name': 'gandi', 'func': self.check_gandi},
            {'name': 'namesilo', 'func': self.check_namesilo},
            {'name': 'dynadot', 'func': self.check_dynadot},
            {'name': 'hover', 'func': self.check_hover},
            {'name': 'domain_com', 'func': self.check_domaincom},
        ])
        
        return services
    
    def _init_status(self):
        """Initialize status - ALL START ON MAIN IP"""
        for service in self.services:
            self.service_status[service['name']] = {
                'use_proxy': False,  # Start on main IP
                'consecutive_failures': 0,
                'last_check': 0,
                'total_checks': 0,
                'last_fail_time': 0,
            }
    
    def check_domain(self, domain):
        """Check domain - simple and fast"""
        # Get healthy services
        available = [s for s in self.services 
                    if self.service_status[s['name']]['consecutive_failures'] < 10]
        
        if len(available) < 3:
            logger.warning("Not enough healthy services")
            time.sleep(1)
            return 'taken'
        
        # Check 8 services in parallel
        random.shuffle(available)
        to_check = available[:8]
        
        results = []
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            
            for service in to_check:
                future = executor.submit(self._check_service, domain, service)
                futures[future] = service
            
            try:
                for future in as_completed(futures, timeout=8):
                    try:
                        service = futures[future]
                        result = future.result(timeout=1)
                        
                        if result is not None:
                            results.append((result, service['name']))
                            
                            # TAKEN - stop immediately
                            if result == False:
                                logger.debug(f"{domain} TAKEN (by {service['name']})")
                                executor.shutdown(wait=False, cancel_futures=True)
                                return 'taken'
                            
                            # AVAILABLE - stop immediately
                            if result == True:
                                logger.info(f"✓ {domain} AVAILABLE (by {service['name']})")
                                executor.shutdown(wait=False, cancel_futures=True)
                                return 'available'
                    except:
                        pass
            except FutureTimeoutError:
                executor.shutdown(wait=False, cancel_futures=True)
        
        # Fallback logic
        if not results:
            return 'taken'
        
        # If ANY service found registration data = taken
        if any(r == False for r, _ in results):
            return 'taken'
        
        # Otherwise available
        return 'available'
    
    def _check_service(self, domain, service):
        """Check with a service - SIMPLE PROXY LOGIC"""
        status = self.service_status[service['name']]
        status['total_checks'] += 1
        status['last_check'] = time.time()
        
        # Decide proxy usage
        proxy = None
        if status['use_proxy']:
            proxy = self.proxy_manager.get_proxy()
            # If no proxy available and we need one, skip
            if not proxy:
                return None
        
        try:
            result = service['func'](domain, proxy=proxy)
            
            if result is not None:
                # SUCCESS
                status['consecutive_failures'] = 0
                return result
            else:
                # UNCLEAR - count as half failure
                status['consecutive_failures'] += 0.5
                
                # If 5 failures on main IP, switch to proxy
                if not status['use_proxy'] and status['consecutive_failures'] >= 5:
                    status['use_proxy'] = True
                    status['last_fail_time'] = time.time()
                    logger.info(f"{service['name']} switching to PROXY after failures")
                
                return None
                
        except Exception:
            # FAILED
            status['consecutive_failures'] += 1
            
            # If 5 failures on main IP, switch to proxy
            if not status['use_proxy'] and status['consecutive_failures'] >= 5:
                status['use_proxy'] = True
                status['last_fail_time'] = time.time()
                logger.info(f"{service['name']} switching to PROXY after failures")
            
            return None
    
    def _recovery_loop(self):
        """Test if rate-limited services can use main IP again"""
        test_domains = ['google.com', 'facebook.com', 'amazon.com']
        
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            try:
                current_time = time.time()
                recovered = []
                
                for service in self.services:
                    status = self.service_status[service['name']]
                    
                    # If using proxy and it's been 60 seconds, test main IP
                    if status['use_proxy'] and (current_time - status['last_fail_time']) > 60:
                        try:
                            test_domain = random.choice(test_domains)
                            result = service['func'](test_domain, proxy=None)
                            
                            if result == False:  # Correctly identified taken domain
                                status['use_proxy'] = False
                                status['consecutive_failures'] = 0
                                recovered.append(service['name'])
                                logger.info(f"{service['name']} recovered to MAIN IP")
                        except:
                            pass
                    
                    # Decay failures
                    if status['consecutive_failures'] > 0:
                        status['consecutive_failures'] = max(0, status['consecutive_failures'] - 0.2)
                
            except Exception as e:
                logger.error(f"Recovery error: {e}")
    
    def _make_request(self, url, proxy=None, timeout=6):
        """Make HTTP request"""
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ])
        }
        
        if proxy:
            proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
            return requests.get(url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
        else:
            return requests.get(url, headers=headers, timeout=timeout, verify=False)
    
    # Service implementations (unchanged)
    def check_godaddy(self, domain, proxy=None):
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            response = self._make_request(url, proxy, timeout=5)
            if response and response.status_code == 200:
                data = response.json()
                if 'ExactMatchDomain' in data:
                    return data['ExactMatchDomain'].get('IsAvailable', False)
            return None
        except:
            return None
    
    def check_namecheap(self, domain, proxy=None):
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'domain taken' in text or 'unavailable' in text or 'already registered' in text:
                    return False
                if 'add to cart' in text and domain.lower() in text:
                    return True
            return None
        except:
            return None
    
    def check_porkbun(self, domain, proxy=None):
        try:
            url = f"https://porkbun.com/products/domains/{domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text or 'register this domain' in text:
                    return True
                if 'unavailable' in text or 'already registered' in text or 'is taken' in text:
                    return False
            return None
        except:
            return None
    
    def check_whois_com(self, domain, proxy=None):
        try:
            url = f"https://www.whois.com/whois/{domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'available for registration' in text or 'no match for' in text:
                    return True
                if any(x in text for x in ['registrar:', 'creation date:', 'registry expiry', 'domain name:']):
                    return False
            return None
        except:
            return None
    
    def check_who_is(self, domain, proxy=None):
        try:
            url = f"https://who.is/whois/{domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text
                if 'No Data Found' in text or 'NOT FOUND' in text or 'No match for' in text:
                    return True
                if any(x in text for x in ['Registrar:', 'Created:', 'Expires:', 'Domain Name:']):
                    return False
            return None
        except:
            return None
    
    def check_mxtoolbox(self, domain, proxy=None):
        try:
            url = f"https://mxtoolbox.com/SuperTool.aspx?action=whois%3a{domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                if 'No Data Found' in response.text or 'No Match' in response.text:
                    return True
                if 'Registrar:' in response.text or 'Creation Date:' in response.text:
                    return False
            return None
        except:
            return None
    
    def check_hostinger(self, domain, proxy=None):
        try:
            url = f"https://www.hostinger.com/domain-name-search?domain={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text and 'not available' not in text:
                    return True
                if 'taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_namecom(self, domain, proxy=None):
        try:
            url = f"https://www.name.com/domain/search/{domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text and domain.lower() in text:
                    return True
                if 'is taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_gandi(self, domain, proxy=None):
        try:
            url = f"https://www.gandi.net/domain/suggest?search={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                if 'available' in response.text.lower() and 'not available' not in response.text.lower():
                    return True
                if 'taken' in response.text.lower() or 'registered' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_namesilo(self, domain, proxy=None):
        try:
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                if 'available' in response.text.lower() and 'unavailable' not in response.text.lower():
                    return True
                if 'unavailable' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_dynadot(self, domain, proxy=None):
        try:
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text and domain.lower() in text:
                    return True
                if 'taken' in text or 'registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_hover(self, domain, proxy=None):
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                if 'available' in response.text.lower() and 'not available' not in response.text.lower():
                    return True
                if 'taken' in response.text.lower() or 'unavailable' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_domaincom(self, domain, proxy=None):
        try:
            url = f"https://www.domain.com/domains/search/results/?q={domain}"
            response = self._make_request(url, proxy)
            if response and response.status_code == 200:
                if 'available' in response.text.lower() and 'not available' not in response.text.lower():
                    return True
                if 'taken' in response.text.lower() or 'unavailable' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def get_health(self):
        """Get health stats"""
        healthy = sum(1 for s in self.service_status.values() 
                     if s['consecutive_failures'] < 5)
        on_main_ip = sum(1 for s in self.service_status.values() 
                        if not s['use_proxy'])
        
        return {
            'healthy': healthy,
            'total': len(self.services),
            'main_ip': on_main_ip
        }

class DomainHunter:
    def __init__(self):
        self.state_file = '/data/hunter_state.json'
        self.results_file = '/data/found_domains.json'
        self.state = self.load_state()
        self.found_domains = self.load_results()
        self.running = True
        self.check_count = self.state.get('total_checked', 0)
        self.domains_per_second = 0
        self.last_stats_time = time.time()
        self.last_stats_count = self.check_count
        self.current_domain = "Starting..."
        
        self.proxy_manager = SmartProxyManager()
        self.service_rotator = SimpleServiceRotator(self.proxy_manager)
        
        threading.Timer(3, self.proxy_manager.trigger_scrape).start()
        
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Domain Hunter initialized - Resuming from #{self.check_count}")
    
    def _monitor_loop(self):
        """Monitor performance"""
        while self.running:
            time.sleep(60)
            
            try:
                current_count = self.check_count
                current_time = time.time()
                elapsed = current_time - self.last_stats_time
                
                if elapsed > 0:
                    self.domains_per_second = (current_count - self.last_stats_count) / elapsed
                    self.last_stats_count = current_count
                    self.last_stats_time = current_time
                
                proxy_stats = self.proxy_manager.get_stats()
                service_health = self.service_rotator.get_health()
                
                logger.info(f"=== Performance ===")
                logger.info(f"Speed: {self.domains_per_second:.2f}/sec ({self.domains_per_second * 60:.0f}/min)")
                logger.info(f"Checked: {self.check_count} | Found: {len(self.found_domains)}")
                logger.info(f"Current: {self.current_domain}")
                logger.info(f"Services: {service_health['healthy']}/{service_health['total']} healthy, "
                          f"{service_health['main_ip']}/{service_health['total']} on main IP")
                logger.info(f"Proxies: {proxy_stats['working']} working")
                
                if proxy_stats['working'] < 5:
                    self.proxy_manager.trigger_scrape()
                
                self.save_state()
                gc.collect()
                
            except Exception as e:
                logger.error(f"Monitor error: {e}")
    
    def shutdown(self, signum, frame):
        logger.info("Shutting down...")
        self.running = False
        self.save_state()
        self.save_results()
        sys.exit(0)
    
    def load_state(self):
        """Load state"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    logger.info(f"Loaded state: {state.get('current_length')} chars, "
                              f"TLD #{state.get('current_tld_index')}, "
                              f"combo #{state.get('current_combo_index')}")
                    return state
            except Exception as e:
                logger.error(f"Error loading state: {e}")
        
        return {
            'current_length': 3,
            'current_tld_index': 0,
            'current_combo_index': 0,
            'total_checked': 0,
            'total_found': 0,
            'last_update': str(datetime.now())
        }
    
    def save_state(self):
        """Save state"""
        try:
            self.state['last_update'] = str(datetime.now())
            self.state['total_checked'] = self.check_count
            self.state['total_found'] = len(self.found_domains)
            
            os.makedirs('/data', exist_ok=True)
            temp_file = self.state_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            os.replace(temp_file, self.state_file)
            
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def load_results(self):
        """Load results"""
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, 'r') as f:
                    results = json.load(f)
                    logger.info(f"Loaded {len(results)} found domains")
                    return results
            except:
                pass
        
        os.makedirs('/data', exist_ok=True)
        with open(self.results_file, 'w') as f:
            json.dump([], f)
        return []
    
    def save_results(self):
        """Save results"""
        try:
            os.makedirs('/data', exist_ok=True)
            temp_file = self.results_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(self.found_domains, f, indent=2)
            os.replace(temp_file, self.results_file)
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def quick_dns_check(self, domain):
        """Fast DNS check"""
        try:
            socket.gethostbyname(domain)
            return False
        except socket.gaierror:
            return True
        except:
            return True
    
    def generate_combinations(self, length, chars=string.ascii_lowercase):
        """Generate combinations"""
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        """Main search loop"""
        logger.info("Starting domain search...")
        
        while self.running:
            current_length = self.state['current_length']
            
            if current_length > 6:
                logger.info("Completed all lengths, restarting...")
                self.state['current_length'] = 3
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                continue
            
            if self.state['current_tld_index'] >= len(PRIORITY_TLDS):
                self.state['current_length'] += 1
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                logger.info(f"Moving to {self.state['current_length']} char domains")
                continue
            
            current_tld = PRIORITY_TLDS[self.state['current_tld_index']]
            
            if current_length <= 3:
                chars = string.ascii_lowercase
            else:
                chars = string.ascii_lowercase + string.digits
            
            all_combos = list(self.generate_combinations(current_length, chars))
            
            logger.info(f"Checking {current_length}-char .{current_tld} domains "
                       f"(from #{self.state['current_combo_index']} of {len(all_combos)})")
            
            for i in range(self.state['current_combo_index'], len(all_combos)):
                if not self.running:
                    break
                
                combo = all_combos[i]
                domain = f"{combo}.{current_tld}"
                self.current_domain = domain
                
                # DNS check
                if not self.quick_dns_check(domain):
                    self.check_count += 1
                    continue
                
                # WHOIS check
                status = self.service_rotator.check_domain(domain)
                self.check_count += 1
                
                if status == 'available':
                    result = {
                        'domain': domain,
                        'length': current_length,
                        'found_at': str(datetime.now()),
                        'status': 'available'
                    }
                    self.found_domains.append(result)
                    logger.info(f"🎯 FOUND: {domain}")
                    self.save_results()
                    time.sleep(2)  # Cool down after find
                
                self.state['current_combo_index'] = i
                
                # MINIMAL DELAY - just don't hammer
                time.sleep(0.1)
                
                # Save state every 100
                if self.check_count % 100 == 0:
                    self.save_state()
                    proxy_stats = self.proxy_manager.get_stats()
                    service_health = self.service_rotator.get_health()
                    logger.info(f"Progress: {self.check_count} | Found: {len(self.found_domains)} | "
                              f"Health: {service_health['healthy']}/{service_health['total']} | "
                              f"Main IP: {service_health['main_ip']}/{service_health['total']}")
            
            # Next TLD
            self.state['current_tld_index'] += 1
            self.state['current_combo_index'] = 0
            self.save_state()
    
    def run(self):
        logger.info("="*60)
        logger.info("DOMAIN HUNTER - SIMPLE & FAST")
        logger.info("="*60)
        logger.info(f"Resume: {self.state['current_length']} chars, "
                   f"TLD #{self.state['current_tld_index']}, "
                   f"combo #{self.state['current_combo_index']}")
        logger.info(f"Found: {len(self.found_domains)} | Checked: {self.check_count}")
        logger.info("Logic:")
        logger.info("  • All services start on main IP")
        logger.info("  • 5 failures → switch to proxy")
        logger.info("  • Every 30s test if main IP recovered")
        logger.info("  • 0.1s delay between domains")
        logger.info("  • No registration data = available")
        logger.info("="*60)
        
        try:
            self.search_domains()
        except Exception as e:
            logger.error(f"Error: {e}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            self.save_state()
            self.save_results()
            logger.info("Hunter stopped.")

if __name__ == "__main__":
    hunter = DomainHunter()
    hunter.run()

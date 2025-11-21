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

# Setup logging
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
    'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot'
]

class ProxyManager:
    """Simple proxy manager"""
    
    def __init__(self):
        self.proxies = deque(maxlen=100)
        self.proxy_queue = Queue()
        self.bad_proxies = set()
        self.last_scrape = 0
        self.running = True
        self.scraping = False
        
        threading.Thread(target=self._tester, daemon=True).start()
        
        logger.info("Proxy manager ready")
    
    def get_proxy(self):
        if self.proxies:
            p = self.proxies.popleft()
            self.proxies.append(p)
            return p
        return None
    
    def mark_bad(self, proxy):
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        self.bad_proxies.add(proxy)
    
    def trigger_scrape(self):
        if time.time() - self.last_scrape > 3600 and not self.scraping and len(self.proxies) < 30:
            self.scraping = True
            threading.Thread(target=self._scrape, daemon=True).start()
    
    def _scrape(self):
        try:
            logger.info("Scraping proxies...")
            urls = [
                'https://www.proxy-list.download/api/v1/get?type=http&anon=elite',
                'https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&simplified=true',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
            ]
            
            found = set()
            for url in urls:
                try:
                    r = requests.get(url, timeout=5)
                    if r.status_code == 200:
                        found.update(re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', r.text)[:200])
                        if len(found) > 300:
                            break
                except:
                    pass
            
            found -= self.bad_proxies
            logger.info(f"Found {len(found)} proxies")
            
            for p in found:
                self.proxy_queue.put(p)
            
            self.last_scrape = time.time()
        finally:
            self.scraping = False
    
    def _tester(self):
        while self.running:
            try:
                if len(self.proxies) >= 50:
                    time.sleep(30)
                    continue
                
                try:
                    proxy = self.proxy_queue.get(timeout=1)
                except Empty:
                    if len(self.proxies) < 20:
                        self.trigger_scrape()
                    time.sleep(10)
                    continue
                
                if proxy not in self.bad_proxies:
                    try:
                        r = requests.get('http://httpbin.org/ip', 
                                       proxies={'http': f'http://{proxy}', 'https': f'http://{proxy}'}, 
                                       timeout=5, verify=False)
                        if r.status_code == 200 and proxy not in self.proxies:
                            self.proxies.append(proxy)
                    except:
                        pass
            except:
                time.sleep(5)

class WHOISChecker:
    """Fast WHOIS checking - WHOIS services + registrars that show registration data"""
    
    def __init__(self, proxy_manager):
        self.proxy_manager = proxy_manager
        
        # ALL sources that can show registration data
        self.services = [
            # Pure WHOIS services
            {'name': 'whois_com', 'check': self.check_whois_com},
            {'name': 'who_is', 'check': self.check_who_is},
            {'name': 'domaintools', 'check': self.check_domaintools},
            {'name': 'whoisxmlapi', 'check': self.check_whoisxmlapi},
            {'name': 'whois_icann', 'check': self.check_whois_icann},
            {'name': 'networksolutions', 'check': self.check_networksolutions},
            {'name': 'whoxy', 'check': self.check_whoxy},
            
            # Registrars that show registration data
            {'name': 'godaddy', 'check': self.check_godaddy},
            {'name': 'namecheap', 'check': self.check_namecheap},
            {'name': 'hostinger', 'check': self.check_hostinger},
            {'name': 'hover', 'check': self.check_hover},
            {'name': 'namesilo', 'check': self.check_namesilo},
            {'name': 'dynadot', 'check': self.check_dynadot},
        ]
        
        logger.info(f"WHOIS checker ready with {len(self.services)} sources")
    
    def check_domain(self, domain):
        """Check domain - errors don't mean available, need clear confirmation"""
        results = []
        
        with ThreadPoolExecutor(max_workers=len(self.services)) as executor:
            futures = {executor.submit(self._check_with_retry, domain, s): s 
                      for s in self.services}
            
            try:
                for future in as_completed(futures, timeout=10):
                    try:
                        result = future.result(timeout=2)
                        if result is not None:
                            results.append(result)
                            
                            # If TAKEN (has registration) - stop immediately
                            if result == False:
                                executor.shutdown(wait=False, cancel_futures=True)
                                return 'taken'
                            
                            # If AVAILABLE (no registration) - stop immediately
                            if result == True:
                                executor.shutdown(wait=False, cancel_futures=True)
                                return 'available'
                    except:
                        pass
            except TimeoutError:
                # Some futures didn't finish - that's OK, evaluate what we have
                executor.shutdown(wait=False, cancel_futures=True)
        
        # Evaluate results
        # If any service found registration = taken
        if any(r == False for r in results):
            return 'taken'
        
        # If any service confirmed no registration = available
        if any(r == True for r in results):
            return 'available'
        
        # All errors/timeouts = can't determine, assume taken
        return 'taken'
    
    def _check_with_retry(self, domain, service):
        """Check with automatic retry on errors"""
        # Try with 50% proxy usage
        use_proxy = random.random() < 0.5
        
        # First attempt
        result = self._check(domain, service, use_proxy)
        if result is not None:
            return result
        
        # Retry with opposite IP strategy
        result = self._check(domain, service, not use_proxy)
        if result is not None:
            return result
        
        # Both failed
        return None
    
    def _check(self, domain, service, use_proxy):
        """Single check attempt"""
        proxy = None
        if use_proxy:
            proxy = self.proxy_manager.get_proxy()
            if not proxy:
                return None
        
        try:
            result = service['check'](domain, proxy)
            
            # If proxy failed multiple times, mark it bad
            if proxy and result is None:
                self.proxy_manager.mark_bad(proxy)
            
            return result
        except:
            if proxy:
                self.proxy_manager.mark_bad(proxy)
            return None
    
    def check_price(self, domain):
        """Check domain price at registrars - return None if can't determine"""
        # Try top 5 registrars for price info
        price_checkers = [
            self.get_godaddy_price,
            self.get_namecheap_price,
            self.get_dynadot_price,
            self.get_namesilo_price,
            self.get_hover_price,
        ]
        
        # Try each price checker with quick timeout
        for checker in price_checkers:
            try:
                price = checker(domain)
                if price is not None:
                    return price
            except:
                continue
        
        # Couldn't get price from any registrar
        return None
    
    def get_godaddy_price(self, domain):
        """Get price from GoDaddy API"""
        try:
            proxy = self.proxy_manager.get_proxy() if random.random() < 0.5 else None
            
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            data = r.json()
            if 'ExactMatchDomain' in data:
                exact = data['ExactMatchDomain']
                # Check if it's a premium domain
                if exact.get('IsPremium', False):
                    if 'Price' in exact:
                        return int(exact['Price'])
                    return 999  # Premium but no price shown
                
                # Regular domain - get standard price
                if 'Price' in exact:
                    return int(exact['Price'])
            
            return None
        except:
            return None
    
    def get_namecheap_price(self, domain):
        """Get price from Namecheap"""
        try:
            proxy = self.proxy_manager.get_proxy() if random.random() < 0.5 else None
            
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Look for price patterns
            price_matches = re.findall(r'\$([0-9,]+\.?\d{0,2})', text)
            if price_matches:
                for match in price_matches:
                    price_str = match.replace(',', '')
                    try:
                        price = float(price_str)
                        if price > 5:  # Reasonable domain price threshold
                            return int(price)
                    except:
                        continue
            
            return None
        except:
            return None
    
    def get_dynadot_price(self, domain):
        """Get price from Dynadot"""
        try:
            proxy = self.proxy_manager.get_proxy() if random.random() < 0.5 else None
            
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Look for price
            price_matches = re.findall(r'\$([0-9,]+\.?\d{0,2})', text)
            if price_matches:
                for match in price_matches:
                    price_str = match.replace(',', '')
                    try:
                        price = float(price_str)
                        if 5 < price < 50000:  # Reasonable range
                            return int(price)
                    except:
                        continue
            
            return None
        except:
            return None
    
    def get_namesilo_price(self, domain):
        """Get price from NameSilo"""
        try:
            proxy = self.proxy_manager.get_proxy() if random.random() < 0.5 else None
            
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Look for price
            price_matches = re.findall(r'\$([0-9,]+\.?\d{0,2})', text)
            if price_matches:
                for match in price_matches:
                    price_str = match.replace(',', '')
                    try:
                        price = float(price_str)
                        if 5 < price < 50000:
                            return int(price)
                    except:
                        continue
            
            return None
        except:
            return None
    
    def get_hover_price(self, domain):
        """Get price from Hover"""
        try:
            proxy = self.proxy_manager.get_proxy() if random.random() < 0.5 else None
            
            url = f"https://www.hover.com/domains/results?q={domain}"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Look for price
            price_matches = re.findall(r'\$([0-9,]+\.?\d{0,2})', text)
            if price_matches:
                for match in price_matches:
                    price_str = match.replace(',', '')
                    try:
                        price = float(price_str)
                        if 5 < price < 50000:
                            return int(price)
                    except:
                        continue
            
            return None
        except:
            return None
    
    def _request(self, url, proxy=None, timeout=6):
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
    
    # WHOIS service implementations
    def check_whois_com(self, domain, proxy=None):
        """whois.com - reliable WHOIS lookup"""
        try:
            url = f"https://www.whois.com/whois/{domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            # Clear indicators of availability
            if 'no match' in text or 'not found' in text or 'available for registration' in text:
                return True
            
            # Clear indicators of registration
            if any(x in text for x in ['registrar:', 'creation date:', 'registry expiry', 'updated date:']):
                return False
            
            return None
        except:
            return None
    
    def check_who_is(self, domain, proxy=None):
        """who.is - another reliable WHOIS"""
        try:
            url = f"https://who.is/whois/{domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Available indicators
            if 'No Data Found' in text or 'NOT FOUND' in text or 'No match for' in text:
                return True
            
            # Taken indicators
            if any(x in text for x in ['Registrar:', 'Created:', 'Expires:', 'Updated:']):
                return False
            
            return None
        except:
            return None
    
    def check_domaintools(self, domain, proxy=None):
        """domaintools.com WHOIS"""
        try:
            url = f"https://whois.domaintools.com/{domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'not found' in text or 'no match' in text or 'available' in text:
                return True
            
            if any(x in text for x in ['registrar:', 'created:', 'expires:', 'updated:']):
                return False
            
            return None
        except:
            return None
    
    def check_whoisxmlapi(self, domain, proxy=None):
        """whoisxmlapi.com"""
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json"
            r = self._request(url, proxy, timeout=8)
            if not r or r.status_code != 200:
                return None
            
            try:
                data = r.json()
                if 'WhoisRecord' in data:
                    record = data['WhoisRecord']
                    # If has registrar info = taken
                    if 'registrarName' in record or 'createdDate' in record:
                        return False
                    # If explicitly says not found = available
                    if 'dataError' in record or record.get('registrarName') == 'No Data':
                        return True
            except:
                pass
            
            return None
        except:
            return None
    
    def check_whois_icann(self, domain, proxy=None):
        """ICANN WHOIS lookup"""
        try:
            url = f"https://lookup.icann.org/en/lookup?name={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'not found' in text or 'no match' in text:
                return True
            
            if any(x in text for x in ['registrar', 'registered', 'creation date']):
                return False
            
            return None
        except:
            return None
    
    def check_networksolutions(self, domain, proxy=None):
        """Network Solutions WHOIS"""
        try:
            url = f"https://www.networksolutions.com/whois/results.jsp?domain={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'no match' in text or 'not found' in text or 'available' in text:
                return True
            
            if any(x in text for x in ['registrar:', 'created:', 'expires:']):
                return False
            
            return None
        except:
            return None
    
    def check_whoxy(self, domain, proxy=None):
        """Whoxy.com WHOIS API"""
        try:
            url = f"https://www.whoxy.com/{domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'not found' in text or 'no match' in text or 'available' in text:
                return True
            
            if any(x in text for x in ['registrar', 'created', 'expires']):
                return False
            
            return None
        except:
            return None
    
    def check_godaddy(self, domain, proxy=None):
        """GoDaddy - shows registration status"""
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            try:
                data = r.json()
                if 'ExactMatchDomain' in data:
                    is_available = data['ExactMatchDomain'].get('IsAvailable', False)
                    return is_available  # True = available, False = taken
            except:
                pass
            
            return None
        except:
            return None
    
    def check_namecheap(self, domain, proxy=None):
        """Namecheap - shows if domain is taken"""
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            # Clear taken indicators
            if 'domain taken' in text or 'unavailable' in text or 'already registered' in text:
                return False
            
            # Clear available indicators
            if 'add to cart' in text and domain.lower() in text:
                return True
            
            return None
        except:
            return None
    
    def check_hostinger(self, domain, proxy=None):
        """Hostinger - shows availability"""
        try:
            url = f"https://www.hostinger.com/domain-name-search?domain={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'is available' in text and 'not available' not in text:
                return True
            
            if 'taken' in text or 'unavailable' in text or 'registered' in text:
                return False
            
            return None
        except:
            return None
    
    def check_hover(self, domain, proxy=None):
        """Hover - shows registration status"""
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'available' in text and 'not available' not in text:
                return True
            
            if 'taken' in text or 'unavailable' in text or 'registered' in text:
                return False
            
            return None
        except:
            return None
    
    def check_namesilo(self, domain, proxy=None):
        """NameSilo - shows availability"""
        try:
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'available' in text and 'unavailable' not in text:
                return True
            
            if 'unavailable' in text or 'registered' in text:
                return False
            
            return None
        except:
            return None
    
    def check_dynadot(self, domain, proxy=None):
        """Dynadot - shows registration status"""
        try:
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text.lower()
            
            if 'add to cart' in text and domain.lower() in text:
                return True
            
            if 'taken' in text or 'registered' in text or 'unavailable' in text:
                return False
            
            return None
        except:
            return None

class PriceChecker:
    """Check domain prices - filter out premium domains"""
    
    def __init__(self, proxy_manager):
        self.proxy_manager = proxy_manager
        self.max_price = 100  # Anything over $100 = premium
        
        logger.info("Price checker ready")
    
    def check_price(self, domain):
        """Check if domain is affordable - returns True if price <= $100, False if premium"""
        # Try multiple registrars in parallel
        registrars = [
            {'name': 'godaddy', 'check': self.check_godaddy_price},
            {'name': 'namecheap', 'check': self.check_namecheap_price},
            {'name': 'hover', 'check': self.check_hover_price},
        ]
        
        prices = []
        
        with ThreadPoolExecutor(max_workers=len(registrars)) as executor:
            futures = {executor.submit(self._check_with_retry, domain, r): r 
                      for r in registrars}
            
            try:
                for future in as_completed(futures, timeout=8):
                    try:
                        price = future.result(timeout=2)
                        if price is not None:
                            prices.append(price)
                            
                            # If ANY registrar says premium (>$100) - it's premium
                            if price > self.max_price:
                                logger.debug(f"{domain} is PREMIUM (${price})")
                                executor.shutdown(wait=False, cancel_futures=True)
                                return False
                    except:
                        pass
            except TimeoutError:
                executor.shutdown(wait=False, cancel_futures=True)
        
        # Evaluate prices
        if not prices:
            # No price found - assume standard pricing (safe default)
            return True
        
        # If we got prices and all are under $100
        avg_price = sum(prices) / len(prices)
        if avg_price <= self.max_price:
            logger.debug(f"{domain} is affordable (~${avg_price:.2f})")
            return True
        
        logger.debug(f"{domain} is PREMIUM (~${avg_price:.2f})")
        return False
    
    def _check_with_retry(self, domain, registrar):
        """Check price with retry"""
        use_proxy = random.random() < 0.5
        
        # First attempt
        price = self._check(domain, registrar, use_proxy)
        if price is not None:
            return price
        
        # Retry with opposite strategy
        price = self._check(domain, registrar, not use_proxy)
        if price is not None:
            return price
        
        return None
    
    def _check(self, domain, registrar, use_proxy):
        """Single price check"""
        proxy = None
        if use_proxy:
            proxy = self.proxy_manager.get_proxy()
            if not proxy:
                return None
        
        try:
            return registrar['check'](domain, proxy)
        except:
            return None
    
    def _request(self, url, proxy=None, timeout=6):
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
    
    def _extract_price(self, text):
        """Extract price from text - finds $XX.XX or XX.XX"""
        # Look for price patterns
        patterns = [
            r'\$(\d+(?:\.\d{2})?)',  # $123.45
            r'(\d+(?:\.\d{2})?)(?:\s*(?:USD|usd|\$))',  # 123.45 USD
            r'price[:\s]+\$?(\d+(?:\.\d{2})?)',  # price: $123.45
            r'(\d+(?:\.\d{2})?)\s*per\s*year',  # 123.45 per year
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except:
                    pass
        
        return None
    
    def check_godaddy_price(self, domain, proxy=None):
        """GoDaddy price check"""
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            r = self._request(url, proxy, timeout=5)
            if not r or r.status_code != 200:
                return None
            
            try:
                data = r.json()
                if 'ExactMatchDomain' in data:
                    # Check for premium flag
                    if data['ExactMatchDomain'].get('IsPremium', False):
                        return 9999  # Premium indicator
                    
                    # Try to get price
                    price_info = data['ExactMatchDomain'].get('Price', {})
                    if isinstance(price_info, dict):
                        list_price = price_info.get('ListPrice', 0)
                        if list_price:
                            return float(list_price)
                    
                    # If no premium flag and no high price, assume standard
                    return 10  # Standard domain price
            except:
                pass
            
            return None
        except:
            return None
    
    def check_namecheap_price(self, domain, proxy=None):
        """Namecheap price check"""
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Check for premium indicator
            if 'premium' in text.lower() or 'make offer' in text.lower():
                return 9999
            
            # Try to extract price
            price = self._extract_price(text)
            if price:
                return price
            
            return None
        except:
            return None
    
    def check_hover_price(self, domain, proxy=None):
        """Hover price check"""
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            r = self._request(url, proxy)
            if not r or r.status_code != 200:
                return None
            
            text = r.text
            
            # Check for premium
            if 'premium' in text.lower():
                return 9999
            
            # Extract price
            price = self._extract_price(text)
            if price:
                return price
            
            return None
        except:
            return None

class DomainHunter:
    def __init__(self):
        self.state_file = '/data/hunter_state.json'
        self.results_file = '/data/found_domains.json'
        self.state = self.load_state()
        self.found_domains = self.load_results()
        self.running = True
        self.check_count = self.state.get('total_checked', 0)
        self.current_domain = "Starting..."
        
        self.proxy_manager = ProxyManager()
        self.whois_checker = WHOISChecker(self.proxy_manager)
        self.price_checker = PriceChecker(self.proxy_manager)
        
        threading.Timer(3, self.proxy_manager.trigger_scrape).start()
        
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
        self.monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Domain Hunter initialized - Resume from #{self.check_count}")
    
    def _monitor(self):
        last_count = self.check_count
        last_time = time.time()
        
        while self.running:
            time.sleep(60)
            
            try:
                current = self.check_count
                now = time.time()
                elapsed = now - last_time
                
                if elapsed > 0:
                    speed = (current - last_count) / elapsed
                    logger.info(f"=== Performance ===")
                    logger.info(f"Speed: {speed:.2f}/sec ({speed * 60:.0f}/min)")
                    logger.info(f"Checked: {self.check_count} | Found: {len(self.found_domains)}")
                    logger.info(f"Current: {self.current_domain}")
                    logger.info(f"Proxies: {len(self.proxy_manager.proxies)} working")
                    
                    last_count = current
                    last_time = now
                
                if len(self.proxy_manager.proxies) < 20:
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
        try:
            self.state['last_update'] = str(datetime.now())
            self.state['total_checked'] = self.check_count
            self.state['total_found'] = len(self.found_domains)
            
            os.makedirs('/data', exist_ok=True)
            temp = self.state_file + '.tmp'
            with open(temp, 'w') as f:
                json.dump(self.state, f, indent=2)
            os.replace(temp, self.state_file)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def load_results(self):
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
        try:
            os.makedirs('/data', exist_ok=True)
            temp = self.results_file + '.tmp'
            with open(temp, 'w') as f:
                json.dump(self.found_domains, f, indent=2)
            os.replace(temp, self.results_file)
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def dns_check(self, domain):
        """Fast DNS check"""
        try:
            socket.gethostbyname(domain)
            return False
        except:
            return True
    
    def generate_combos(self, length, chars=string.ascii_lowercase):
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        logger.info("Starting domain search...")
        
        while self.running:
            length = self.state['current_length']
            
            if length > 6:
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
            
            tld = PRIORITY_TLDS[self.state['current_tld_index']]
            chars = string.ascii_lowercase if length <= 3 else string.ascii_lowercase + string.digits
            all_combos = list(self.generate_combos(length, chars))
            
            logger.info(f"Checking {length}-char .{tld} domains "
                       f"(from #{self.state['current_combo_index']} of {len(all_combos)})")
            
            for i in range(self.state['current_combo_index'], len(all_combos)):
                if not self.running:
                    break
                
                combo = all_combos[i]
                domain = f"{combo}.{tld}"
                self.current_domain = domain
                
                # DNS check first
                if not self.dns_check(domain):
                    self.check_count += 1
                    continue
                
                # WHOIS check
                status = self.whois_checker.check_domain(domain)
                self.check_count += 1
                
                if status == 'available':
                    # Check price - filter out premium domains
                    logger.debug(f"{domain} is available - checking price...")
                    is_affordable = self.price_checker.check_price(domain)
                    
                    if not is_affordable:
                        logger.info(f"⚠️  SKIP: {domain} (premium pricing)")
                        continue
                    
                    result = {
                        'domain': domain,
                        'length': length,
                        'found_at': str(datetime.now()),
                        'status': 'available'
                    }
                    self.found_domains.append(result)
                    logger.info(f"🎯 FOUND: {domain} (affordable)")
                    self.save_results()
                    time.sleep(1)
                
                self.state['current_combo_index'] = i
                
                # Save every 100
                if self.check_count % 100 == 0:
                    self.save_state()
                    logger.info(f"Progress: {self.check_count} checked | {len(self.found_domains)} found | "
                              f"Proxies: {len(self.proxy_manager.proxies)}")
            
            # Next TLD
            self.state['current_tld_index'] += 1
            self.state['current_combo_index'] = 0
            self.save_state()
    
    def run(self):
        logger.info("="*60)
        logger.info("DOMAIN HUNTER - FAST & ACCURATE")
        logger.info("="*60)
        logger.info(f"Resume: {self.state['current_length']} chars, "
                   f"TLD #{self.state['current_tld_index']}, "
                   f"combo #{self.state['current_combo_index']}")
        logger.info(f"Found: {len(self.found_domains)} | Checked: {self.check_count}")
        logger.info("Logic:")
        logger.info("  • Fast DNS pre-check")
        logger.info(f"  • {len(self.whois_checker.services)} sources (WHOIS + registrars)")
        logger.info("  • No registration data = available")
        logger.info("  • ANY registration data = taken")
        logger.info("  • Price check: Skip if > $100 (premium)")
        logger.info("  • Errors = retry with different IP/proxy")
        logger.info("  • 50% proxy usage for speed")
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

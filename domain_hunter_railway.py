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
from concurrent.futures import ThreadPoolExecutor
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

class WhoisProxyRotator:
    """Rotates through multiple WHOIS proxy services to avoid rate limits"""
    
    def __init__(self):
        self.services = [
            # Primary services
            {'name': 'whois.com', 'func': self.check_whois_com, 'weight': 10},
            {'name': 'who.is', 'func': self.check_who_is, 'weight': 10},
            {'name': 'godaddy', 'func': self.check_godaddy, 'weight': 10},
            {'name': 'namecheap', 'func': self.check_namecheap, 'weight': 10},
            {'name': 'porkbun', 'func': self.check_porkbun, 'weight': 10},
            
            # Additional WHOIS services
            {'name': 'whoisxml', 'func': self.check_whoisxmlapi, 'weight': 8},
            {'name': 'domaintools', 'func': self.check_domaintools, 'weight': 7},
            {'name': 'mxtoolbox', 'func': self.check_mxtoolbox, 'weight': 8},
            {'name': 'whatsmydns', 'func': self.check_whatsmydns, 'weight': 6},
            {'name': 'hostinger', 'func': self.check_hostinger, 'weight': 9},
            {'name': 'name.com', 'func': self.check_namecom, 'weight': 8},
            {'name': 'hover', 'func': self.check_hover, 'weight': 7},
            {'name': 'gandi', 'func': self.check_gandi, 'weight': 9},
            {'name': 'namesilo', 'func': self.check_namesilo, 'weight': 8},
            {'name': 'dynadot', 'func': self.check_dynadot, 'weight': 8},
            {'name': 'enom', 'func': self.check_enom, 'weight': 5},
            {'name': 'domain.com', 'func': self.check_domaincom, 'weight': 7},
            {'name': 'register.com', 'func': self.check_registercom, 'weight': 5},
            {'name': 'bluehost', 'func': self.check_bluehost, 'weight': 6},
            {'name': 'dreamhost', 'func': self.check_dreamhost, 'weight': 5},
        ]
        
        # Track service health
        self.service_health = {s['name']: {'failures': 0, 'last_used': 0} for s in self.services}
        
    def get_next_service(self):
        """Get next healthy service using weighted rotation"""
        current_time = time.time()
        
        # Build list of available services
        available = []
        for service in self.services:
            name = service['name']
            health = self.service_health[name]
            
            # Skip if too many failures
            if health['failures'] > 7:
                continue
                
            # Skip if used too recently (within 1.5 seconds)
            if current_time - health['last_used'] < 1.5:
                continue
                
            # Add based on weight
            available.extend([service] * service['weight'])
        
        if not available:
            # All services exhausted, reset and wait
            logger.warning("All services rate limited or failed, resetting...")
            for name in self.service_health:
                self.service_health[name]['failures'] = max(0, self.service_health[name]['failures'] - 3)
            time.sleep(8)
            # Force pick any service after reset
            return random.choice(self.services)
        
        # Pick random service from weighted list
        return random.choice(available)
    
    def query_once(self, domain):
        """Query a single service"""
        service = self.get_next_service()
        name = service['name']
        try:
            logger.debug(f"Checking {domain} with {name}")
            result = service['func'](domain)
            if result is not None:
                self.service_health[name]['failures'] = 0
                return result, name
            else:
                self.service_health[name]['failures'] += 1
        except Exception as e:
            logger.debug(f"Error with {name}: {e}")
            self.service_health[name]['failures'] += 1
        return None, name
    
    # Service implementation methods - all kept, with improvements to key ones
    
    def check_whois_com(self, domain):
        """Check whois.com"""
        try:
            url = f"https://www.whois.com/whois/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                
                if 'available for registration' in text or 'no match for' in text:
                    return True
                if any(x in text for x in ['registrar:', 'creation date:', 'registry expiry']):
                    return False
            return None
        except:
            return None
    
    def check_who_is(self, domain):
        """Check who.is"""
        try:
            url = f"https://who.is/whois/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text
                if 'No Data Found' in text or 'NOT FOUND' in text or 'No match for' in text:
                    return True
                if any(x in text for x in ['Registrar:', 'Created:', 'Expires:', 'Creation Date:']):
                    return False
            return None
        except:
            return None
    
    def check_godaddy(self, domain):
        """Check GoDaddy"""
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            headers = {'User-Agent': self._get_random_ua(), 'Accept': 'application/json'}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                if 'ExactMatchDomain' in data:
                    return data['ExactMatchDomain'].get('IsAvailable', False)
            return None
        except:
            return None
    
    def check_namecheap(self, domain):
        """Check Namecheap"""
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'domain taken' in text or 'unavailable' in text:
                    return False
                if 'add to cart' in text and domain.lower() in text:
                    return True
            return None
        except:
            return None
    
    def check_porkbun(self, domain):
        """Check Porkbun"""
        try:
            url = f"https://porkbun.com/products/domains/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text or 'register this domain' in text:
                    return True
                if 'unavailable' in text or 'already registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_mxtoolbox(self, domain):
        """Check MXToolbox"""
        try:
            url = f"https://mxtoolbox.com/SuperTool.aspx?action=whois%3a{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text
                if 'No Data Found' in text or 'No Match' in text:
                    return True
                if 'Registrar:' in text or 'Creation Date:' in text:
                    return False
            return None
        except:
            return None
    
    def check_whoisxmlapi(self, domain):
        """Check via whoisxmlapi (free tier)"""
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}"
            response = requests.get(url, timeout=10, verify=False)
            if 'No Data Found' in response.text or 'NOT FOUND' in response.text:
                return True
            if 'registrar' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_domaintools(self, domain):
        """Check via DomainTools"""
        try:
            url = f"https://whois.domaintools.com/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text
                if 'No results found' in text or 'is available' in text:
                    return True
                if 'Registrar:' in text:
                    return False
            return None
        except:
            return None
    
    def check_whatsmydns(self, domain):
        """Check via whatsmydns.net"""
        try:
            url = f"https://www.whatsmydns.net/api/domain/{domain}"
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 404:
                return True
            if response.status_code == 200:
                return False
            return None
        except:
            return None
    
    def check_hostinger(self, domain):
        """Check Hostinger"""
        try:
            url = f"https://www.hostinger.com/domain-name-search?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text and 'taken' not in text:
                    return True
                if 'taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_namecom(self, domain):
        """Check Name.com"""
        try:
            url = f"https://www.name.com/domain/search/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'is available' in text or 'add to cart' in text:
                    return True
                if 'is taken' in text or 'unavailable' in text:
                    return False
            return None
        except:
            return None
    
    def check_hover(self, domain):
        """Check Hover"""
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'available' in response.text.lower() and 'taken' not in response.text.lower():
                    return True
                if 'taken' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_gandi(self, domain):
        """Check Gandi"""
        try:
            url = f"https://www.gandi.net/domain/suggest?search={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'available' in text and 'registered' not in text:
                    return True
                if 'taken' in text or 'registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_namesilo(self, domain):
        """Check NameSilo"""
        try:
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'available' in response.text.lower():
                    return True
                if 'unavailable' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_dynadot(self, domain):
        """Check Dynadot"""
        try:
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                if 'add to cart' in text:
                    return True
                if 'taken' in text or 'registered' in text:
                    return False
            return None
        except:
            return None
    
    def check_enom(self, domain):
        """Check eNom"""
        try:
            url = f"https://www.enom.com/domains/search-results?query={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'available' in response.text.lower():
                    return True
                if 'taken' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_domaincom(self, domain):
        """Check Domain.com"""
        try:
            url = f"https://www.domain.com/domains/search/results/?q={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'available' in response.text.lower():
                    return True
                if 'taken' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_registercom(self, domain):
        """Check Register.com"""
        try:
            url = f"https://www.register.com/domain/search/wizard.rcmx?searchDomainName={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'is available' in response.text.lower():
                    return True
                if 'not available' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_bluehost(self, domain):
        """Check Bluehost"""
        try:
            url = f"https://www.bluehost.com/domains?search={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'available' in response.text.lower():
                    return True
                if 'taken' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def check_dreamhost(self, domain):
        """Check DreamHost"""
        try:
            url = f"https://www.dreamhost.com/domains/search/?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                if 'is available' in response.text.lower():
                    return True
                if 'is taken' in response.text.lower():
                    return False
            return None
        except:
            return None
    
    def _get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(user_agents)


class DomainHunter:
    def __init__(self):
        self.state_file = 'hunter_state.json'
        self.results_file = 'found_domains.json'
        self.uncertain_file = 'uncertain_domains.json'  # Kept for legacy, but won't be used
        self.state = self.load_state()
        self.found_domains = self.load_results()
        self.uncertain_domains = self.load_uncertain()  # Kept for legacy
        self.running = True
        self.check_count = 0
        self.last_save = time.time()
        
        # Initialize proxy rotator
        self.proxy = WhoisProxyRotator()
        
        # Setup graceful shutdown
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
    def shutdown(self, signum, frame):
        logger.info("Shutting down gracefully...")
        self.running = False
        self.save_state()
        self.save_results()
        self.save_uncertain()  # Kept for legacy
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
        return []
    
    def load_uncertain(self):
        """Load uncertain domains - kept for legacy"""
        if os.path.exists(self.uncertain_file):
            try:
                with open(self.uncertain_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def save_results(self):
        """Save found domains"""
        with open(self.results_file, 'w') as f:
            json.dump(self.found_domains, f, indent=2)
    
    def save_uncertain(self):
        """Save uncertain domains - kept but won't add new"""
        with open(self.uncertain_file, 'w') as f:
            json.dump(self.uncertain_domains, f, indent=2)
    
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
        """Determine availability with certainty - no uncertain"""
        positive = []
        negative = []
        attempted = set()
        attempt = 0
        max_attempts = 30  # Safety cap, but usually resolves fast
        
        while True:
            if attempt >= max_attempts:
                logger.warning(f"{domain} exhausted attempts, default to taken")
                return 'taken'
            
            result, service = self.proxy.query_once(domain)
            attempt += 1
            
            if result is None:
                time.sleep(1 + attempt * 0.3)  # Backoff
                continue
            
            if service in attempted:
                continue  # Avoid duplicates
            attempted.add(service)
            
            if result:
                positive.append(service)
            else:
                negative.append(service)
            
            logger.debug(f"{domain} - {service}: {'AVAILABLE' if result else 'TAKEN'} (P:{len(positive)} N:{len(negative)})")
            
            # If any negative, it's taken
            if negative:
                logger.debug(f"{domain} - Definitively TAKEN by {negative}")
                return 'taken'
            
            # Strong consensus for available
            if len(positive) >= 3 and not negative:
                # Final verification with one more
                verify_result, verify_service = self.proxy.query_once(domain)
                if verify_result:
                    logger.info(f"{domain} - CONFIRMED AVAILABLE by {positive + [verify_service]}")
                    return 'available'
                else:
                    logger.warning(f"{domain} - Verification failed by {verify_service}, continuing checks")
                    negative.append(verify_service)
                    if negative:
                        return 'taken'
            
            time.sleep(random.uniform(0.5, 1.5))
    
    def generate_combinations(self, length, chars=string.ascii_lowercase):
        """Generate domain combinations"""
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        """Main search loop"""
        logger.info("Starting domain hunt with proxy rotation...")
        logger.info(f"Using {len(self.proxy.services)} different WHOIS services")
        
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
                        logger.info(f"Checked {self.check_count} domains, found {len(self.found_domains)}")
                    continue
                
                # Comprehensive check
                status = self.comprehensive_check(domain)
                
                self.state['total_checked'] += 1
                self.check_count += 1
                
                if status == 'available':
                    # Check for suspicious consecutive finds
                    current_time = time.time()
                    if current_time - last_find_time < 60:
                        consecutive_finds += 1
                        if consecutive_finds >= 2:
                            logger.warning(f"Found {consecutive_finds} domains rapidly, adding verification...")
                            time.sleep(10)
                            status = self.comprehensive_check(domain)
                            if status != 'available':
                                logger.warning(f"{domain} failed re-verification")
                                continue
                    else:
                        consecutive_finds = 0
                    
                    last_find_time = current_time
                    
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
                    time.sleep(3)  # Cool down after find
                
                self.state['current_combo_index'] = i
                
                if self.check_count % 50 == 0:
                    # Log service health
                    healthy_services = sum(1 for s in self.proxy.service_health.values() if s['failures'] < 5)
                    logger.info(f"Progress: {domain} | Checked: {self.state['total_checked']} | Found: {len(self.found_domains)} | Healthy services: {healthy_services}/{len(self.proxy.services)}")
                    
                if time.time() - self.last_save > 300:
                    self.save_state()
                    self.last_save = time.time()
                
                # Minimal delay
                time.sleep(random.uniform(0.2, 0.5))
            
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
                })
            except:
                pass
    
    def run(self):
        """Main run method"""
        logger.info("="*60)
        logger.info("DOMAIN HUNTER - Proxy Rotation Edition")
        logger.info("="*60)
        logger.info(f"Starting from: {self.state['current_length']} chars, TLD #{self.state['current_tld_index']}")
        logger.info(f"Previously found: {len(self.found_domains)} domains")
        logger.info(f"Using {len(self.proxy.services)} different WHOIS services")
        logger.info("="*60)
        
        try:
            self.search_domains()
        except Exception as e:
            logger.error(f"Error: {e}")
            self.save_state()
            self.save_results()
            self.save_uncertain()
            raise
        finally:
            self.save_state()
            self.save_results()
            self.save_uncertain()
            logger.info("Hunter stopped.")

if __name__ == "__main__":
    hunter = DomainHunter()
    hunter.run()

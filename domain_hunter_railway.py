#!/usr/bin/env python3
import os
import json
import time
import string
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import subprocess
import random
import logging
from datetime import datetime, timedelta
import signal
import sys
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    print("ERROR: requests module required. Install with: pip install requests")
    sys.exit(1)

# Setup logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')  # Can set to DEBUG for more details
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
    # 2-letter TLDs (most valuable)
    'io', 'ai', 'me', 'co', 'to', 'so', 'sh', 'gg', 'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    # 3-letter premium
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot',
    # Others worth checking
    'tech', 'info', 'link', 'live', 'site', 'club', 'cool', 'world', 'today', 'life'
]

# WHOIS servers mapping
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'ai': 'whois.nic.ai',
    'me': 'whois.nic.me',
    'info': 'whois.afilias.net',
    'biz': 'whois.neulevel.biz',
    'xyz': 'whois.nic.xyz',
    'app': 'whois.nic.google',
    'dev': 'whois.nic.google',
    'to': 'whois.tonic.to',
    'sh': 'whois.nic.sh',
    'fm': 'whois.nic.fm',
    'gg': 'whois.gg',
    'cc': 'whois.nic.cc',
    'tv': 'tvwhois.verisign-grs.com',
    'ws': 'whois.website.ws',
}

class DomainHunter:
    def __init__(self):
        self.state_file = 'hunter_state.json'
        self.results_file = 'found_domains.json'
        self.uncertain_file = 'uncertain_domains.json'  # Track uncertain for manual review
        self.state = self.load_state()
        self.found_domains = self.load_results()
        self.uncertain_domains = self.load_uncertain()
        self.running = True
        self.check_count = 0
        self.last_save = time.time()
        
        # Setup graceful shutdown
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
    def shutdown(self, signum, frame):
        logger.info("Shutting down gracefully...")
        self.running = False
        self.save_state()
        self.save_results()
        self.save_uncertain()
        sys.exit(0)
        
    def load_state(self):
        """Load previous state to resume where we left off"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    logger.info(f"Resumed from: {state.get('current_length')} chars, TLD: {state.get('current_tld')}")
                    return state
            except:
                pass
        
        # Default state
        return {
            'current_length': 3,
            'current_tld_index': 0,
            'current_combo_index': 0,
            'total_checked': 0,
            'total_found': 0,
            'last_update': str(datetime.now())
        }
    
    def save_state(self):
        """Save current state for resuming"""
        self.state['last_update'] = str(datetime.now())
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def load_results(self):
        """Load previously found domains"""
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def save_results(self):
        """Save found domains"""
        with open(self.results_file, 'w') as f:
            json.dump(self.found_domains, f, indent=2)
    
    def load_uncertain(self):
        """Load uncertain domains for review"""
        if os.path.exists(self.uncertain_file):
            try:
                with open(self.uncertain_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return []
    
    def save_uncertain(self):
        """Save uncertain domains"""
        with open(self.uncertain_file, 'w') as f:
            json.dump(self.uncertain_domains, f, indent=2)
    
    def quick_dns_check(self, domain):
        """Fast DNS check to filter out taken domains"""
        try:
            socket.gethostbyname(domain)
            return False  # Resolves = taken
        except socket.gaierror:
            return True  # Doesn't resolve = potentially available
        except:
            return True  # Error = check with WHOIS
    
    def direct_whois_check(self, domain):
        """Direct WHOIS socket check"""
        try:
            tld = domain.split('.')[-1]
            whois_server = WHOIS_SERVERS.get(tld, f'whois.nic.{tld}')
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((whois_server, 43))
            s.send((domain + '\r\n').encode('utf-8'))
            response = b''
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
                if len(response) > 16384:
                    break
            s.close()
            
            resp_text = response.decode('utf-8', errors='ignore')
            resp_lower = resp_text.lower()
            
            # Log the response for debugging
            if len(resp_text.strip()) < 200:
                logger.debug(f"WHOIS for {domain}: {resp_text.strip()[:100]}")
            
            # VERY SHORT or EMPTY response = likely available
            if len(resp_text.strip()) < 50:
                logger.debug(f"{domain} - Very short WHOIS response, marking as available")
                return True
            
            # Clear indicators of availability
            if any(x in resp_lower for x in [
                'no data found', 'not found', 'no match', 'available',
                'not registered', 'no entries found', 'status: free',
                'domain not found', 'no matching record'
            ]):
                return True
            
            # Premium domain indicators
            if any(x in resp_lower for x in ['premium', 'broker', 'aftermarket', 'reserved']):
                return 'premium'
                
            # Check for registration data - if ANY of these exist, it's taken
            registration_markers = [
                'registrar:', 'creation date:', 'created:', 'registered:',
                'expiry date:', 'expires:', 'updated:', 'name server:',
                'registrant:', 'domain name:', 'registry domain id:'
            ]
            
            if any(marker in resp_lower for marker in registration_markers):
                return False
                
            # If response is short-ish with no registration data, likely available
            if len(resp_text.strip()) < 150:
                logger.debug(f"{domain} - Short WHOIS with no registration data, marking as available")
                return True
                
            # Uncertain - log for review
            logger.debug(f"{domain} - Uncertain WHOIS response length: {len(resp_text)}")
            return None
            
        except Exception as e:
            logger.debug(f"WHOIS error for {domain}: {e}")
            return None
    
    def check_godaddy(self, domain):
        """Check GoDaddy API - good for filtering premium domains"""
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
            
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                if 'ExactMatchDomain' in data:
                    exact = data['ExactMatchDomain']
                    is_available = exact.get('IsAvailable', False)
                    
                    if is_available:
                        # Check if it's premium
                        if 'Products' in exact and exact['Products']:
                            for product in exact['Products']:
                                price_info = product.get('priceInfo', {})
                                list_price = price_info.get('ListPrice', 0)
                                # If price > $100, likely premium
                                if list_price > 100:
                                    return 'premium', list_price
                        return True, None
                    return False, None
            return None, None
        except:
            return None, None
    
    def check_namecheap(self, domain):
        """Check Namecheap - another good source"""
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                text = response.text.lower()
                
                # Premium indicators
                if 'premium domain' in text or 'premium listing' in text:
                    return 'premium'
                    
                if 'domain taken' in text or 'unavailable' in text:
                    return False
                    
                if 'add to cart' in text and domain.lower() in text:
                    return True
                    
            return None
        except:
            return None
    
    def check_porkbun(self, domain):
        """Check Porkbun - they have a good API for availability"""
        try:
            # Porkbun's public API endpoint
            url = f"https://porkbun.com/api/json/v3/pricing/get"
            response = requests.get(url, timeout=5, verify=False)
            
            # Alternative: Check their domain search page
            search_url = f"https://porkbun.com/products/domains/{domain}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            search_response = requests.get(search_url, headers=headers, timeout=5, verify=False)
            
            if search_response.status_code == 200:
                text = search_response.text.lower()
                
                # If "add to cart" or "register" button exists, it's available
                if 'add to cart' in text or 'register this domain' in text:
                    return True
                    
                # If it says taken or unavailable
                if 'unavailable' in text or 'already registered' in text:
                    return False
                    
                # Check for premium
                if 'premium' in text:
                    return 'premium'
                    
            return None
        except:
            return None
    
    def comprehensive_check(self, domain):
        """Comprehensive check using multiple sources"""
        results = {'available': 0, 'taken': 0, 'premium': 0, 'unknown': 0}
        details = []
        
        # 1. Direct WHOIS (most reliable for positive availability)
        whois_result = self.direct_whois_check(domain)
        if whois_result == True:
            results['available'] += 3  # Strong signal
            details.append("WHOIS: available")
        elif whois_result == 'premium':
            results['premium'] += 3
            details.append("WHOIS: premium")
            logger.info(f"  {domain} - Premium domain detected")
            return 'premium'
        elif whois_result == False:
            results['taken'] += 2  # Less weight since WHOIS can be wrong
            details.append("WHOIS: taken")
        else:
            results['unknown'] += 1
            details.append("WHOIS: unknown")
        
        # 2. GoDaddy check
        godaddy_result, price = self.check_godaddy(domain)
        if godaddy_result == 'premium':
            results['premium'] += 2
            details.append(f"GoDaddy: premium ${price}")
            return 'premium'
        elif godaddy_result == True:
            results['available'] += 2
            details.append(f"GoDaddy: available ${price if price else '?'}")
        elif godaddy_result == False:
            results['taken'] += 1  # Less weight
            details.append("GoDaddy: taken")
        else:
            results['unknown'] += 1
            details.append("GoDaddy: unknown")
        
        # 3. Namecheap check
        namecheap_result = self.check_namecheap(domain)
        if namecheap_result == 'premium':
            results['premium'] += 2
            details.append("Namecheap: premium")
            return 'premium'
        elif namecheap_result == True:
            results['available'] += 2
            details.append("Namecheap: available")
        elif namecheap_result == False:
            results['taken'] += 1
            details.append("Namecheap: taken")
        else:
            results['unknown'] += 1
            details.append("Namecheap: unknown")
        
        # 4. Porkbun check
        porkbun_result = self.check_porkbun(domain)
        if porkbun_result == 'premium':
            results['premium'] += 1
            details.append("Porkbun: premium")
            return 'premium'
        elif porkbun_result == True:
            results['available'] += 2
            details.append("Porkbun: available")
        elif porkbun_result == False:
            results['taken'] += 1
            details.append("Porkbun: taken")
        else:
            results['unknown'] += 1
            details.append("Porkbun: unknown")
        
        # Log details for debugging
        logger.debug(f"{domain} - Scores: available={results['available']}, taken={results['taken']}, unknown={results['unknown']}")
        logger.debug(f"{domain} - Details: {', '.join(details)}")
        
        # Decision logic - LESS CONSERVATIVE
        if results['premium'] > 0:
            return 'premium'
            
        # If WHOIS shows available and at least one other source agrees, it's available
        if whois_result == True and results['available'] >= 5:
            logger.info(f"  {domain} - Strong availability signal")
            return 'available'
            
        # If multiple sources say available and taken signals are weak
        if results['available'] >= 4 and results['taken'] <= 1:
            logger.info(f"  {domain} - Multiple sources confirm availability")
            return 'available'
            
        # If strongly taken
        if results['taken'] >= 4:
            return 'taken'
            
        # If more available signals than taken
        if results['available'] > results['taken'] and results['available'] >= 3:
            logger.info(f"  {domain} - Likely available (worth manual check)")
            return 'available'
            
        # Default to taken if ambiguous (but log it)
        if results['available'] > 0:
            logger.warning(f"  {domain} - Ambiguous, marking as uncertain: {details}")
            return 'uncertain'
            
        return 'taken'
    
    def generate_combinations(self, length, chars=string.ascii_lowercase + string.digits):
        """Generate domain combinations"""
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        """Main search loop"""
        logger.info("Starting domain hunt...")
        
        while self.running:
            current_length = self.state['current_length']
            
            # Stop at 6 characters (gets too many results)
            if current_length > 6:
                logger.info("Reached maximum length (6 chars). Restarting from 3...")
                self.state['current_length'] = 3
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                continue
            
            # Get current TLD
            if self.state['current_tld_index'] >= len(PRIORITY_TLDS):
                # Move to next length
                self.state['current_length'] += 1
                self.state['current_tld_index'] = 0
                self.state['current_combo_index'] = 0
                logger.info(f"Moving to {self.state['current_length']} character domains")
                continue
            
            current_tld = PRIORITY_TLDS[self.state['current_tld_index']]
            
            # Use letters only for 3 chars, letters+numbers for 4+
            if current_length <= 3:
                chars = string.ascii_lowercase
            else:
                chars = string.ascii_lowercase + string.digits
            
            # Generate all combinations
            all_combos = list(self.generate_combinations(current_length, chars))
            
            logger.info(f"Checking {current_length}-char .{current_tld} domains ({len(all_combos)} total)")
            
            # Resume from where we left off
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
                    # Found one!
                    result = {
                        'domain': domain,
                        'length': current_length,
                        'found_at': str(datetime.now()),
                        'status': 'available'
                    }
                    self.found_domains.append(result)
                    self.state['total_found'] += 1
                    
                    logger.info(f"🎯 FOUND AVAILABLE: {domain} ({current_length} chars)")
                    
                    # Save immediately
                    self.save_results()
                    
                    # Send notification if configured
                    self.send_notification(domain)
                
                elif status == 'uncertain':
                    # Save for manual review
                    uncertain_result = {
                        'domain': domain,
                        'length': current_length,
                        'checked_at': str(datetime.now()),
                        'status': 'uncertain'
                    }
                    self.uncertain_domains.append(uncertain_result)
                    logger.info(f"❓ UNCERTAIN (check manually): {domain}")
                    self.save_uncertain()
                
                elif status == 'premium':
                    logger.debug(f"Premium/Brokered: {domain}")
                
                # Update state periodically
                self.state['current_combo_index'] = i
                
                if self.check_count % 50 == 0:
                    logger.info(f"Progress: {domain} | Total checked: {self.state['total_checked']} | Found: {len(self.found_domains)}")
                    
                # Save state every 5 minutes
                if time.time() - self.last_save > 300:
                    self.save_state()
                    self.last_save = time.time()
                
                # Rate limiting - adjust based on your needs
                time.sleep(random.uniform(0.5, 1.5))
            
            # Move to next TLD
            self.state['current_tld_index'] += 1
            self.state['current_combo_index'] = 0
            self.save_state()
    
    def send_notification(self, domain):
        """Send notification when domain is found (implement webhook/email if needed)"""
        # You can add Discord webhook, email, or other notifications here
        # Example for Discord webhook:
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
        logger.info("DOMAIN HUNTER - Railway Edition")
        logger.info("="*60)
        logger.info(f"Starting from: {self.state['current_length']} chars, TLD #{self.state['current_tld_index']}")
        logger.info(f"Previously found: {len(self.found_domains)} domains")
        logger.info(f"Uncertain domains to review: {len(self.uncertain_domains)}")
        logger.info("="*60)
        
        try:
            self.search_domains()
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
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

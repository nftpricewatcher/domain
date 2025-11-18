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
        # Create empty file if doesn't exist
        empty_list = []
        with open(self.results_file, 'w') as f:
            json.dump(empty_list, f)
        return empty_list
    
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
        # Create empty file if doesn't exist
        empty_list = []
        with open(self.uncertain_file, 'w') as f:
            json.dump(empty_list, f)
        return empty_list
    
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
    
    def direct_whois_check(self, domain, retry_count=0):
        """Direct WHOIS socket check with rate limit detection"""
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
            
            # CRITICAL: Check for rate limiting indicators
            rate_limit_indicators = [
                'limit exceeded', 'too many requests', 'quota exceeded',
                'try again later', 'blocked', 'rate limit', 'throttled',
                'maximum queries', 'please wait', 'slow down'
            ]
            
            if any(indicator in resp_lower for indicator in rate_limit_indicators):
                logger.warning(f"Rate limit detected for {domain}! Waiting...")
                time.sleep(10)  # Wait 10 seconds
                if retry_count < 2:
                    return self.direct_whois_check(domain, retry_count + 1)
                return None  # Can't determine
            
            # Check if we got a real response (not empty or error)
            if len(resp_text.strip()) < 20:
                logger.warning(f"{domain} - Suspiciously short WHOIS: '{resp_text.strip()}'")
                # Too short to be real - might be rate limited
                if retry_count < 1:
                    time.sleep(5)
                    return self.direct_whois_check(domain, retry_count + 1)
                return None  # Can't trust this
            
            # Log full response for debugging false positives
            logger.debug(f"WHOIS for {domain} ({len(resp_text)} chars): {resp_text[:200]}")
            
            # STRONG indicators it's TAKEN (if ANY of these exist)
            taken_indicators = [
                'registrar:', 'creation date:', 'created:', 'registered:',
                'expiry date:', 'expires:', 'expire:', 'updated:', 'modified:',
                'name server:', 'nameserver:', 'dns:', 'registrant:', 
                'domain name:', 'registry domain id:', 'domain status:',
                'whois server:', 'registry expiry', 'admin contact',
                'tech contact', 'billing contact', 'registration date'
            ]
            
            # If we find ANY registration data, it's definitely taken
            for indicator in taken_indicators:
                if indicator in resp_lower:
                    logger.debug(f"{domain} is TAKEN - found '{indicator}'")
                    return False
            
            # STRONG indicators it's AVAILABLE
            available_indicators = [
                'no data found', 'not found', 'no match', 
                'no matching record', 'not registered', 'no entries found',
                'status: free', 'domain not found', 'available for registration',
                'no found', 'nothing found', 'not in database'
            ]
            
            for indicator in available_indicators:
                if indicator in resp_lower:
                    logger.debug(f"{domain} appears AVAILABLE - found '{indicator}'")
                    # But let's be cautious with short responses
                    if len(resp_text) < 100:
                        logger.warning(f"{domain} - Short 'not found' response, might be rate limited")
                        return None  # Don't trust it
                    return True
            
            # Premium/broker indicators
            if any(x in resp_lower for x in ['premium', 'broker', 'aftermarket', 'reserved']):
                return 'premium'
            
            # If response is substantial but has no registration data, be suspicious
            if len(resp_text) > 200:
                logger.warning(f"{domain} - Long response but no clear status")
                return None  # Uncertain
            
            # Default to uncertain for safety
            logger.debug(f"{domain} - Could not determine status from WHOIS")
            return None
            
        except socket.timeout:
            logger.warning(f"WHOIS timeout for {domain}")
            if retry_count < 1:
                time.sleep(2)
                return self.direct_whois_check(domain, retry_count + 1)
            return None
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {e}")
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
        """Comprehensive check using multiple sources - STRICT to avoid false positives"""
        results = {'available': 0, 'taken': 0, 'premium': 0, 'unknown': 0}
        details = []
        sources_checked = 0
        positive_sources = []
        
        # 1. Direct WHOIS (most important)
        whois_result = self.direct_whois_check(domain)
        sources_checked += 1
        
        if whois_result == True:
            results['available'] += 2  # Reduced weight
            details.append("WHOIS: available")
            positive_sources.append("WHOIS")
        elif whois_result == 'premium':
            results['premium'] += 3
            details.append("WHOIS: premium")
            return 'premium'
        elif whois_result == False:
            results['taken'] += 5  # STRONG signal if WHOIS shows taken
            details.append("WHOIS: taken")
        else:
            results['unknown'] += 1
            details.append("WHOIS: unknown")
        
        # If WHOIS clearly shows taken, don't bother checking more
        if whois_result == False:
            logger.debug(f"{domain} - WHOIS shows registration data, marking as TAKEN")
            return 'taken'
        
        # 2. GoDaddy check
        godaddy_result, price = self.check_godaddy(domain)
        sources_checked += 1
        
        if godaddy_result == 'premium':
            results['premium'] += 2
            details.append(f"GoDaddy: premium ${price}")
            return 'premium'
        elif godaddy_result == True:
            results['available'] += 2
            details.append(f"GoDaddy: available ${price if price else '?'}")
            positive_sources.append("GoDaddy")
        elif godaddy_result == False:
            results['taken'] += 3
            details.append("GoDaddy: taken")
        else:
            results['unknown'] += 1
            details.append("GoDaddy: unknown")
        
        # 3. Namecheap check
        namecheap_result = self.check_namecheap(domain)
        sources_checked += 1
        
        if namecheap_result == 'premium':
            results['premium'] += 2
            details.append("Namecheap: premium")
            return 'premium'
        elif namecheap_result == True:
            results['available'] += 2
            details.append("Namecheap: available")
            positive_sources.append("Namecheap")
        elif namecheap_result == False:
            results['taken'] += 3
            details.append("Namecheap: taken")
        else:
            results['unknown'] += 1
            details.append("Namecheap: unknown")
        
        # 4. Porkbun check
        porkbun_result = self.check_porkbun(domain)
        sources_checked += 1
        
        if porkbun_result == 'premium':
            results['premium'] += 1
            details.append("Porkbun: premium")
            return 'premium'
        elif porkbun_result == True:
            results['available'] += 2
            details.append("Porkbun: available")
            positive_sources.append("Porkbun")
        elif porkbun_result == False:
            results['taken'] += 3
            details.append("Porkbun: taken")
        else:
            results['unknown'] += 1
            details.append("Porkbun: unknown")
        
        # Log details
        logger.debug(f"{domain} - Scores: available={results['available']}, taken={results['taken']}, unknown={results['unknown']}")
        logger.debug(f"{domain} - Details: {', '.join(details)}")
        logger.debug(f"{domain} - Positive sources: {positive_sources}")
        
        # STRICT Decision logic to avoid false positives
        
        # If ANY source definitively shows taken, it's taken
        if results['taken'] >= 3:
            logger.debug(f"{domain} - Marked as TAKEN (score: {results['taken']})")
            return 'taken'
        
        # Need MULTIPLE sources to agree it's available
        # And NO sources should say taken
        if len(positive_sources) >= 3 and results['taken'] == 0:
            # Triple verification for safety
            logger.info(f"{domain} - {len(positive_sources)} sources say available, verifying...")
            
            # Do a second WHOIS check to be sure
            time.sleep(2)
            verify_result = self.direct_whois_check(domain)
            if verify_result == True:
                logger.info(f"{domain} - Verification passed! Sources: {', '.join(positive_sources)}")
                return 'available'
            else:
                logger.warning(f"{domain} - Verification failed, marking as uncertain")
                return 'uncertain'
        
        # If we have too many unknowns, we can't trust the result
        if results['unknown'] >= 3:
            logger.debug(f"{domain} - Too many unknown responses, marking as uncertain")
            return 'uncertain'
        
        # If we have some positive signals but not enough confidence
        if len(positive_sources) >= 1:
            logger.debug(f"{domain} - Some positive signals but not enough confidence")
            return 'uncertain'
        
        # Default to taken for safety
        logger.debug(f"{domain} - No strong signals, defaulting to taken")
        return 'taken'
    
    def generate_combinations(self, length, chars=string.ascii_lowercase + string.digits):
        """Generate domain combinations"""
        for combo in itertools.product(chars, repeat=length):
            yield ''.join(combo)
    
    def search_domains(self):
        """Main search loop"""
        logger.info("Starting domain hunt...")
        
        consecutive_finds = 0
        last_find_time = 0
        
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
                    # Check for suspicious consecutive finds
                    current_time = time.time()
                    if current_time - last_find_time < 30:  # Found within 30 seconds
                        consecutive_finds += 1
                        if consecutive_finds >= 2:
                            logger.warning(f"⚠️ Found {consecutive_finds} domains rapidly - possible false positives!")
                            logger.warning("Adding extra verification and cooldown...")
                            time.sleep(30)  # Wait 30 seconds
                            
                            # Re-verify the domain
                            logger.info(f"Re-verifying {domain}...")
                            time.sleep(5)
                            status = self.comprehensive_check(domain)
                            if status != 'available':
                                logger.warning(f"❌ {domain} failed re-verification, was a false positive")
                                continue
                    else:
                        consecutive_finds = 0
                    
                    last_find_time = current_time
                    
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
                    
                    # Extra delay after finding a domain to avoid rate limits
                    time.sleep(5)
                
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
                
                # Dynamic rate limiting based on recent activity
                if consecutive_finds > 0:
                    # Slower if we found domains recently (might be hitting limits)
                    time.sleep(random.uniform(2.0, 4.0))
                else:
                    # Normal rate
                    time.sleep(random.uniform(1.0, 2.0))
            
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

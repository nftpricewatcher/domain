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
import requests
import threading
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
    """Rotates through multiple WHOIS services and proxies to avoid rate limits"""
    
    def __init__(self):
        self.services = [
            # Primary services (higher weights for reliable ones)
            {'name': 'whois.com', 'func': self.check_whois_com, 'weight': 12},
            {'name': 'who.is', 'func': self.check_who_is, 'weight': 12},
            {'name': 'godaddy', 'func': self.check_godaddy, 'weight': 15},
            {'name': 'namecheap', 'func': self.check_namecheap, 'weight': 15},
            {'name': 'porkbun', 'func': self.check_porkbun, 'weight': 12},
            
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
            
            # New services for more rotation
            {'name': 'icann', 'func': self.check_icann, 'weight': 10},
            {'name': 'verisign', 'func': self.check_verisign, 'weight': 10},
            {'name': 'networksolutions', 'func': self.check_networksolutions, 'weight': 8},
            {'name': 'ultratools', 'func': self.check_ultratools, 'weight': 8},
        ]
        
        # Hardcoded list of 300 fresh proxies (collected from multiple sources on November 18, 2025)
        self.proxies = [
            '152.230.215.123:80', '65.108.159.129:8081', '139.59.1.14:80', '95.173.218.66:8082', '123.30.154.171:7777', '95.173.218.75:8081', '159.65.245.255:80', '133.18.234.13:80', '32.223.6.94:80', '103.65.237.92:5678', '23.247.136.254:80', '190.58.248.86:80', '50.122.86.118:80', '138.124.49.149:10808', '35.197.89.213:80', '188.40.57.101:80', '198.7.62.199:3128', '192.73.244.36:80', '210.223.44.230:3128', '213.157.6.50:80', '213.33.126.130:80', '194.158.203.14:80', '189.202.188.149:80', '194.219.134.234:80', '4.195.16.140:80', '124.108.6.20:8085', '143.42.66.91:80', '103.249.133.226:10808', '62.99.138.162:80', '20.205.61.143:80', '211.230.49.122:3128', '213.143.113.82:80', '200.174.198.32:8888', '5.45.126.128:8080', '181.41.194.186:80', '47.56.110.204:8989', '176.126.103.194:44214', '4.149.153.123:3128', '0.0.0.0:80', '97.74.87.226:80', '127.0.0.7:80', '130.193.57.247:1080', '115.79.70.69:8470', '38.154.193.167:5440', '38.154.227.158:5859', '166.88.83.167:6824', '45.81.149.114:6546', '23.26.94.116:6098', '23.27.78.98:5678', '45.81.149.222:6654', '107.175.135.152:6593', '23.27.93.56:5635', '45.61.100.100:6368', '67.227.112.16:6056', '192.186.151.148:8649', '46.203.196.250:5696', '157.66.192.91:8080', '103.82.23.118:5178', '47.74.157.194:80', '197.221.234.253:80', '219.93.101.60:80', '84.39.112.144:3128', '14.241.80.37:8080', '98.71.99.164:8080', '67.43.236.18:17781', '72.10.160.173:1157', '72.10.160.90:1237', '138.68.60.8:80', '37.27.6.46:80', '38.54.71.67:80', '139.162.78.109:8080', '177.53.215.119:8080', '159.65.245.255:80', '68.183.143.134:80', '103.14.231.214:3188', '103.133.26.119:8080', '197.254.84.86:32650', '118.97.47.249:55443', '103.96.79.75:8080', '91.238.104.172:2024', '109.224.242.5:8080', '45.61.122.80:6372', '149.57.85.155:6123', '23.229.125.113:5382', '193.233.211.219:8085', '154.29.235.120:6461', '193.202.16.110:8085', '173.211.0.115:6608', '31.58.21.212:6483', '92.113.7.164:6890', '136.0.188.86:6049', '45.41.179.25:6560', '145.223.54.17:5982', '38.154.233.243:5653', '89.249.194.158:6557', '98.159.38.227:6527', '45.41.173.215:6582', '199.180.9.36:6056', '202.148.18.178:8080', '161.82.141.218:8080', '202.179.93.132:58080', '103.10.55.174:7653', '38.159.232.108:999', '176.117.106.149:8080', '180.211.179.126:8080', '31.58.19.166:6438', '154.29.87.5:6426', '199.96.165.211:8085', '31.134.2.81:8085', '107.174.25.52:5506', '104.238.37.113:6670', '179.61.166.214:6637', '23.229.110.120:8648', '136.0.186.18:6379', '212.119.40.232:8085', '82.26.238.94:6401', '89.249.194.187:6586', '185.77.220.171:8085', '23.95.255.11:6595', '45.61.127.89:6028', '31.57.87.229:5914', '91.247.163.89:8085', '206.206.73.168:6784', '167.253.18.72:8085', '94.154.127.96:8085', '184.174.43.12:6552', '64.49.36.186:8085', '166.88.155.205:6364', '23.27.210.143:6513', '217.145.225.192:8085', '140.235.170.235:8085', '103.251.223.14:5993', '174.140.254.235:6826', '64.49.36.188:8085', '45.56.175.139:5813', '184.174.44.162:6588', '146.103.55.25:6077', '142.147.131.214:6114', '193.233.218.100:8085', '64.49.36.38:8085', '142.111.44.234:5946', '45.61.100.139:6407', '69.58.12.65:8070', '166.88.83.26:6683', '173.244.41.60:6244', '45.61.97.144:6670', '167.253.48.77:8085', '38.154.204.95:8136', '198.20.191.128:5198', '140.235.2.184:8085', '191.96.104.235:5972', '23.95.255.98:6682', '45.136.25.245:8085', '89.249.192.116:6515', '142.111.93.244:6805', '184.174.43.214:6754', '154.6.23.36:6503', '184.174.30.64:5733', '23.236.222.132:7163', '45.41.162.41:6678', '45.41.177.143:5793', '136.0.188.217:6180', '45.41.162.194:6831', '31.58.151.26:6017', '154.6.8.164:5631', '91.242.228.66:8085', '98.159.38.46:6346', '136.0.207.227:6804', '199.96.164.218:8085', '194.180.237.113:8085', '161.123.130.215:5886', '185'
        ]
        
        # Track service health
        self.service_health = {s['name']: {'failures': 0, 'last_used': 0} for s in self.services}
        self.last_reset = time.time()
        
        # Start background service recovery thread
        self.recovery_thread = threading.Thread(target=self.recover_services_background, daemon=True)
        self.recovery_thread.start()
    
    def recover_services_background(self):
        """Background thread to regularly test and recover disabled services"""
        while True:
            time.sleep(300)  # Every 5 minutes
            current_time = time.time()
            logger.info("Running background service recovery...")
            for service in self.services:
                name = service['name']
                health = self.service_health[name]
                if health['failures'] > 10:  # Only test disabled ones
                    try:
                        # Test with a known taken domain
                        result = service['func']("google.com")
                        if result == False:  # Correctly detects as taken
                            health['failures'] = 0
                            logger.info(f"Recovered service {name} - now healthy")
                        else:
                            health['failures'] += 1  # Still bad
                    except:
                        health['failures'] += 1
            self.last_reset = current_time
    
    def get_next_service(self):
        """Get next healthy service using weighted rotation"""
        current_time = time.time()
        
        # Periodic passive recovery every 5 minutes (in addition to active testing)
        if current_time - self.last_reset > 300:
            for health in self.service_health.values():
                if health['failures'] > 0:
                    health['failures'] -= 1
            logger.info("Periodic passive service health recovery applied")
        
        available = []
        for service in self.services:
            name = service['name']
            health = self.service_health[name]
            
            if health['failures'] > 10:
                continue
                
            if current_time - health['last_used'] < 3:
                continue
                
            available.extend([service] * service['weight'])
        
        if not available:
            logger.warning("All services rate limited or failed, forcing reset...")
            for name in self.service_health:
                self.service_health[name]['failures'] = max(0, self.service_health[name]['failures'] - 5)
            time.sleep(20)
            return random.choice(self.services)
        
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
    
    def _get_response(self, url, headers):
        """Helper for requests with proxy rotation"""
        if self.proxies:
            proxy = random.choice(self.proxies)
            proxies = {'http': f'http://{proxy}', 'https': f'https://{proxy}'}
        else:
            proxies = None
        try:
            return requests.get(url, headers=headers, timeout=5, verify=False, proxies=proxies)
        except:
            return None
    
    # Service implementation methods
    
    def check_whois_com(self, domain):
        try:
            url = f"https://www.whois.com/whois/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'available for registration' in text or 'no match for' in text:
                return True
            if any(x in text for x in ['registrar:', 'creation date:', 'registry expiry']):
                return False
            return None
        except:
            return None
    
    def check_who_is(self, domain):
        try:
            url = f"https://who.is/whois/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text
            if 'No Data Found' in text or 'NOT FOUND' in text or 'No match for' in text:
                return True
            if any(x in text for x in ['Registrar:', 'Created:', 'Expires:', 'Creation Date:']):
                return False
            return None
        except:
            return None
    
    def check_godaddy(self, domain):
        try:
            url = f"https://find.godaddy.com/domainsapi/v1/search/exact?q={domain}&key=dpp_search"
            headers = {'User-Agent': self._get_random_ua(), 'Accept': 'application/json'}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            data = response.json()
            if 'ExactMatchDomain' in data:
                return data['ExactMatchDomain'].get('IsAvailable', False)
            return None
        except:
            return None
    
    def check_namecheap(self, domain):
        try:
            url = f"https://www.namecheap.com/domains/registration/results/?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'domain taken' in text or 'unavailable' in text:
                return False
            if 'add to cart' in text and domain.lower() in text:
                return True
            return None
        except:
            return None
    
    def check_porkbun(self, domain):
        try:
            url = f"https://porkbun.com/products/domains/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'add to cart' in text or 'register this domain' in text:
                return True
            if 'unavailable' in text or 'already registered' in text:
                return False
            return None
        except:
            return None
    
    def check_mxtoolbox(self, domain):
        try:
            url = f"https://mxtoolbox.com/SuperTool.aspx?action=whois%3a{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text
            if 'No Data Found' in text or 'No Match' in text:
                return True
            if 'Registrar:' in text or 'Creation Date:' in text:
                return False
            return None
        except:
            return None
    
    def check_whoisxmlapi(self, domain):
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}"
            response = self._get_response(url, {})
            if response.status_code != 200:
                return None
            if 'No Data Found' in response.text or 'NOT FOUND' in response.text:
                return True
            if 'registrar' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_domaintools(self, domain):
        try:
            url = f"https://whois.domaintools.com/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text
            if 'No results found' in text or 'is available' in text:
                return True
            if 'Registrar:' in text:
                return False
            return None
        except:
            return None
    
    def check_whatsmydns(self, domain):
        try:
            url = f"https://www.whatsmydns.net/api/domain/{domain}"
            response = self._get_response(url, {})
            if response.status_code == 404:
                return True
            if response.status_code == 200:
                return False
            return None
        except:
            return None
    
    def check_hostinger(self, domain):
        try:
            url = f"https://www.hostinger.com/domain-name-search?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'is available' in text and 'taken' not in text:
                return True
            if 'taken' in text or 'unavailable' in text:
                return False
            return None
        except:
            return None
    
    def check_namecom(self, domain):
        try:
            url = f"https://www.name.com/domain/search/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'is available' in text or 'add to cart' in text:
                return True
            if 'is taken' in text or 'unavailable' in text:
                return False
            return None
        except:
            return None
    
    def check_hover(self, domain):
        try:
            url = f"https://www.hover.com/domains/results?q={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'available' in response.text.lower() and 'taken' not in response.text.lower():
                return True
            if 'taken' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_gandi(self, domain):
        try:
            url = f"https://www.gandi.net/domain/suggest?search={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'available' in text and 'registered' not in text:
                return True
            if 'taken' in text or 'registered' in text:
                return False
            return None
        except:
            return None
    
    def check_namesilo(self, domain):
        try:
            url = f"https://www.namesilo.com/domain/search-domains?query={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'available' in response.text.lower():
                return True
            if 'unavailable' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_dynadot(self, domain):
        try:
            url = f"https://www.dynadot.com/domain/search.html?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'add to cart' in text:
                return True
            if 'taken' in text or 'registered' in text:
                return False
            return None
        except:
            return None
    
    def check_enom(self, domain):
        try:
            url = f"https://www.enom.com/domains/search-results?query={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'available' in response.text.lower():
                return True
            if 'taken' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_domaincom(self, domain):
        try:
            url = f"https://www.domain.com/domains/search/results/?q={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'available' in response.text.lower():
                return True
            if 'taken' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_registercom(self, domain):
        try:
            url = f"https://www.register.com/domain/search/wizard.rcmx?searchDomainName={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'is available' in response.text.lower():
                return True
            if 'not available' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_bluehost(self, domain):
        try:
            url = f"https://www.bluehost.com/domains?search={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'available' in response.text.lower():
                return True
            if 'taken' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_dreamhost(self, domain):
        try:
            url = f"https://www.dreamhost.com/domains/search/?domain={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            if 'is available' in response.text.lower():
                return True
            if 'is taken' in response.text.lower():
                return False
            return None
        except:
            return None
    
    def check_icann(self, domain):
        try:
            url = f"https://lookup.icann.org/api/v2/domain?name={domain}"
            headers = {'User-Agent': self._get_random_ua(), 'Accept': 'application/json'}
            response = self._get_response(url, headers)
            if response.status_code == 404:
                return True
            if response.status_code == 200:
                text = response.text.lower()
                if 'registered' in text or 'registrar' in text:
                    return False
                return True
            return None
        except:
            return None
    
    def check_verisign(self, domain):
        try:
            url = f"https://webwhois.verisign.com/webwhois-ui/rest/whois?q={domain}&lang=en_US"
            headers = {'User-Agent': self._get_random_ua(), 'Accept': 'application/json'}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'no match' in text or 'available' in text:
                return True
            if 'registrar' in text or 'creation date' in text:
                return False
            return None
        except:
            return None
    
    def check_networksolutions(self, domain):
        try:
            url = f"https://www.networksolutions.com/whois-search/{domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'available' in text or 'not registered' in text:
                return True
            if 'registered' in text or 'registrar' in text:
                return False
            return None
        except:
            return None
    
    def check_ultratools(self, domain):
        try:
            url = f"https://www.ultratools.com/tools/domainWhois?domainName={domain}"
            headers = {'User-Agent': self._get_random_ua()}
            response = self._get_response(url, headers)
            if response.status_code != 200:
                return None
            text = response.text.lower()
            if 'domain not found' in text or 'available' in text:
                return True
            if 'registrar' in text or 'creation date' in text:
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
        self.save_uncertain()
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
                
                # Comprehensive check using proxy rotation
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
                
                # Minimal delay since we're using different services
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

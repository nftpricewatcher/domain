#!/usr/bin/env python3
"""
Quick test to verify domain checking accuracy
"""
import os
import sys
import logging

# Set debug logging
os.environ['LOG_LEVEL'] = 'DEBUG'

from domain_hunter_railway import DomainHunter

# Configure logging for test
logging.basicConfig(
    level=logging.DEBUG,
    format='%(message)s'
)

def test_specific_domains():
    """Test specific domains that should be available"""
    
    print("="*60)
    print("TESTING DOMAIN VERIFICATION ACCURACY")
    print("="*60)
    
    hunter = DomainHunter()
    
    # Test domains - add the domain you mentioned
    test_domains = [
        'ihj.io',  # The domain you mentioned
        'xqz.io',  # Likely available
        'zzq.io',  # Likely available  
        'google.com',  # Obviously taken (control)
    ]
    
    print("\nTesting domain availability detection:\n")
    
    for domain in test_domains:
        print(f"\n{'='*40}")
        print(f"Testing: {domain}")
        print(f"{'='*40}")
        
        # Quick DNS check
        dns = hunter.quick_dns_check(domain)
        print(f"DNS Check: {'No DNS record (potentially available)' if dns else 'Has DNS (likely taken)'}")
        
        # Direct WHOIS
        whois = hunter.direct_whois_check(domain)
        if whois == True:
            print(f"WHOIS: ✅ AVAILABLE")
        elif whois == 'premium':
            print(f"WHOIS: 💰 PREMIUM")
        elif whois == False:
            print(f"WHOIS: ❌ TAKEN")
        else:
            print(f"WHOIS: ❓ UNCERTAIN")
        
        # Full comprehensive check
        print(f"\nRunning comprehensive check...")
        result = hunter.comprehensive_check(domain)
        
        print(f"\nFINAL VERDICT: ", end="")
        if result == 'available':
            print(f"✅ AVAILABLE - You should be able to register this!")
        elif result == 'taken':
            print(f"❌ TAKEN - Already registered")
        elif result == 'premium':
            print(f"💰 PREMIUM - Available but at premium price")
        else:
            print(f"❓ UNCERTAIN - Needs manual verification")
        
        if domain == 'ihj.io':
            print(f"\nNOTE: If {domain} shows as available on Porkbun/who.is")
            print(f"but this shows it as taken/uncertain, the detection needs adjustment.")
    
    print(f"\n{'='*60}")
    print("TEST COMPLETE")
    print(f"{'='*60}")
    
    print("\nIf ihj.io showed as TAKEN or UNCERTAIN but you can register it,")
    print("please share the debug output above so we can improve detection!")

if __name__ == "__main__":
    test_specific_domains()

#!/usr/bin/env python3
"""
Test false positive domains to understand why they were incorrectly marked as available
"""
import os
import sys
import time
import logging

# Set debug logging
os.environ['LOG_LEVEL'] = 'DEBUG'

from domain_hunter_railway import DomainHunter

# Configure logging for test
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s: %(message)s'
)

def test_false_positives():
    """Test domains that were incorrectly marked as available"""
    
    print("="*60)
    print("FALSE POSITIVE INVESTIGATION")
    print("="*60)
    
    hunter = DomainHunter()
    
    # These domains were incorrectly marked as available but are actually taken
    false_positives = [
        'cnr.io',
        'cnv.io', 
        'pou.io',
        'pox.io'
    ]
    
    print("\nTesting domains that were false positives:\n")
    print("All of these domains ARE TAKEN but were marked as available.")
    print("Let's see what went wrong...\n")
    
    for domain in false_positives:
        print(f"\n{'='*50}")
        print(f"TESTING: {domain} (this domain IS TAKEN)")
        print(f"{'='*50}\n")
        
        # DNS Check
        print("1. DNS Check:")
        dns = hunter.quick_dns_check(domain)
        if dns:
            print(f"   ❌ No DNS record found (but domain is still taken!)")
        else:
            print(f"   ✅ Has DNS record (correctly indicates taken)")
        
        # Direct WHOIS with detailed response
        print("\n2. WHOIS Check (with retries):")
        whois = hunter.direct_whois_check(domain)
        if whois == True:
            print(f"   ❌ WHOIS returned AVAILABLE (FALSE POSITIVE!)")
        elif whois == 'premium':
            print(f"   💰 WHOIS returned PREMIUM")
        elif whois == False:
            print(f"   ✅ WHOIS returned TAKEN (correct)")
        else:
            print(f"   ❓ WHOIS returned UNCERTAIN")
        
        time.sleep(2)  # Wait between checks
        
        # GoDaddy check
        print("\n3. GoDaddy Check:")
        godaddy, price = hunter.check_godaddy(domain)
        if godaddy == True:
            print(f"   ❌ GoDaddy says AVAILABLE (FALSE POSITIVE!)")
        elif godaddy == False:
            print(f"   ✅ GoDaddy says TAKEN (correct)")
        else:
            print(f"   ❓ GoDaddy returned {godaddy}")
        
        # Full comprehensive check
        print(f"\n4. Comprehensive Check (all sources):")
        result = hunter.comprehensive_check(domain)
        
        print(f"\n📊 FINAL VERDICT: ", end="")
        if result == 'available':
            print(f"❌ AVAILABLE (FALSE POSITIVE - this domain is actually taken!)")
        elif result == 'taken':
            print(f"✅ TAKEN (correct)")
        elif result == 'premium':
            print(f"💰 PREMIUM")
        else:
            print(f"❓ UNCERTAIN")
        
        print("\nAnalysis:")
        if result == 'available':
            print("⚠️ This is a FALSE POSITIVE. The domain is taken but marked as available.")
            print("Likely causes:")
            print("- Rate limiting returning empty/error responses")
            print("- WHOIS server issues")
            print("- Misinterpreting error messages as 'not found'")
        
        time.sleep(3)  # Delay between domains to avoid rate limits
    
    print(f"\n{'='*60}")
    print("INVESTIGATION COMPLETE")
    print(f"{'='*60}\n")
    
    print("Summary:")
    print("- If any showed as AVAILABLE, those are false positives")
    print("- The updated script should now catch these better")
    print("- Key improvements: rate limit detection, verification step, stricter consensus")
    
    # Test a domain that should actually be available
    print(f"\n{'='*60}")
    print("CONTROL TEST - Testing a likely available domain")
    print(f"{'='*60}\n")
    
    test_available = 'xqz9876.io'  # Very unlikely to be taken
    print(f"Testing: {test_available} (should be available)")
    
    result = hunter.comprehensive_check(test_available)
    print(f"\nResult: {result}")
    
    if result == 'available':
        print("✅ Correctly identified as available")
    else:
        print(f"Domain marked as {result}")

if __name__ == "__main__":
    test_false_positives()

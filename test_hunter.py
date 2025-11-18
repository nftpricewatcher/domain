#!/usr/bin/env python3
"""
Test script to verify domain checking functions before deployment
"""
import sys
import time
from domain_hunter_railway import DomainHunter

def test_domain_check():
    """Test the domain checking functions with known domains"""
    
    print("="*60)
    print("DOMAIN HUNTER - Function Test")
    print("="*60)
    
    hunter = DomainHunter()
    
    # Test domains - mix of taken and potentially available
    test_domains = [
        'google.com',  # Obviously taken
        'asdfghjkl123456789.com',  # Likely available
        'xyz.io',  # Likely taken (short)
        'qwerty987654321.io',  # Likely available
    ]
    
    print("\nTesting domain checking functions...\n")
    
    for domain in test_domains:
        print(f"Testing: {domain}")
        
        # DNS Check
        dns_result = hunter.quick_dns_check(domain)
        print(f"  DNS Check: {'Potentially available' if dns_result else 'Taken'}")
        
        # WHOIS Check
        whois_result = hunter.direct_whois_check(domain)
        if whois_result == True:
            print(f"  WHOIS: Available")
        elif whois_result == 'premium':
            print(f"  WHOIS: Premium/Brokered")
        elif whois_result == False:
            print(f"  WHOIS: Taken")
        else:
            print(f"  WHOIS: Unknown")
        
        # Comprehensive Check
        comprehensive_result = hunter.comprehensive_check(domain)
        print(f"  Comprehensive: {comprehensive_result}")
        
        print("-"*40)
        time.sleep(1)  # Rate limit
    
    print("\n✅ Test complete! If results look reasonable, you're ready to deploy.")
    print("\nExpected results:")
    print("  - google.com should show as 'taken'")
    print("  - Long random strings should show as 'available' or 'uncertain'")
    
    # Test state saving
    print("\nTesting state persistence...")
    hunter.state['test_value'] = 'test123'
    hunter.save_state()
    
    # Test results saving
    if hunter.comprehensive_check('asdfghjkl123456789.com') == 'available':
        test_domain = {
            'domain': 'test-domain.com',
            'length': 11,
            'found_at': str(time.time()),
            'status': 'test'
        }
        hunter.found_domains.append(test_domain)
        hunter.save_results()
        print("✅ State and results files created successfully")
    
    print("\nFiles created:")
    import os
    for file in ['hunter_state.json', 'found_domains.json']:
        if os.path.exists(file):
            print(f"  ✅ {file}")
        else:
            print(f"  ❌ {file}")

if __name__ == "__main__":
    try:
        test_domain_check()
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

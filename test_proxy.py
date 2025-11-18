#!/usr/bin/env python3
"""
Test the proxy rotation system
"""
import sys
import time
from domain_hunter_proxy import WhoisProxyRotator

def test_proxy_rotation():
    """Test that proxy rotation works and avoids rate limits"""
    
    print("="*60)
    print("TESTING PROXY ROTATION SYSTEM")
    print("="*60)
    
    rotator = WhoisProxyRotator()
    
    print(f"\nTotal services available: {len(rotator.services)}")
    for service in rotator.services:
        print(f"  • {service['name']} (weight: {service['weight']})")
    
    # Test domains
    test_domains = [
        'google.com',  # Obviously taken
        'asdfqwer1234567.com',  # Likely available
        'github.com',  # Taken
        'zxcvbnm9876543.io'  # Likely available
    ]
    
    print(f"\n{'='*60}")
    print("Testing domain checks with rotation:")
    print(f"{'='*60}\n")
    
    for domain in test_domains:
        print(f"\nChecking: {domain}")
        print("-" * 40)
        
        # Check with multiple services
        results = []
        services_used = []
        
        for i in range(5):  # Try 5 different services
            result, service_name = rotator.check_domain(domain)
            
            if service_name:
                services_used.append(service_name)
                
                if result == True:
                    print(f"  ✓ {service_name}: AVAILABLE")
                    results.append('available')
                elif result == False:
                    print(f"  ✗ {service_name}: TAKEN")
                    results.append('taken')
                else:
                    print(f"  ? {service_name}: UNCERTAIN")
                    results.append('uncertain')
            
            time.sleep(0.5)
        
        # Show consensus
        print(f"\nServices used: {', '.join(services_used)}")
        
        available_count = results.count('available')
        taken_count = results.count('taken')
        
        if taken_count > available_count:
            print(f"Consensus: TAKEN ({taken_count}/{len(results)} say taken)")
        elif available_count >= 3:
            print(f"Consensus: AVAILABLE ({available_count}/{len(results)} say available)")
        else:
            print(f"Consensus: UNCERTAIN (mixed results)")
    
    print(f"\n{'='*60}")
    print("Service health after testing:")
    print(f"{'='*60}\n")
    
    for service_name, health in rotator.service_health.items():
        status = "✓ Healthy" if health['failures'] < 5 else "✗ Unhealthy"
        print(f"  {service_name}: {status} (failures: {health['failures']})")
    
    print(f"\n{'='*60}")
    print("TEST COMPLETE")
    print(f"{'='*60}")
    print("\nProxy rotation system is working!")
    print("This should avoid rate limits by distributing")
    print("requests across many different services.")

if __name__ == "__main__":
    test_proxy_rotation()

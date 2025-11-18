#!/usr/bin/env python3
import json
import os
from datetime import datetime

def load_json_safe(filename):
    """Safely load JSON file"""
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except:
            return None
    return None

def main():
    print("="*60)
    print("DOMAIN HUNTER - Status Report")
    print("="*60)
    
    # Load state
    state = load_json_safe('hunter_state.json')
    if state:
        print("\n📊 Current Progress:")
        print(f"  • Current length: {state.get('current_length', 'N/A')} characters")
        print(f"  • Current TLD index: {state.get('current_tld_index', 'N/A')}")
        print(f"  • Total checked: {state.get('total_checked', 0):,}")
        print(f"  • Total found: {state.get('total_found', 0):,}")
        print(f"  • Last update: {state.get('last_update', 'N/A')}")
    else:
        print("❌ No state file found - hunter may not have started yet")
    
    # Load found domains
    domains = load_json_safe('found_domains.json')
    if domains:
        print(f"\n🎯 Found Domains ({len(domains)} total):")
        
        # Group by length
        by_length = {}
        for domain in domains:
            length = domain.get('length', 'unknown')
            if length not in by_length:
                by_length[length] = []
            by_length[length].append(domain)
        
        # Show grouped results
        for length in sorted(by_length.keys()):
            if length != 'unknown':
                print(f"\n  {length}-character domains ({len(by_length[length])}):")
                for d in by_length[length][:10]:  # Show max 10 per category
                    print(f"    • {d['domain']} - found {d.get('found_at', 'unknown time')}")
                if len(by_length[length]) > 10:
                    print(f"    ... and {len(by_length[length])-10} more")
    else:
        print("\n🔍 No domains found yet")
    
    # Check log file
    if os.path.exists('domain_hunter.log'):
        size = os.path.getsize('domain_hunter.log') / (1024*1024)  # MB
        print(f"\n📝 Log file size: {size:.2f} MB")
        
        # Show last few log lines
        try:
            with open('domain_hunter.log', 'r') as f:
                lines = f.readlines()
                recent = lines[-5:] if len(lines) >= 5 else lines
                print("\n📜 Recent log entries:")
                for line in recent:
                    print(f"  {line.strip()}")
        except:
            pass
    
    print("\n" + "="*60)
    
    # Save a formatted report
    report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_name, 'w') as f:
        f.write("DOMAIN HUNTER REPORT\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*60 + "\n\n")
        
        if state:
            f.write("PROGRESS:\n")
            f.write(f"  Total checked: {state.get('total_checked', 0):,}\n")
            f.write(f"  Total found: {state.get('total_found', 0):,}\n\n")
        
        if domains:
            f.write(f"FOUND DOMAINS ({len(domains)} total):\n")
            for d in domains:
                f.write(f"  {d['domain']} - {d.get('found_at', 'unknown')}\n")
    
    print(f"📄 Report saved to: {report_name}")

if __name__ == "__main__":
    main()

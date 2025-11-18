# Domain Hunter Configuration
# Copy this to config.py and adjust as needed

# Checking behavior
CHECK_MODE = "balanced"  # Options: "fast" (less accurate), "balanced", "thorough" (slower)

# Priority TLDs to check (order matters!)
PRIORITY_TLDS = [
    # Ultra-premium 2-letter TLDs
    'io', 'ai', 'me', 'co', 'to', 'so', 'sh', 'gg', 'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    
    # Premium 3-letter TLDs  
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot',
    
    # Other valuable TLDs
    'tech', 'info', 'link', 'live', 'site', 'club', 'cool', 'world', 'today', 'life'
]

# Character sets for different lengths
CHAR_SETS = {
    3: "abcdefghijklmnopqrstuvwxyz",  # Letters only for 3-char
    4: "abcdefghijklmnopqrstuvwxyz0123456789",  # Letters + numbers for 4+
    5: "abcdefghijklmnopqrstuvwxyz0123456789",
    6: "abcdefghijklmnopqrstuvwxyz0123456789"
}

# Rate limiting (seconds between checks)
RATE_LIMIT = {
    "fast": (0.2, 0.5),      # Min 0.2s, max 0.5s
    "balanced": (0.5, 1.5),   # Min 0.5s, max 1.5s  
    "thorough": (1.0, 2.0)    # Min 1s, max 2s
}

# Maximum character length to search
MAX_LENGTH = 6

# Minimum availability score to mark as available
# Lower = more false positives, Higher = more false negatives
AVAILABILITY_THRESHOLD = {
    "fast": 3,      # Need 3 points to mark available
    "balanced": 4,  # Need 4 points to mark available
    "thorough": 5   # Need 5 points to mark available
}

# Sources to check (can disable slow ones)
ENABLED_SOURCES = {
    "whois": True,
    "godaddy": True,
    "namecheap": True,
    "porkbun": True
}

# Notification settings
NOTIFICATIONS = {
    "discord_webhook": "",  # Add your Discord webhook URL
    "email": "",  # Future: email notifications
    "min_notify_length": 4  # Only notify for domains this short or shorter
}

# Debug settings
DEBUG_MODE = False  # Set True for verbose logging
SAVE_UNCERTAIN = True  # Save domains we're not sure about

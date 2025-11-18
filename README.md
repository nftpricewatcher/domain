# Domain Hunter - Railway Edition

## Overview
Automated domain availability checker that runs continuously on Railway, searching for the shortest available domains starting from 3 characters. It filters out premium/brokered domains and only reports truly available domains.

## Features
- ✅ 100% accuracy with multi-source verification
- 🚫 Filters out premium/brokered domains
- 📊 Persistent state (resumes where it left off)
- 🎯 Prioritizes short TLDs (.io, .ai, .me, .co, etc.)
- 📈 Progressive search (3 chars → 4 chars → 5 chars → 6 chars)
- 💾 Saves all found domains to JSON
- 📝 Comprehensive logging
- 🔄 Automatic restart on failure

## How It Works
1. Starts with 3-character domains
2. Checks priority TLDs in order (.io, .ai, .me, .co, etc.)
3. Quick DNS check to filter obvious taken domains
4. Multi-source verification (WHOIS, GoDaddy, Namecheap)
5. Filters out premium/aftermarket domains
6. Saves truly available domains
7. Moves to 4-char, 5-char, etc. progressively

## Railway Deployment Steps

### Option 1: Deploy via GitHub (Recommended)

1. **Fork/Upload to GitHub**
   - Create a new GitHub repository
   - Upload these files:
     - `domain_hunter_railway.py`
     - `requirements.txt`
     - `Procfile`
     - `check_status.py`

2. **Create Railway Project**
   - Go to [railway.app](https://railway.app)
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Connect your GitHub account if needed
   - Select your repository

3. **Configure Environment Variables (Optional)**
   - In Railway dashboard, go to your service
   - Click "Variables" tab
   - Add optional variables:
     ```
     DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
     ```

4. **Deploy**
   - Railway will automatically detect the Procfile and start deployment
   - The hunter will start running immediately after deployment

### Option 2: Deploy via Railway CLI

1. **Install Railway CLI**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway**
   ```bash
   railway login
   ```

3. **Initialize Project**
   ```bash
   railway init
   ```

4. **Link and Deploy**
   ```bash
   railway link
   railway up
   ```

### Option 3: Deploy with Docker

If you want more control, use the Dockerfile:

1. Upload all files including `Dockerfile` and `railway.json`
2. Railway will automatically detect and use Docker configuration

## Monitoring

### View Logs in Railway
- Go to your service in Railway dashboard
- Click "View Logs" to see real-time output

### Download Status Report
You can SSH into Railway or download the files:
- `found_domains.json` - All found available domains
- `hunter_state.json` - Current progress/state
- `domain_hunter.log` - Detailed logs

### Local Status Check
If you have Railway CLI:
```bash
railway run python check_status.py
```

## Files Explained

- **domain_hunter_railway.py** - Main hunter script
- **requirements.txt** - Python dependencies (just requests)
- **Procfile** - Tells Railway how to run the worker
- **Dockerfile** - Alternative Docker deployment
- **railway.json** - Railway configuration (optional)
- **check_status.py** - Monitor script to check progress

## Persistence Files (Created Automatically)

- **hunter_state.json** - Saves progress (current length, TLD, position)
- **found_domains.json** - List of all found available domains
- **domain_hunter.log** - Detailed activity log

## Configuration

Edit these in `domain_hunter_railway.py`:

```python
# Priority TLDs (order matters!)
PRIORITY_TLDS = [
    'io', 'ai', 'me', 'co', 'to', 'so', 'sh', 'gg', 'fm', 'am', 'is', 'it', 'tv', 'cc', 'ws',
    'com', 'net', 'org', 'app', 'dev', 'xyz', 'pro', 'biz', 'top', 'fun', 'art', 'bot',
    # Add more TLDs as needed
]

# Rate limiting (seconds between checks)
time.sleep(random.uniform(0.5, 1.5))  # Adjust as needed
```

## Cost Optimization

Railway charges based on usage. To minimize costs:

1. **Use Sleep Intervals**: The script has built-in delays (0.5-1.5 seconds)
2. **Set Resource Limits**: In Railway settings, you can limit CPU/RAM
3. **Schedule Downtime**: Use Railway's sleep feature during certain hours

## Notifications

To get notified when domains are found:

### Discord Webhook
1. Create webhook in Discord server
2. Add to Railway environment variables:
   ```
   DISCORD_WEBHOOK=your_webhook_url
   ```

### Email/SMS
Modify the `send_notification()` method in the script to add email or SMS alerts.

## Troubleshooting

### Hunter Stops/Crashes
- Railway will automatically restart it (configured in railway.json)
- State is saved, so it resumes where it left off

### Too Many Rate Limits
- Increase sleep time in the script
- Reduce number of TLDs being checked

### Not Finding Domains
- 3-character domains are extremely rare
- Let it run longer to reach 4-5 character domains
- Most available domains will be 5-6 characters

## Important Notes

1. **Legal**: Respect WHOIS rate limits and terms of service
2. **Patience**: Good domains are rare, especially short ones
3. **Cost**: Monitor Railway usage to avoid unexpected charges
4. **Premium Domains**: Script filters these out automatically

## Example Found Domains

The script will find domains like:
- `x7q.io` (3-char)
- `k9z2.me` (4-char)
- `tech5.ai` (5-char)

These are saved in `found_domains.json` with timestamps.

## Support

Check logs for errors:
```bash
railway logs
```

View current state:
```bash
railway run cat hunter_state.json
```

View found domains:
```bash
railway run cat found_domains.json
```

## License
Use at your own risk. Respect all applicable laws and terms of service.

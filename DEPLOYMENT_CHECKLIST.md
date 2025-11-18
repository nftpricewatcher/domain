# QUICK DEPLOYMENT CHECKLIST

## Before Deploying

✅ **Test Locally First:**
```bash
# Install dependencies
pip install requests

# Test the script works
python test_false_positives.py

# Should show all test domains as TAKEN (not available)
```

## Deploy to Railway

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Domain hunter with false positive fixes"
git remote add origin YOUR_GITHUB_REPO
git push -u origin main
```

### Step 2: Deploy on Railway
1. Go to [railway.app](https://railway.app)
2. New Project → Deploy from GitHub
3. Select your repo
4. It auto-detects Procfile and starts

### Step 3: Set Environment Variables (Optional)
In Railway dashboard → Variables:
```
LOG_LEVEL=INFO              # or DEBUG for more details
DISCORD_WEBHOOK=https://... # for notifications
```

### Step 4: Monitor
- View Logs: Railway dashboard → View Logs
- Check found domains: Download `found_domains.json`
- Check uncertain: Download `uncertain_domains.json`

## Files Created Automatically

These will be created on first run:
- ✅ `found_domains.json` - Truly available domains
- ✅ `uncertain_domains.json` - Need manual verification  
- ✅ `hunter_state.json` - Progress tracking
- ✅ `domain_hunter.log` - Activity log

## What to Expect

### First Hour
- Checking 3-character .io domains
- ~1000-2000 domains checked
- 0-1 domains found (3-char are rare!)

### First Day  
- Moves to .ai, .me, .co TLDs
- Starts 4-character domains
- 1-5 domains found typically

### First Week
- Reaches 5-character domains  
- 10-50 domains found
- More in uncertain list

## Warning Signs 🚨

**Good Pattern:**
```
Found domain: xyz9.io (4 chars) at 10:30
Found domain: ab7k.me (4 chars) at 14:22  
```
(Spread out, different TLDs)

**Bad Pattern (False Positives):**
```
Found domain: cnr.io (3 chars) at 10:30
Found domain: cnv.io (3 chars) at 10:31
```
(Too close together, same TLD = likely rate limited)

## If You See False Positives

1. Check the logs for "rate limit" warnings
2. Increase delays in the script
3. Set `LOG_LEVEL=DEBUG` to see what's happening
4. The script now auto-detects and re-verifies suspicious finds

## Quick Commands

### Check Status Remotely (Railway CLI)
```bash
railway run python check_status.py
```

### View Logs
```bash
railway logs
```

### Download Results
```bash
railway run cat found_domains.json
railway run cat uncertain_domains.json
```

## Success Metrics

- ✅ No domains found in rapid succession
- ✅ Found domains pass manual verification
- ✅ Uncertain list has some actual available domains
- ✅ No "rate limit detected" warnings in logs

## Remember

- 3-char domains: EXTREMELY rare (maybe 1 per week)
- 4-char domains: Rare (1-5 per day)
- 5-char domains: More common (5-20 per day)
- Better to miss some than get false positives!

---
Deploy and let it run! Check back in 24 hours for first results.

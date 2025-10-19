# Setup Commands

Copy/paste these commands to set up your repository:

## 1. Create Directory Structure

```bash
# Create project structure
mkdir -p cti-platform
cd cti-platform
mkdir -p src/integrations
mkdir -p frontend
mkdir -p docs
mkdir -p .github/workflows
```

## 2. Copy Files

Now copy/paste each file from the artifacts into these locations:

- `.gitignore` → root
- `README.md` → root
- `LICENSE` → root (edit copyright year/name)
- `CONTRIBUTING.md` → root
- `wrangler.toml` → root
- `package.json` → root (edit author/username)
- `.github/workflows/deploy.yml` → `.github/workflows/`
- `src/index.js` → use the backend code from artifact #2
- `frontend/index.html` → use the React UI from artifact #1

## 3. Initialize Git

```bash
git init
git add .
git commit -m "Initial commit: CTI Platform v1.0

- Frontend with multi-theme support and customization
- Cloudflare Worker backend with Durable Objects
- Crowdstrike Falcon integration
- IOC management API with CRUD operations
- KV caching layer for performance
- Complete documentation and contribution guidelines"
```

## 4. Create GitHub Repository

### Option A: Using GitHub CLI (easiest)
```bash
gh repo create cti-platform --public \
  --description "Enterprise Cyber Threat Intelligence platform with agentless IOC enrichment, threat actor tracking, and multi-source integration" \
  --source=. \
  --remote=origin \
  --push
```

### Option B: Manual
1. Go to https://github.com/new
2. Repository name: `cti-platform`
3. Description: `Enterprise Cyber Threat Intelligence platform with agentless IOC enrichment, threat actor tracking, and multi-source integration`
4. Public repository
5. **Don't** initialize with README (we already have one)
6. Click "Create repository"

Then run:
```bash
git remote add origin https://github.com/YOUR_USERNAME/cti-platform.git
git branch -M main
git push -u origin main
```

## 5. Add GitHub Topics

On your GitHub repo page, click the gear icon next to "About" and add these topics:
- `cybersecurity`
- `threat-intelligence`
- `ioc`
- `cloudflare-workers`
- `durable-objects`
- `security-automation`
- `soc`
- `siem`
- `mitre-attack`

## 6. Setup Cloudflare

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Create KV namespace
wrangler kv:namespace create "CTI_CACHE"
# Copy the ID and update wrangler.toml line 7
```

## 7. Configure Secrets

```bash
# Crowdstrike
wrangler secret put CROWDSTRIKE_CLIENT_ID
# Enter your client ID when prompted

wrangler secret put CROWDSTRIKE_CLIENT_SECRET
# Enter your client secret when prompted

# Add more secrets as needed:
wrangler secret put VIRUSTOTAL_API_KEY
wrangler secret put ABUSEIPDB_API_KEY
wrangler secret put SHODAN_API_KEY
```

## 8. Deploy

```bash
wrangler deploy
```

Your worker is now live! 🎉

## 9. Setup GitHub Actions (Optional)

For automatic deployments on push to main:

1. Get your Cloudflare API Token:
   - Go to https://dash.cloudflare.com/profile/api-tokens
   - Create Token → Edit Cloudflare Workers → Use template
   - Token name: "GitHub Actions Deploy"
   - Copy the token

2. Add to GitHub Secrets:
   - Go to your repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `CF_API_TOKEN`
   - Value: Paste your Cloudflare API token
   - Click "Add secret"

Now every push to `main` will auto-deploy!

## 10. What's Safe to Commit vs Secret

### ✅ SAFE TO COMMIT (already in repo):
- `wrangler.toml` (even with KV namespace ID)
- All code files
- Documentation
- Configuration (non-sensitive)

### ❌ NEVER COMMIT (use wrangler secrets or GitHub secrets):
- API keys (Crowdstrike, VirusTotal, etc.)
- Client secrets
- Personal access tokens
- `.env` files

### 🔐 GitHub Secrets (for CI/CD only):
- `CF_API_TOKEN` - For GitHub Actions to deploy

## Troubleshooting

### "Error: No namespace with id"
- Make sure you updated the KV namespace ID in `wrangler.toml`

### "Authentication failed"
- Run `wrangler login` again
- Check your Cloudflare account has Workers enabled

### "Module not found"
- Make sure `src/index.js` exists
- Check `main = "src/index.js"` in wrangler.toml

### Secrets not working
- Secrets are per-environment
- Make sure you're deploying to the right environment
- List secrets: `wrangler secret list`

## Next Steps

1. Test your deployment: `curl https://YOUR_WORKER.workers.dev/api/health`
2. Open the frontend and configure your org name/logo
3. Test IOC enrichment with Crowdstrike
4. Add more integrations (VirusTotal, AbuseIPDB, etc.)
5. Setup Cloudflare Access for authentication

Happy threat hunting! 🛡️
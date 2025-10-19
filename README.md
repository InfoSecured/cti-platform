# 🛡️ CTI Platform

Enterprise Cyber Threat Intelligence platform with agentless IOC enrichment, threat actor tracking, and multi-source integration. Built on Cloudflare Workers + Durable Objects.

## 🚀 Features

- **IOC Management** - Centralized repository for IPs, domains, hashes, and URLs
- **Multi-Source Enrichment** - Crowdstrike, VirusTotal, AbuseIPDB, Shodan, MISP, OpenCTI
- **Threat Actor Profiles** - Track APT groups with MITRE ATT&CK mapping
- **Incident Correlation** - Link indicators to active security incidents
- **Real-time Dashboard** - Live threat landscape visualization
- **Durable Storage** - IOCs persisted in Cloudflare Durable Objects
- **Customizable UI** - Multi-theme support with dark/light modes
- **Zero Trust Security** - Cloudflare Access with AD group integration

## 🏗️ Architecture

```
┌─────────────┐
│   Frontend  │ (React + Tailwind)
│  (Artifact) │
└──────┬──────┘
       │
       ↓
┌─────────────────────────────────────┐
│   Cloudflare Worker (Edge Runtime)  │
├─────────────────────────────────────┤
│  • API Routes                       │
│  • CORS Handling                    │
│  • Auth Middleware                  │
└──────┬──────────────────┬───────────┘
       │                  │
       ↓                  ↓
┌──────────────┐   ┌──────────────────┐
│ Durable      │   │   KV Store       │
│ Objects      │   │   (Cache)        │
│ (IOC Store)  │   │                  │
└──────────────┘   └──────────────────┘
       │
       ↓
┌─────────────────────────────────────┐
│   External Integrations (via Secrets)│
│  • Crowdstrike Falcon               │
│  • VirusTotal                       │
│  • AbuseIPDB                        │
│  • Shodan                           │
│  • MISP / OpenCTI                   │
└─────────────────────────────────────┘
```

## 📋 Prerequisites

- [Node.js](https://nodejs.org/) 18+ 
- [Cloudflare Account](https://dash.cloudflare.com/sign-up) (Free tier works!)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- API keys for integrations (Crowdstrike, VirusTotal, etc.)

## 🚀 Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/InfoSecured/cti-platform.git
cd cti-platform
npm install -g wrangler
wrangler login
```

### 2. Create KV Namespace

```bash
wrangler kv:namespace create "CTI_CACHE"
# Copy the ID output and update wrangler.toml
```

### 3. Configure Secrets

```bash
# Crowdstrike
wrangler secret put CROWDSTRIKE_CLIENT_ID
wrangler secret put CROWDSTRIKE_CLIENT_SECRET

# VirusTotal
wrangler secret put VIRUSTOTAL_API_KEY

# AbuseIPDB
wrangler secret put ABUSEIPDB_API_KEY

# Shodan
wrangler secret put SHODAN_API_KEY

# Add more as needed...
```

### 4. Update wrangler.toml

Edit `wrangler.toml` and replace `YOUR_KV_NAMESPACE_ID` with the ID from step 2.

### 5. Deploy

```bash
wrangler deploy
```

Your worker will be live at: `https://cti-platform.YOUR_SUBDOMAIN.workers.dev`

### 6. Setup Cloudflare Access (Optional)

For Active Directory integration and role-based access:

1. Go to [Zero Trust Dashboard](https://one.dash.cloudflare.com/)
2. Create Access Application for your worker domain
3. Add policies with AD groups:
   - `CTI_ANALYSTS` - Read-only access
   - `CTI_MANAGERS` - Read + Write access
   - `CTI_ADMINS` - Full admin access

See [docs/CLOUDFLARE_ACCESS.md](docs/CLOUDFLARE_ACCESS.md) for detailed setup.

## 📖 API Documentation

### Health Check
```bash
GET /api/health
```

### Store IOC
```bash
POST /api/ioc/store
Content-Type: application/json

{
  "indicator": "192.168.1.100",
  "type": "ip",
  "threatLevel": "high",
  "source": "manual"
}
```

### List IOCs
```bash
GET /api/ioc/list?type=ip&limit=50&offset=0
```

### Get Specific IOC
```bash
GET /api/ioc/get?indicator=192.168.1.100
```

### Enrich IOC
```bash
GET /api/enrich?indicator=192.168.1.100&type=ip&source=crowdstrike
```

Supported sources: `crowdstrike`, `virustotal`, `abuseipdb`, `shodan`

## 🎨 Frontend Customization

The frontend supports:
- **Custom Logo Upload** - Upload your organization's logo
- **Color Schemes** - 4 built-in themes (Cyber Red, Security Blue, Tactical Purple, Defense Green)
- **Dark/Light Mode** - Toggle between modes
- **Organization Name** - Customize platform branding

All preferences are stored in browser localStorage.

## 🔧 Development

### Local Development
```bash
wrangler dev
```

### Add New Integration

1. Add secret:
```bash
wrangler secret put NEWSERVICE_API_KEY
```

2. Create integration class in `src/integrations/newservice.js`:
```javascript
export class NewServiceIntegration {
  constructor(env) {
    this.env = env;
    this.apiKey = env.NEWSERVICE_API_KEY;
  }

  async enrichIOC(indicator, type) {
    // Your implementation
  }
}
```

3. Register in `src/index.js`

See [docs/ADDING_INTEGRATIONS.md](docs/ADDING_INTEGRATIONS.md) for details.

## 🔐 Security

- **No Secrets in Code** - All credentials stored in Cloudflare Secrets
- **CORS Protection** - Configurable origin restrictions
- **Rate Limiting** - Built-in KV-based rate limiting
- **Audit Logging** - All IOC operations logged
- **Encryption at Rest** - Durable Objects encrypted by default

## 📊 Roadmap

- [ ] GraphQL API
- [ ] STIX/TAXII 2.1 support
- [ ] Automated playbook execution
- [ ] Slack/Teams alerting
- [ ] MITRE ATT&CK Navigator integration
- [ ] ML-based threat scoring
- [ ] Export to SIEM (Splunk, Elastic)
- [ ] Malware sandbox integration (Cuckoo, Any.Run)

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on [Cloudflare Workers](https://workers.cloudflare.com/)
- UI powered by [React](https://react.dev/) + [Tailwind CSS](https://tailwindcss.com/)
- Icons by [Lucide](https://lucide.dev/)
- Inspired by MISP, OpenCTI, and the threat intelligence community

## 📧 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/InfoSecured/cti-platform/issues)
- 💬 [Discussions](https://github.com/InfoSecured/cti-platform/discussions)

---

Made with 🛡️ for the security community
# AgenticPhishDetector

> AI-powered multi-agent phishing email detection using LangGraph + NVIDIA Nemotron-3-ultra-550b-a55b model. 

```
AgenticPhishDetector
├── React SPA (e.g. Cloudflare Pages)
│   
└── FastAPI + LangGraph Agent Pipeline
    ├── Supervisor (Nemotron LLM) → decides tools
    ├── HeaderParser → email metadata analysis
    ├── WHOISTool → domain age/registrar lookup
    ├── URLScanner → URLScan.io public search
    ├── Heuristics → rule-based NLP patterns
    └── FinalVerdict (Nemotron LLM) → synthesized verdict
```

## Features

- **Multi-agent pipeline**: LangGraph StateGraph orchestrates 4 specialized tools + 2 LLM calls
- **Free tools only**: No API keys needed for WHOIS, URL scanning, header parsing, or heuristics
- **Real-time analysis**: Submit any email and get verdict (PHISHING/SUSPICIOUS/LEGITIMATE) with confidence score
- **Highlighted evidence**: Character-offset spans highlight phishing indicators in the email body
- **Per-tool reasoning**: Expandable cards show each tool's findings and risk assessment
- **AI reasoning trace**: View the LLM's chain-of-thought reasoning
- **Example emails**: Pre-included phishing and legitimate examples for quick testing

## Prerequisites

- **Node.js** 20+
- **Python** 3.11+
- **NVIDIA API key** (free at [build.nvidia.com](https://build.nvidia.com))

## Local Development

### Backend

```bash
cd backend

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
copy .env.example .env
# Edit .env with your NVIDIA_API_KEY

# Run the server
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000/api/docs`.

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Run dev server (proxies /api to localhost:8000)
npm run dev
```

The app will be available at `http://localhost:5173/agenticphishdetector/`.

## Environment Variables

| Variable | Description | Required |
|---|---|---|
| `NVIDIA_API_KEY` | NVIDIA NIM API key for Nemotron model | Yes |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | Yes |
| `RATE_LIMIT_PER_MINUTE` | Max API requests per IP per minute | No (default: 10) |
| `MAX_BODY_LENGTH` | Max email body characters | No (default: 50000) |
| `WORKER_SECRET` | Shared secret for Cloudflare Worker auth | Production only |

## Deployment

### Frontend (Cloudflare Pages)

1. Connect GitHub repo to Cloudflare Pages
2. Build command: `cd frontend && npm install && npm run build`
3. Output directory: `frontend/dist`
4. Set `BACKEND_ORIGIN` in `wrangler.toml`
5. Deploy the Worker proxy: `cd frontend && npx wrangler deploy`

### Backend (Fly.io / Railway / Render)

```bash
cd backend
# Deploy with Docker
fly launch --dockerfile Dockerfile
fly secrets set NVIDIA_API_KEY=your-key
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyze a single email for phishing |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/docs` | Swagger UI documentation |

## Security

- NVIDIA API key stored only in backend `.env`, never exposed to frontend
- All user input sanitized (HTML stripped, truncated, validated)
- Prompt injection protection with explicit content delimiters
- Rate limiting at both Cloudflare Worker edge and FastAPI levels
- CORS whitelist restricts origins

## Testing

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Frontend build check
cd frontend
npm run build
```

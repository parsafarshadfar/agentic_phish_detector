# AgenticPhishDetector

> AI-powered multi-agent phishing email detection using LangGraph + NVIDIA Nemotron-3-ultra-550b-a55b model. 


# Demo  
Check out the live demo: 
[https://agenticphishdetector.parsafarshadfar.com/](https://agenticphishdetector.parsafarshadfar.com/) or
[https://agenticphishdetector.pages.dev/](https://agenticphishdetector.pages.dev/)

 

![AgenticPishDetector DEMO](/AgenticPishDetectorDEMO.jpg)

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

# Create virtual environment (only first time)
python -m venv .venv

#Activate virtual environment
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux

# Install dependencies (only first time)
pip install -r requirements.txt

# Copy and configure environment (only first time)
copy .env.example .env
# Edit .env with your personal NVIDIA_API_KEY

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

## Online Deployment

### 1. Backend (Render)
- Deploy using the repository's Blueprint (`render.yaml`).
- Set environment variables: `NVIDIA_API_KEY`, `WORKER_SECRET`, and `ALLOWED_ORIGINS`.

### 2. Frontend (Cloudflare Pages)
- Connect repository, configure root directory to `frontend`, build command to `npm run build`, and output directory to `dist`.
- Set environment variables: `BACKEND_ORIGIN` and `WORKER_SECRET` (encrypted).

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyze a single email for phishing |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/docs` | Swagger UI documentation |

## Security

- NVIDIA API key stored only in backend `.env`, never exposed to frontend
- Shared `WORKER_SECRET` authentication header secures backend-frontend communication and prevents unauthorized direct API access
- Input sanitization: User inputs undergo a strict pipeline—HTML tags are stripped using `bleach` to prevent cross-site scripting (XSS) and injection attacks, text is truncated (50k characters for body, 500 for subject) to prevent Denial of Service (DoS) and context overflow, and email addresses are structurally validated via RFC-compliant patterns.
- Prompt injection protection: email inputs are strictly encapsulated within explicit `--- BEGIN EMAIL CONTENT (untrusted) ---` and `--- END EMAIL CONTENT ---` boundaries in LLM prompts, with system instructions enforcing that content inside the delimiters is treated as data, not instructions.
- Layered rate limiting: Request rates are constrained at the edge via Cloudflare Workers (using the `RATE_LIMITER` binding to filter traffic by IP before forwarding) and at the application layer via FastAPI (using SlowAPI to track and restrict client remote IP requests).

## Testing

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Frontend build check
cd frontend
npm run build
```

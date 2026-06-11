# AgenticPhishDetector Backend

The backend of AgenticPhishDetector is a Python-based REST API built with FastAPI. It leverages LangGraph and Nvidia's Nemotron-3-ultra-550b-a55b model (via LangChain) to perform agentic, AI-driven analysis of suspicious emails to detect phishing attempts.

## Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/)
- **Server**: [Uvicorn](https://www.uvicorn.org/)
- **Agent Orchestration**: [LangGraph](https://python.langchain.com/v0.1/docs/langgraph/) & [LangChain](https://python.langchain.com/)
- **LLM Provider**: NVIDIA AI Endpoints (NVIDIA's Nemotron-3-ultra-550b-a55b model) 
- **Rate Limiting**: [SlowAPI](https://slowapi.readthedocs.io/en/latest/)
- **Security & Validation**: Pydantic, Bleach
- **Testing**: Pytest

## Directory Structure

```text
backend/
├── agent/                # LangGraph agents and LLM logic
├── routers/              # FastAPI route handlers (e.g., /api/analyze)
├── tests/                # Pytest test cases
├── config.py             # Application configuration (Pydantic Settings)
├── main.py               # FastAPI application entrypoint
├── security.py           # Security utilities and configuration
├── requirements.txt      # Python dependencies
└── Dockerfile            # Container configuration
```

## Setup & Installation

1. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables:**
   Create a `.env` file in the `backend` directory. Ensure you have the necessary NVIDIA API key and other configurations.
   ```env
   # Example .env content
   NVIDIA_API_KEY=your_nvidia_api_key_here
   ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000,https://yourdomain.com
   RATE_LIMIT_PER_MINUTE=3
   MAX_BODY_LENGTH=50000
   MAX_SUBJECT_LENGTH=500
   WORKER_SECRET=REPLACE_WITH_A_STRONG_RANDOM_SECRET
   DEBUG=false
   ```

## Running the Application

To run the development server:

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

### API Documentation

Once the server is running, you can access the automatically generated API documentation:
- **Swagger UI**: `http://localhost:8000/api/docs`
- **ReDoc**: `http://localhost:8000/api/redoc`

## Key Endpoints

- `GET /api/health`: Health check endpoint. Returns API status and configured model.
- `POST /api/analyze`: Endpoint to submit email data for phishing analysis.

## Security

The application uses SlowAPI for per-IP rate limiting to prevent abuse. Cross-Origin Resource Sharing (CORS) is configured to only allow requests from specific origins defined in the settings. Additional security headers are appended to all responses via middleware.

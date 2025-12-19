# CyberSentinel - Cognitive Cybersecurity AI Agent

## Overview
CyberSentinel is an advanced AI agent designed to mimic a security analyst's reasoning. It evaluates URLs using a multi-layer approach:
1. **Lexical Analysis**: Entropy and DGA detection.
2. **Infrastructure Analysis**: DNS, Whois age, and API reputation (VirusTotal).
3. **Visual Perception**: Visual spoofing detection using CLIP comparisons.
4. **Cognitive Core**: LLM-based final verdict (LangGraph).

## Prerequisites
- **Python 3.10+** (managed by `uv`)
- **Docker** & **Docker Compose**

## Installation

1. **Clone & Setup**:
   ```bash
   git clone <repo>
   cd CyberSentinel
   uv sync
   ```

2. **Environment Variables**:
   Copy `.env.example` to `.env` and fill in your API keys (OpenAI, VirusTotal, etc.).
   ```bash
   cp .env.example .env
   ```

3. **Start Infrastructure**:
   ```bash
   docker compose up -d
   ```

4. **Initialize Visual Database** (Optional but recommended):
   ```bash
   uv run src/scripts/setup_visual_db.py
   ```

## Running the API

Start the FastAPI server:
```bash
uv run uvicorn src.main:app --reload
```
The API will be available at `http://localhost:8000`.

- **Swagger UI**: `http://localhost:8000/docs`

## Testing

Run the included verification scripts:
- **Infrastructure**: `uv run src/scripts/verify_infra.py`
- **Workflow**: `uv run src/scripts/test_workflow.py`
- **API**: `uv run src/scripts/test_api.py`

## Architecture
- `src/analysis`: Core analysis modules (Lexical, Visual, Infra).
- `src/workflow`: LangGraph state machine definition.
- `src/api`: FastAPI routes and models.

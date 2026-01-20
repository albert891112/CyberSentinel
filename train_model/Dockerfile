FROM python:3.11-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy project files
COPY pyproject.toml .
COPY *.py .

# Install dependencies using uv
RUN uv sync --frozen --no-dev

# Create models directory
RUN mkdir -p /app/models

CMD ["uv", "run", "python", "train_lexical_model.py"]

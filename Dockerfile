FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app.py .
COPY agents/ ./agents/
COPY tools/ ./tools/
COPY mcp/ ./mcp/
COPY frontend/ ./frontend/
COPY backend/ ./backend/

# Expose FastAPI default port
EXPOSE 8000

# Set environment variable to run python unbuffered
ENV PYTHONUNBUFFERED=1

# Command to run the FastAPI app
CMD ["python", "app.py"]

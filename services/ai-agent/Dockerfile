FROM python:3.11-slim
WORKDIR /app
RUN pip install anthropic pyyaml
COPY ai_agent.py .
CMD ["python", "ai_agent.py"]

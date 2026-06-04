FROM python:3.11-slim
WORKDIR /app
RUN pip install anthropic
COPY few_shot.py .
CMD ["python", "few_shot.py"]

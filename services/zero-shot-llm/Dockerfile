FROM python:3.11-slim
WORKDIR /app
RUN pip install anthropic
COPY zero_shot.py .
CMD ["python", "zero_shot.py"]
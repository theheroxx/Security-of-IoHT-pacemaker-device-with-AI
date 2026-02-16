FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

ENV PYTHONPATH=/app/logs
EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", "dashboard/master_dashboard.py", "--server.address=0.0.0.0", "--server.port=8501"]

FROM python:3.12-slim

# Install nmap system binary
RUN apt-get update && apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_DEBUG=false
ENV SECRET_KEY=change-me-in-production

EXPOSE 5000

CMD ["python", "app.py"]

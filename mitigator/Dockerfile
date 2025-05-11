FROM python:3.11-slim

# Install dependencies
RUN pip install exabgp flask python-dotenv jinja2

ENV PYTHONUNBUFFERED=1
ENV EXABGP_LOG_ALL=true
ENV EXABGP_LOG_LEVEL=INFO
ENV EXABGP_API_ENCODER=json

# Create required directories and named pipes
RUN mkdir -p /app/run && \
    # Create file for metrics
    touch /var/log/blackholes.json && \
    chmod 666 /var/log/blackholes.json && \
    # Create pipes for exabgp
    mkfifo /run/exabgp.in /run/exabgp.out && \
    chmod 777 /run/exabgp.in /run/exabgp.out && \
    mkdir -p /usr/local/etc/exabgp && \
    exabgp --fi > /usr/local/etc/exabgp/exabgp.env

WORKDIR /app
COPY . /app

EXPOSE 5000
EXPOSE 179

CMD ["python", "mitigator.py"]

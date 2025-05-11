FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the app
COPY preprocessor.py .
COPY config.py .
COPY utils.py .
COPY external_checks.py .

# Expose the UDP port
EXPOSE 5514/udp

# Default command
CMD ["python", "preprocessor.py"]

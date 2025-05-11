FROM python:3.11-slim

# Install build dependencies (psycopg2, sqlite etc.)
RUN apt-get update && apt-get install -y \
    libpq-dev gcc python3-dev sqlite3 libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the app
COPY preprocessor.py .
COPY config.py .
COPY utils.py .


# Default command
CMD ["python", "preprocessor.py"]

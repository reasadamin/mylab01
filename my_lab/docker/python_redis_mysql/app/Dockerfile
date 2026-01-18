# Stage1: Build App
FROM python:3.11-slim as builder

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install --user -r requirements.txt

#Stage2: Runtime
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /root/.local /root/.local

ENV PATH="/root/.local/bin:$PATH"
ENV PYTHONPATH="/root/.local/lib/python3.11/site-packages"

COPY . . 

CMD ["python", "main.py"] 
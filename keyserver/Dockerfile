FROM python:3.12-slim

WORKDIR /app
COPY keyserver /app/keyserver

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8765

CMD ["python3", "-m", "keyserver.ende_keyserver"]

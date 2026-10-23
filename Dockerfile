FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY app/server.py /app/server.py
RUN addgroup -S app && adduser -S -G app -u 10001 app && mkdir -p /data && chown -R app:app /data /app
USER 10001:10001
EXPOSE 18082
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18082/health',timeout=3)"
CMD ["python", "/app/server.py"]

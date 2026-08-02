FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /srv
COPY client.py .
RUN useradd -r -u 10002 victim && mkdir -p /data && chown victim /data
USER victim
CMD ["python", "client.py"]

# Backend « portail » commun à toutes les cibles. Le TLS est TERMINÉ EN AMONT
# par le front-end vulnérable propre à chaque challenge (nginx/apache/openssl) ;
# ce conteneur ne sert donc qu'en clair sur le réseau interne du lab.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py challenges.py crypto_utils.py ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data/keys && useradd -r -u 10001 lab && chown -R lab /srv /data
USER lab

EXPOSE 5000
# 2 workers suffisent pour un TP ; le flag mémoire (C5) reste résident par worker.
CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "8", \
     "--timeout", "120", "--graceful-timeout", "30", \
     "-b", "0.0.0.0:5000", "app:app"]

# C0 — cible de reconnaissance. nginx minimal servant le flag dans le titre HTML,
# sur un port non standard (9000) à découvrir au scan nmap.
FROM nginx:1.27-alpine
COPY default.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN rm -f /etc/nginx/conf.d/default.conf.default 2>/dev/null || true; chmod +x /entrypoint.sh
EXPOSE 9000
ENTRYPOINT ["/entrypoint.sh"]

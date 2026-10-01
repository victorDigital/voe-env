FROM postgres:17

COPY docker-entrypoint.sh /usr/local/bin/voe-db-entrypoint.sh

ENTRYPOINT ["sh", "/usr/local/bin/voe-db-entrypoint.sh"]
CMD ["postgres"]

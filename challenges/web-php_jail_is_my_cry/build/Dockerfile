FROM php:8.3.0-fpm

COPY --chmod=755 files/readflag /readflag
RUN chmod u+s /readflag

RUN apt-get update && apt-get install -y \
    nginx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/nginx /var/log/nginx \
    && usermod -u 1000 www-data \
    && groupmod -g 1000 www-data \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log


COPY config/nginx.conf /etc/nginx/sites-available/default
RUN rm -f /etc/nginx/sites-enabled/default && \
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
COPY --chmod=500 files/init.sh /init.sh


COPY config/php.ini /usr/local/etc/php/php.ini
COPY src/ /var/www/html/

EXPOSE 80
ENTRYPOINT ["/init.sh"]
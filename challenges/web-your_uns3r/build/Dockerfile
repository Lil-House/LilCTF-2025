FROM php:5.6-fpm-alpine

RUN  apk add --no-cache shadow nginx && mkdir -p /run/nginx && \
     usermod -u 1000 www-data && \
     groupmod -g 1000 www-data && \
     sed -i 's/worker_processes auto;/worker_processes 1;/' /etc/nginx/nginx.conf

COPY config/php.ini /usr/local/etc/php/conf.d/php.ini
COPY config/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=www-data:www-data src/ /var/www/html/
RUN  chown -R www-data:www-data /var/www/html
COPY --chmod=500 service/init.sh /init.sh

EXPOSE 80

CMD ["/init.sh"]
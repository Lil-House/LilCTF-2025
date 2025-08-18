FROM ghcr.io/gzctf/challenge-base/flask:alpine

RUN apk add --no-cache nginx && \
    chown -R ctf:ctf /var/lib/nginx /var/log/nginx /run/nginx && \
    sed -i 's/worker_processes auto;/worker_processes 1;/' /etc/nginx/nginx.conf && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

COPY src/nginx.conf /etc/nginx/http.d/default.conf

COPY --chown=ctf:ctf --chmod=500 src/init.sh src/serve.py /home/ctf/

WORKDIR /home/ctf
USER ctf

CMD ["./init.sh"]

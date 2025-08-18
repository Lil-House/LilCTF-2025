FROM ubuntu:22.04 AS builder

FROM ghcr.io/gzctf/challenge-base/socat:alpine

COPY src/start.sh /start.sh

RUN cp -R /lib* /home/ctf && \
    mkdir /home/ctf/dev  && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/* && \
    mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    cp /bin/base64 /home/ctf/bin && \
    chmod +x /start.sh

WORKDIR /home/ctf

COPY --from=builder /lib64/ld-linux-x86-64.so.2 /home/ctf/lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /home/ctf/lib/x86_64-linux-gnu/

COPY --chmod=500 --chown=ctf:ctf src/vuln ./vuln

CMD ["/start.sh"]

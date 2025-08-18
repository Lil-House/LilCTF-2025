FROM ubuntu:24.04 AS builder

FROM ghcr.io/gzctf/challenge-base/socat:alpine

COPY src/start.sh /start.sh
COPY src/run.sh /run.sh

WORKDIR /home/ctf/

COPY src/chtest /home/ctf

RUN chmod +x /start.sh          && \
    chmod +x /run.sh          && \
    chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf      && \
    chmod +s /home/ctf/chtest   && \
    mkdir /lib/x86_64-linux-gnu/

COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libseccomp.so.2.5.5 /lib/x86_64-linux-gnu/libseccomp.so.2


CMD ["/start.sh"]

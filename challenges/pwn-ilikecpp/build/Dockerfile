FROM ubuntu:24.04 AS builder

FROM ghcr.io/gzctf/challenge-base/socat:alpine

COPY src/start.sh /start.sh

WORKDIR /home/ctf/

COPY src/pwn /home/ctf

RUN chmod +x /start.sh          && \
    chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf      && \
    chmod +x /home/ctf/pwn

COPY --from=builder /lib64/ld-linux-x86-64.so.2 /home/ctf/lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /home/ctf/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libstdc++.so.6 /home/ctf/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /home/ctf/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libm.so.6 /home/ctf/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /home/ctf/lib/x86_64-linux-gnu/

CMD ["/start.sh"]

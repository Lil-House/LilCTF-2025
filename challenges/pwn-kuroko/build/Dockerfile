FROM ubuntu:24.04 AS builder

RUN apt update && \
    apt --no-install-recommends install -y make gcc gcc-multilib git ca-certificates

RUN git clone --depth=1 https://github.com/kuroko-lang/kuroko.git && \
    cd kuroko && \
    git checkout 05d30e8d5e5ecd36fe37ff5067fa30ae992b3319 && \
    make

FROM ghcr.io/gzctf/challenge-base/readflag:latest AS readflag

FROM ghcr.io/gzctf/challenge-base/socat:alpine

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
    cp /bin/base64 /home/ctf/bin

COPY --chmod=500 src/start.sh /start.sh
COPY --chmod=500 --chown=ctf:ctf src/run.sh /home/ctf/run.sh
COPY --from=builder /lib64/ld-linux-x86-64.so.2 /home/ctf/lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /home/ctf/lib/x86_64-linux-gnu/
COPY --from=readflag --chown=root:root /readflag /home/ctf/readflag
COPY --from=builder --chmod=500 --chown=ctf:ctf /kuroko/kuroko /home/ctf/kuroko

COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /usr/sbin/chroot /chroot

CMD ["/start.sh"]

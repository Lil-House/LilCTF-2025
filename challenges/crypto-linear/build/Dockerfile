FROM ghcr.io/gzctf/challenge-base/python:alpine

COPY --chown=ctf:ctf --chmod=500 src/chall.py /home/ctf/chall.py
COPY --chown=ctf:ctf --chmod=500 src/init.sh /init.sh

CMD ["/init.sh"]

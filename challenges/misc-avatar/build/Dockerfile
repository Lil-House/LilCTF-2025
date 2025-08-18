FROM ghcr.io/gzctf/challenge-base/flask:alpine

RUN pip install --no-cache-dir pillow

COPY --chown=ctf:ctf --chmod=700 src/ /home/ctf/

USER ctf
WORKDIR /home/ctf

CMD ["./init.sh"]

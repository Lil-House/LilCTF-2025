FROM ghcr.io/gzctf/challenge-base/python:alpine

RUN pip install --no-cache-dir flask werkzeug flask_sqlalchemy requests

COPY --chown=ctf --chmod=700 src /home/ctf/app/
COPY --chown=ctf --chmod=744 flag /flag

WORKDIR /home/ctf/app

EXPOSE 5000

CMD ["./init.sh"]

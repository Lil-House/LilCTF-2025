# pylint: disable=missing-module-docstring,missing-function-docstring

import os
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "<h1>Hello, CTFer!</h1>"


@app.route("/secret")
def secret():
    return os.getenv("LILCTF_FLAG", "LILCTF{default}")


if __name__ == "__main__":
    app.run("0.0.0.0", 8080, debug=False)

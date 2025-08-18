from flask import Flask, make_response, send_file

app = Flask(__name__)


@app.route("/api/file/download/72ddc765-caf6-43e3-941e-eeddf924f8df", methods=["GET"])
def test():
    with open("avatar.png", "rb") as f:
        data = f.read()
    res = make_response(data)
    res.headers["Content-Length"] = "10086"
    res.headers["Content-Type"] = "image/webp"
    res.headers["Content-Disposition"] = 'attachment; filename="avatar.webp"'
    res.headers["Connection"] = "keep-alive"
    return res


@app.route("/", methods=["GET"])
def index():
    return send_file("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", 8080, debug=False)

import subprocess
from flask import Flask, request, send_from_directory

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return send_from_directory(".", "index.html")


@app.route("/Coloringoutomic_Host.mp3", methods=["GET"])
def first_file():
    return send_from_directory(".", "Coloringoutomic_Host.mp3")


@app.route("/bestudding.jpg", methods=["GET"])
def second_file():
    return send_from_directory(".", "bestudding.jpg")


@app.route("/whereami", methods=["POST"])
def report_host():
    data = request.get_data(as_text=True)
    if not data:
        return "No data received", 400
    if len(data) > 64:
        return "Data too long", 400
    if not all(32 < ord(c) < 127 for c in data):
        return "Invalid data received", 400
    try:
        subprocess.run(
            ["python", "/home/ctf/passive-gen.py", data], check=True, timeout=5
        )
    except:
        return "Error running script", 500
    return "OK", 200


if __name__ == "__main__":
    app.run("0.0.0.0", 80, debug=False)

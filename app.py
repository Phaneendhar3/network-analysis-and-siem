from flask import Flask,render_template
from backend.device_discovery import discover_devices
app=Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/devices")
def devices():
    devices=discover_devices()
    return render_template("devices.html",devices=devices)

@app.route("/siem")
def siem():
    return "<h2>SIEM module coming soon</h2>"

if __name__=="__main__":
    app.run(debug=True)
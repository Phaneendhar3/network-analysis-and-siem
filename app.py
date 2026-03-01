from flask import Flask,render_template,jsonify
from backend.device_discovery import discover_devices,detect_os,get_active_ip
app=Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/devices")
def devices():
    devices=discover_devices()
    local_ip = get_active_ip()
    return render_template("devices.html", devices=devices, local_ip=local_ip)

@app.route("/api/detect-os/<ip>")
def detect_os_api(ip):
    os_info=detect_os(ip)
    return jsonify({"ip":ip,"os":os_info})

@app.route("/siem")
def siem():
    return "<h2>SIEM module coming soon</h2>"

@app.route("/devices/<ip>")
def device_details(ip):
    os_info=detect_os(ip)
    return render_template(
        "device_details.html",
        ip=ip,
        os_info=os_info,
        show_devices=True
    )

if __name__=="__main__":
    app.run(debug=True)
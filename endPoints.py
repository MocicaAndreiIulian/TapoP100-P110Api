import logging

from PyP100 import PyP110
from flask import Flask, jsonify, request, Response

log = logging.getLogger(__name__)
app = Flask(__name__)


@app.route('/switchStatus/<int:status>/<ip>', methods=['POST'])
def switchStatus(status, ip):
    p110 = PyP110.P110(ip, "email", "pass")

    p110.handshake()
    p110.login()
    try:
        if status:
            p110.turnOn()
        else:
            p110.turnOff()
        return Response(status=200)
    except:
        return Response(status=500)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

#!/usr/bin/env python3
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__)
CORS(app)

# Route pour le dashboard
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Route pour les fichiers statiques (CSS, JS, etc.)
@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

# API pour récupérer les données des agents (via api.json)
@app.route('/api/data')
def api_data():
    try:
        with open('api.json', 'r') as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"active_nodes": []})

# API pour lancer une attaque
@app.route('/api/attack', methods=['POST'])
def api_attack():
    subprocess.Popen(["./test_attack.sh", "--force"])
    return jsonify({"status": "attack_launched", "message": "🔥 Attaque simulée en cours"})

# API pour récupérer les logs
@app.route('/api/logs')
def api_logs():
    try:
        with open('api.json', 'r') as f:
            data = json.load(f)
            return jsonify(data.get('logs', []))
    except:
        return jsonify([])

# API pour récupérer le statut du système
@app.route('/api/status')
def api_status():
    return jsonify({
        "c2_online": os.path.exists('api.json'),
        "websocket_port": 8081,
        "dashboard_version": "3.0"
    })

if __name__ == '__main__':
    print("🚀 NEURO-MESH Web Server démarré")
    print("📡 Dashboard: http://localhost:5000")
    print("⚔️ Interface de commandement prête")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# NEURO-MESH : C2 BRIDGE API (Web-to-System Execution)
# ============================================================

import http.server
import socketserver
import subprocess
import json
import os

PORT = 5000

class ThreatAPIHandler(http.server.SimpleHTTPRequestHandler):
    
    # Gestion des règles CORS (Pour autoriser React à parler à cette API)
    def do_OPTIONS(self):
        self.send_response(200, "ok")
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-type')
        self.end_headers()

    def do_POST(self):
        if self.path == '/api/attack':
            try:
                # Vérification de l'existence du script d'attaque
                if not os.path.exists("./test_attack.sh"):
                    raise FileNotFoundError("Le script test_attack.sh est introuvable.")

                # Exécution asynchrone du script bash
                subprocess.Popen(["./test_attack.sh", "--force"])
                
                # Réponse de succès au Dashboard
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "attack_launched"}).encode())
                print("\n\033[1;31m[API] 💣 Ordre d'attaque reçu depuis le Dashboard ! Lancement du payload...\033[0m")
                
            except Exception as e:
                # Gestion des erreurs
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                print(f"\n\033[1;33m[ERREUR API] {str(e)}\033[0m")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    try:
        # Configuration pour réutiliser le port immédiatement après un arrêt
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", PORT), ThreatAPIHandler) as httpd:
            print(f"\033[1;36m[BRIDGE] 🌉 API de pont en écoute sur le port {PORT}...\033[0m")
            print("\033[1;32m[STATUS] Le bouton 'INJECT THREAT' du Dashboard est connecté au système Linux.\033[0m")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[1;33m[BRIDGE] Arrêt de l'API.\033[0m")

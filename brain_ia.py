#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# NEURO-MESH CORTEX IA : ULTIMATE FINAL EDITION (PERFECT TIMING)
# ============================================================
# Auteur : El Yazid
# Description : Isolation Forest 5D avec entraînement périodique,
#               modèles conservés en mémoire ET sur disque (joblib),
#               prédiction à chaque cycle, garbage collection optimisé.
# ============================================================

import json
import time
import numpy as np
from sklearn.ensemble import IsolationForest
import os
from collections import deque
import joblib

# ============================================================
# CONFIGURATION
# ============================================================
DATA_FILE = "api.json"
CMD_FILE = "ia_commands.txt"
HISTORY_LIMIT = 30          # Nombre d'échantillons pour l'entraînement
LEARNING_WARMUP = 20        # Échantillons avant de commencer à détecter
RETRAIN_INTERVAL = 10.0     # Secondes entre deux réentraînements du modèle
SLEEP_INTERVAL = 1.0        # Intervalle d'analyse (seconde)
CONTAMINATION = 0.05        # 5% d'anomalies max
STATIC_DELTA_RAM_MB = 50
STATIC_CPU_LOAD = 2.0
MODELS_DIR = "trained_models"

os.makedirs(MODELS_DIR, exist_ok=True)

nodes_history = {}          # historique des features par nœud
trained_models = {}         # modèles Isolation Forest en mémoire
last_train_time = time.time()

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
def write_command_safe(cmd):
    """Écrit une commande dans le fichier."""
    with open(CMD_FILE, 'a') as f:
        f.write(cmd + "\n")

def log_info(msg):
    print(f"\033[1;36m[INFO]\033[0m {msg}")

def log_alert(msg):
    print(f"\033[1;41;37m[ALERTE]\033[0m {msg}")

def save_model(nid, model):
    """Sauvegarde le modèle sur le disque."""
    path = os.path.join(MODELS_DIR, f"{nid}.joblib")
    joblib.dump(model, path)

def load_model(nid):
    """Charge un modèle depuis le disque s'il existe."""
    path = os.path.join(MODELS_DIR, f"{nid}.joblib")
    if os.path.exists(path):
        return joblib.load(path)
    return None

def garbage_collection(active_ids):
    """Supprime les historiques et modèles des agents disparus."""
    global nodes_history, trained_models
    to_delete = []
    for nid in nodes_history:
        if nid not in active_ids:
            to_delete.append(nid)
    for nid in to_delete:
        del nodes_history[nid]
        if nid in trained_models:
            del trained_models[nid]
        # Supprimer le fichier modèle associé
        model_path = os.path.join(MODELS_DIR, f"{nid}.joblib")
        if os.path.exists(model_path):
            os.remove(model_path)

# ============================================================
# CŒUR DE L'ANOMALY DETECTION
# ============================================================
def analyze_anomalies():
    global nodes_history, trained_models, last_train_time

    if not os.path.exists(DATA_FILE):
        return
    try:
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return

    nodes = data.get('active_nodes', [])
    active_ids = set(node.get('id', 'UNKNOWN') for node in nodes)
    current_time = time.time()
    retrain_now = (current_time - last_train_time) >= RETRAIN_INTERVAL

    for node in nodes:
        nid = node.get('id', 'UNKNOWN')
        hostname = node.get('hostname', 'UNKNOWN')
        ram = node.get('ram_mb', 0)
        lat = node.get('latency', 0)
        cpu = node.get('cpu_load', 0.0)
        net_out = node.get('net_out_bytes_s', 0)
        status = node.get('status', 'UNKNOWN')

        if status == "COMPROMIS" or nid == 'UNKNOWN':
            continue

        # Initialiser l'historique
        if nid not in nodes_history:
            nodes_history[nid] = deque(maxlen=HISTORY_LIMIT)
            # Charger un modèle préexistant
            model = load_model(nid)
            if model:
                trained_models[nid] = model

        # Delta RAM (vélocité)
        delta_ram = 0
        if len(nodes_history[nid]) > 0:
            delta_ram = ram - nodes_history[nid][-1][0]

        current_point = [ram, lat, delta_ram, cpu, net_out]
        nodes_history[nid].append(current_point)

        if len(nodes_history[nid]) < LEARNING_WARMUP:
            continue

        # Réentraînement périodique (et sauvegarde)
        if retrain_now:
            X = np.array(nodes_history[nid])
            clf = IsolationForest(contamination=CONTAMINATION, random_state=42)
            clf.fit(X)
            trained_models[nid] = clf
            save_model(nid, clf)

        # Prédiction avec le modèle existant (ou fallback simple)
        prediction = 1  # normal par défaut
        if nid in trained_models:
            prediction = trained_models[nid].predict([current_point])[0]

        # Seuils adaptatifs
        hist_delta = np.array([x[2] for x in nodes_history[nid]])
        hist_cpu = np.array([x[3] for x in nodes_history[nid]])
        delta_threshold = max(STATIC_DELTA_RAM_MB,
                              3 * np.std(hist_delta) if len(hist_delta) > 1 else STATIC_DELTA_RAM_MB)
        cpu_threshold = max(STATIC_CPU_LOAD,
                            2 * np.median(hist_cpu) if len(hist_cpu) > 0 else STATIC_CPU_LOAD)

        # Décision : anomalie si modèle le dit ET condition seuil (ou seuil seul si pas de modèle)
        is_anomaly = False
        if nid in trained_models:
            is_anomaly = (prediction == -1) and (delta_ram > delta_threshold or cpu > cpu_threshold)
        else:
            is_anomaly = (delta_ram > delta_threshold or cpu > cpu_threshold)

        if is_anomaly:
            log_alert(f"DÉTECTION HEURISTIQUE sur {hostname} ({nid})")
            print(f"   📊 Delta RAM: +{delta_ram:.1f} MB (seuil: {delta_threshold:.1f})")
            print(f"   📊 CPU: {cpu:.2f} (seuil: {cpu_threshold:.2f})")
            print(f"   📊 Latence: {lat} ms | Trafic out: {net_out} B/s")
            print(f"   ⚡ Action : transmission de l'ordre d'auto-isolation au C2\n")
            write_command_safe(f"CMD_IA:ISOLATE|{nid}")
            # On ne vide PAS l'historique : on continue à surveiller

    if retrain_now:
        last_train_time = current_time

    # 🔥 CORRECTION : Le nettoyage de la mémoire s'effectue à la TOUTE FIN du cycle
    garbage_collection(active_ids)

# ============================================================
# BOUCLE PRINCIPALE
# ============================================================
def main():
    print("\033[1;36m[SYSTEME]\033[0m Initialisation du Cortex IA (Isolation Forest 5D) - Version Ultime")
    print("\033[1;35m[NEURAL]\033[0m Moteur prédictif (RAM, Latence, Delta RAM, CPU, Trafic) en écoute.")
    print("\033[1;33m[CONFIG]\033[0m Entraînement périodique toutes les {} secondes".format(RETRAIN_INTERVAL))
    print("\033[1;33m[CONFIG]\033[0m Garbage collection automatique des agents disparus.")
    print("\033[1;33m[CONFIG]\033[0m Modèles sauvegardés dans le dossier '{}'\n".format(MODELS_DIR))

    while True:
        analyze_anomalies()
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;36m[SYSTEME]\033[0m Cortex IA arrêté proprement.")

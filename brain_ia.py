#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# NEURO-MESH CORTEX IA : STAFF ENGINEER EDITION (TRUE SONAR FIX)
# ============================================================
import json
import time
import numpy as np
from sklearn.ensemble import IsolationForest
import os
from collections import deque
import joblib
import socket
import threading

DATA_FILE = "api.json"
REACT_FILE = "api_react.json"
CMD_FILE = "ia_commands.txt"
HISTORY_LIMIT = 30
LEARNING_WARMUP = 20
RETRAIN_INTERVAL = 10.0
SLEEP_INTERVAL = 1.0
CONTAMINATION = 0.05
STATIC_DELTA_RAM_MB = 50
STATIC_CPU_LOAD = 2.0
MODELS_DIR = "trained_models"

os.makedirs(MODELS_DIR, exist_ok=True)

nodes_history = {}
trained_models = {}
last_train_time = time.time()

# Dictionnaire pour stocker la télémétrie P2P en direct
live_p2p_nodes = {}

def listen_p2p_telemetry():
    """ Écoute en mode Sonar Unicast garanti sur localhost (Port 9998) """
    UDP_IP = "127.0.0.1"
    UDP_PORT = 9998
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
        pass
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        try:
            data, addr = sock.recvfrom(65536)
            msg = data.decode('utf-8')
            if msg.startswith("TELEMETRY:"):
                node_data = json.loads(msg[10:])
                nid = node_data.get("ID")
                live_p2p_nodes[nid] = {
                    "id": nid,
                    "hostname": node_data.get("HOST", "UNKNOWN"),
                    "ram_mb": node_data.get("RAM_MB", 0),
                    "cpu_load": node_data.get("CPU_LOAD", 0.0),
                    "procs": node_data.get("PROCS", 1),
                    "net_out_bytes_s": node_data.get("NET_OUT", 0),
                    "latency": 0,
                    "status": "COMPROMIS" if "SELF_ISOLATED" in str(node_data.get("STATUS", "")) else "STABLE",
                    "p2p_state": node_data.get("STATE", "NORMAL"),
                    "neighbors": node_data.get("NEIGHBORS", ""),
                    "_last_seen": time.time()
                }
        except Exception:
            pass

# Lancement du Thread Sonar
threading.Thread(target=listen_p2p_telemetry, daemon=True).start()

def write_command_safe(cmd):
    with open(CMD_FILE, 'a') as f:
        f.write(cmd + "\n")

def log_info(msg):
    print(f"\033[1;36m[INFO]\033[0m {msg}")

def log_alert(msg):
    print(f"\033[1;41;37m[ALERTE]\033[0m {msg}")

def save_model(nid, model):
    path = os.path.join(MODELS_DIR, f"{nid}.joblib")
    joblib.dump(model, path)

def load_model(nid):
    path = os.path.join(MODELS_DIR, f"{nid}.joblib")
    if os.path.exists(path):
        return joblib.load(path)
    return None

def export_to_dashboard(nodes, anomalous_nids):
    temp_file = "react_temp.json"
    agents_data = []
    for node in nodes:
        nid = node.get('id', 'UNKNOWN')
        current_status = "COMPROMIS" if nid in anomalous_nids else node.get('status', 'STABLE')
        
        agents_data.append({
            "id": nid,
            "hostname": node.get('hostname', 'UNKNOWN'),
            "cpu_load": node.get('cpu_load', 0.0),
            "ram_mb": node.get('ram_mb', 0),
            "procs": node.get('procs', 1),
            "net_out_bytes_s": node.get('net_out_bytes_s', node.get('net_tx_bs', 0)),
            "latency": node.get('latency', 0),
            "status": current_status,
            "p2p_state": node.get('p2p_state', 'NORMAL'),
            "neighbors": node.get('neighbors', '')
        })

    telemetry = {
        "architecture": "NEURO-MESH (SURVIE CORTEX IA)",
        "system_status": "THREAT" if len(anomalous_nids) > 0 else "ONLINE",
        "active_nodes": agents_data,
        "timestamp": time.time()
    }
    
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(telemetry, f, indent=4)
        os.replace(temp_file, REACT_FILE)
    except Exception as e:
        log_alert(f"Échec de l'export React: {str(e)}")

def analyze_anomalies():
    global nodes_history, trained_models, last_train_time, live_p2p_nodes

    current_time = time.time()
    nodes = []

    c2_is_alive = False
    if os.path.exists(DATA_FILE):
        try:
            mtime = os.path.getmtime(DATA_FILE)
            if current_time - mtime < 3.0: 
                with open(DATA_FILE, 'r') as f:
                    data = json.load(f)
                nodes = data.get('active_nodes', [])
                c2_is_alive = True
        except (json.JSONDecodeError, IOError, OSError):
            pass

    if not c2_is_alive:
        dead_keys = [k for k, v in live_p2p_nodes.items() if current_time - v.get('_last_seen', current_time) > 10.0]
        for k in dead_keys:
            del live_p2p_nodes[k]
        nodes = list(live_p2p_nodes.values())

    if not nodes:
        export_to_dashboard([], set())
        return

    active_ids = set(node.get('id', 'UNKNOWN') for node in nodes)
    retrain_now = (current_time - last_train_time) >= RETRAIN_INTERVAL
    anomalous_nids = set()

    for node in nodes:
        nid = node.get('id', 'UNKNOWN')
        hostname = node.get('hostname', 'UNKNOWN')
        ram = node.get('ram_mb', 0)
        lat = node.get('latency', 0)
        cpu = node.get('cpu_load', 0.0)
        net_out = node.get('net_out_bytes_s', node.get('net_tx_bs', 0))
        status = node.get('status', 'UNKNOWN')

        if status == "COMPROMIS" or nid == 'UNKNOWN':
            continue

        if nid not in nodes_history:
            nodes_history[nid] = deque(maxlen=HISTORY_LIMIT)
            model = load_model(nid)
            if model: trained_models[nid] = model

        delta_ram = ram - nodes_history[nid][-1][0] if len(nodes_history[nid]) > 0 else 0
        current_point = [ram, lat, delta_ram, cpu, net_out]
        nodes_history[nid].append(current_point)

        if len(nodes_history[nid]) < LEARNING_WARMUP:
            continue

        if retrain_now:
            X = np.array(nodes_history[nid])
            clf = IsolationForest(contamination=CONTAMINATION, random_state=42)
            clf.fit(X)
            trained_models[nid] = clf
            save_model(nid, clf)

        prediction = trained_models[nid].predict([current_point])[0] if nid in trained_models else 1
        
        hist_delta = np.array([x[2] for x in nodes_history[nid]])
        hist_cpu = np.array([x[3] for x in nodes_history[nid]])
        delta_threshold = max(STATIC_DELTA_RAM_MB, 3 * np.std(hist_delta) if len(hist_delta) > 1 else STATIC_DELTA_RAM_MB)
        cpu_threshold = max(STATIC_CPU_LOAD, 2 * np.median(hist_cpu) if len(hist_cpu) > 0 else STATIC_CPU_LOAD)

        if nid in trained_models:
            is_anomaly = (prediction == -1) and (delta_ram > delta_threshold or cpu > cpu_threshold)
        else:
            is_anomaly = (delta_ram > delta_threshold or cpu > cpu_threshold)

        if is_anomaly:
            anomalous_nids.add(nid)
            log_alert(f"DÉTECTION HEURISTIQUE sur {hostname} ({nid})")
            print(f"   📊 Delta RAM: +{delta_ram:.1f} MB (seuil: {delta_threshold:.1f})")
            print(f"   📊 CPU: {cpu:.2f} (seuil: {cpu_threshold:.2f})")
            write_command_safe(f"CMD_IA:ISOLATE|{nid}")

    if retrain_now:
        last_train_time = current_time

    to_delete = [n for n in nodes_history if n not in active_ids]
    for n in to_delete:
        del nodes_history[n]
        if n in trained_models:
            del trained_models[n]
    
    export_to_dashboard(nodes, anomalous_nids)

def main():
    log_info("Initialisation du Cortex IA (Isolation Forest 5D) - True Sonar Unicast Edition")
    log_info("Moteur prédictif en écoute. Export atomique vers React activé.")
    
    while True:
        analyze_anomalies()
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_info("Cortex IA arrêté proprement.")

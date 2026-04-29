# 🧠 NEURAL OVERLORD : MOTEUR D'ANALYSE PRÉDICTIVE (ISOLATION FOREST)
import json
import time
import numpy as np
from sklearn.ensemble import IsolationForest
import os
from collections import deque

# Configuration du Moteur
DATA_FILE = "api.json"
CMD_FILE = "ia_commands.txt"
HISTORY_LIMIT = 30  # Fenêtre glissante de 30 secondes pour apprendre la "normalité"
nodes_history = {}

print("\033[1;36m[SYSTEME]\033[0m Initialisation du Cortex IA (Isolation Forest)...")
print("\033[1;35m[NEURAL]\033[0m Moteur prédictif en écoute sur le maillage P2P.\n")

def analyze_anomalies():
    global nodes_history
    if not os.path.exists(DATA_FILE):
        return

    try:
        # Lecture tolérante aux pannes (si le C++ écrit en même temps)
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)

        for node in data.get('active_nodes', []):
            nid = node['id']
            ram = node['ram_mb']
            lat = node['latency']
            status = node['status']

            # On n'analyse pas les agents déjà morts ou isolés
            if status == "COMPROMIS":
                continue

            if nid not in nodes_history:
                nodes_history[nid] = deque(maxlen=HISTORY_LIMIT)

            # 🧬 FEATURE ENGINEERING : Calcul de la Vélocité (Delta RAM)
            delta_ram = 0
            if len(nodes_history[nid]) > 0:
                delta_ram = ram - nodes_history[nid][-1][0] # RAM actuelle - RAM précédente

            # On stocke [RAM_Totale, Latence, Variation_RAM]
            nodes_history[nid].append([ram, lat, delta_ram])

            # Déclenchement de l'IA uniquement si on a assez de données d'apprentissage
            if len(nodes_history[nid]) == HISTORY_LIMIT:
                X = np.array(nodes_history[nid])
                
                # Entraînement dynamique (Contamination = 5% de chance d'anomalie)
                clf = IsolationForest(contamination=0.05, random_state=42)
                clf.fit(X)
                
                # Prédiction sur l'instant T
                current_state = np.array([[ram, lat, delta_ram]])
                prediction = clf.predict(current_state)

                # ⚡ PRISE DE DÉCISION (Anomalie ET augmentation brutale de la RAM > 50MB/s)
                if prediction[0] == -1 and delta_ram > 50:
                    print(f"\n\033[1;41;37m [!!! DÉTECTION HEURISTIQUE DE MALWARE !!!] \033[0m")
                    print(f"🎯 Cible : {node['hostname']} ({nid})")
                    print(f"📊 Analyse : Hausse suspecte de RAM (+{delta_ram}MB) & Latence ({lat}ms)")
                    print(f"⚡ Action  : Transmission de l'ordre d'AUTO-ISOLATION au C2...\n")
                    
                    # L'IA DONNE UN ORDRE AU C++
                    with open(CMD_FILE, 'a') as cmd_f:
                        cmd_f.write(f"CMD_IA:ISOLATE|{nid}\n")
                    
                    # On vide l'historique de cet agent pour éviter de spammer le C2
                    nodes_history[nid].clear()

    except json.JSONDecodeError:
        pass # Le fichier était en cours d'écriture par le C++, on réessaiera dans 1s
    except Exception as e:
        print(f"❌ Erreur Mineure IA: {e}")

# Boucle Temporelle (Heartbeat de l'IA)
while True:
    analyze_anomalies()
    time.sleep(1)

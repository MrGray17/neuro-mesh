#!/bin/bash
# ============================================================
# NEURO-MESH : Lancement complet de la démo (ULTIME)
# ============================================================
# - Nettoie les processus résiduels
# - Supprime les modèles IA (trained_models) pour repartir de zéro
# - Compile avec make
# - Lance C2, IA, dashboard, 3 agents
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}🧬 NEURO-MESH : Lancement de la démo (Ultime)${NC}"
echo -e "${CYAN}========================================${NC}"

# Nettoyage complet (processus + fichiers + modèles IA)
echo -e "${YELLOW}[1/6] Nettoyage des anciens processus, fichiers et modèles...${NC}"
pkill -f listener 2>/dev/null || true
pkill -f client 2>/dev/null || true
pkill -f brain_ia.py 2>/dev/null || true
pkill -f "python3 -m http.server" 2>/dev/null || true
rm -f api.json api_tmp.json ia_commands.txt incident_report.txt
# 🔥 Nettoyage des modèles IA persistants (pour repartir de zéro)
rm -rf trained_models/*.joblib 2>/dev/null || true
sleep 1

# Compilation
echo -e "${YELLOW}[2/6] Compilation du C2 et de l'agent...${NC}"
make clean > /dev/null 2>&1
if ! make > /dev/null 2>&1; then
    echo -e "${RED}❌ Erreur de compilation${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Compilation réussie${NC}"

# Lancement du C2
echo -e "${YELLOW}[3/6] Lancement du C2 (listener) sur le port 8080...${NC}"
./listener &
LISTENER_PID=$!
sleep 2
if kill -0 $LISTENER_PID 2>/dev/null; then
    echo -e "${GREEN}✅ C2 lancé (PID: $LISTENER_PID)${NC}"
else
    echo -e "${RED}❌ Le C2 n'a pas démarré${NC}"
    exit 1
fi

# Lancement de l'IA
echo -e "${YELLOW}[4/6] Lancement du Cortex IA (Isolation Forest)...${NC}"
python3 brain_ia.py &
IA_PID=$!
sleep 1
echo -e "${GREEN}✅ IA lancée (PID: $IA_PID)${NC}"

# Lancement du serveur Web (dashboard)
echo -e "${YELLOW}[5/6] Lancement du serveur Web (dashboard) sur le port 8000...${NC}"
python3 -m http.server 8000 > /dev/null 2>&1 &
HTTP_PID=$!
sleep 1
echo -e "${GREEN}✅ Dashboard disponible sur http://localhost:8000${NC}"

# Lancement de 3 agents
echo -e "${YELLOW}[6/6] Lancement de 3 agents...${NC}"
for i in 1 2 3; do
    ./client &
    echo -e "${GREEN}   Agent $i lancé${NC}"
    sleep 1
done

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}✅ TOUT EST OPÉRATIONNEL${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "📡 Dashboard : ${CYAN}http://localhost:8000${NC}"
echo -e "🧠 IA Cortex : ${CYAN}active (modèles réinitialisés)${NC}"
echo -e "🛡️ Honeypot : ${CYAN}port 2222 ou suivant${NC}"
echo -e "🔌 WebSocket : ${CYAN}ws://localhost:8081${NC}"
echo -e "⚔️ Pour simuler une attaque : ${CYAN}./test_attack.sh${NC}"
echo -e "🛑 Pour tout arrêter : ${CYAN}pkill -f listener; pkill -f client; pkill -f python3${NC}"
echo -e "${CYAN}========================================${NC}"

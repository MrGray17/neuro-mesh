#!/bin/bash

# ============================================================
# NEURO-MESH : DEPLOYMENT SCRIPT (ULTIMATE EDITION)
# PBFT + Edge AI + React Dashboard + CORS Bypass
# ============================================================

# Couleurs pour l'affichage terminal
GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
NC='\033[0m'

echo -e "${CYAN}==============================================${NC}"
echo -e "${CYAN}      INITIALISATION DE NEURO-MESH V3.0       ${NC}"
echo -e "${CYAN}==============================================${NC}"

# 1. Nettoyage de la zone de combat
echo -e "\n${YELLOW}[*] Purge des anciens processus...${NC}"
killall listener client python3 node 2>/dev/null
rm -f api.json ia_commands.txt incident_report.txt
sleep 1
echo -e "${GREEN}[+] Zone sécurisée.${NC}"

# 2. Lancement du C2 Supreme (Moelle Épinière)
echo -e "\n${YELLOW}[*] Démarrage du C2 Supreme...${NC}"
if [ -f "./listener" ]; then
    ./listener > /dev/null 2>&1 &
    sleep 2
    echo -e "${GREEN}[+] C2 en ligne (Port 8080 et WS 8081).${NC}"
else
    echo -e "${RED}[!] ERREUR : Exécutable 'listener' introuvable. As-tu fait un 'make' ?${NC}"
    exit 1
fi

# 3. Lancement du Cortex IA Central (optionnel selon ton archi, mais sécurisé)
echo -e "\n${YELLOW}[*] Activation du Cortex IA (brain_ia.py)...${NC}"
if [ -f "brain_ia.py" ]; then
    python3 brain_ia.py > /dev/null 2>&1 &
    sleep 1
    echo -e "${GREEN}[+] IA Centrale connectée.${NC}"
else
    echo -e "${YELLOW}[-] Fichier 'brain_ia.py' absent, les agents fonctionneront en Edge AI autonome.${NC}"
fi

# 4. Déploiement des Agents PBFT
echo -e "\n${YELLOW}[*] Déploiement de la flotte d'agents (Architecture P2P)...${NC}"
if [ -f "./client" ]; then
    for i in 1 2 3
    do
        ./client > /dev/null 2>&1 &
        echo -e "${MAGENTA}  -> Déploiement de l'Agent $i...${NC}"
        sleep 1
    done
    echo -e "${GREEN}[+] Maillage P2P et Consensus PBFT actifs.${NC}"
else
    echo -e "${RED}[!] ERREUR : Exécutable 'client' introuvable.${NC}"
    exit 1
fi

# 5. Déploiement du pont HTTP et de l'interface React
echo -e "\n${YELLOW}[*] Déploiement des interfaces de monitoring...${NC}"
echo -e "${CYAN}  -> Configuration du pont HTTP CORS (Port 8000)...${NC}"

# 🔥 LE SERVEUR PYTHON AVEC CONTOURNEMENT CORS
python3 -c "
from http.server import HTTPServer, SimpleHTTPRequestHandler
class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()
HTTPServer(('0.0.0.0', 8000), CORSRequestHandler).serve_forever()
" > /dev/null 2>&1 &

sleep 1
echo -e "${GREEN}[+] Pont HTTP actif.${NC}"

# Lancement de React
DASHBOARD_DIR="dashboard-react"
if [ -d "$DASHBOARD_DIR" ]; then
    echo -e "${CYAN}  -> Lancement du Dashboard React (Port 3000)...${NC}"
    cd "$DASHBOARD_DIR"
    
    # Vérifie si npm install a été fait
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  -> Installation des dépendances (patientez un instant)...${NC}"
        npm install --silent
    fi
    
    npm start > /dev/null 2>&1 &
    cd ..
    echo -e "${GREEN}[+] Node.js lancé en arrière-plan.${NC}"
else
    echo -e "${YELLOW}[-] Dashboard React non trouvé. Interface statique de secours disponible.${NC}"
fi

# ============================================================
# OUTRO & INSTRUCTIONS
# ============================================================
echo -e "\n${GREEN}==============================================${NC}"
echo -e "${GREEN}  🚀 DÉPLOIEMENT TERMINÉ AVEC SUCCÈS !  🚀${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e ""
echo -e "🔗 ${CYAN}C2 WebSocket${NC}  : ws://localhost:8081/?token=NEURO_MESH_SECRET"
echo -e "🔗 ${CYAN}API JSON${NC}      : http://localhost:8000/api.json"
if [ -d "$DASHBOARD_DIR" ]; then
    echo -e "🔗 ${MAGENTA}DASHBOARD REACT${NC} : http://localhost:3000"
else
    echo -e "🔗 ${MAGENTA}DASHBOARD WEB${NC}   : http://localhost:8000"
fi
echo -e ""
echo -e "${YELLOW}Pour lancer une attaque et tester le consensus PBFT :${NC}"
echo -e "👉 Exécute : ./test_attack.sh"
echo -e ""
echo -e "${YELLOW}Pour tout éteindre :${NC}"
echo -e "👉 Exécute : killall listener client python3 node"
echo -e ""

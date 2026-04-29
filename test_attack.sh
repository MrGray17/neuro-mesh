#!/bin/bash
# ============================================================
# NEURO-MESH : Simulation d'attaque mémoire (ULTIME - FIABLE)
# ============================================================
# - Scanne api.json ET api_react.json (C2 + P2P)
# - Gère le mode forcé (--force) avec envoi de SIGUSR1
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FORCE_ISOLATE=false
if [[ "$1" == "--force" ]]; then
    FORCE_ISOLATE=true
    echo -e "${YELLOW}⚠️ Mode forcé : envoi d'un signal d'isolation direct à l'agent${NC}"
fi

# Trouver le PID d'un agent (binaire ./client)
AGENT_PID=$(pgrep -f "./client" | head -1)

if [ -z "$AGENT_PID" ]; then
    echo -e "${RED}❌ Aucun agent trouvé. Lance d'abord ./start_demo.sh${NC}"
    exit 1
fi

echo -e "${CYAN}========================================${NC}"
echo -e "${RED}🔥 SIMULATION D'ATTAQUE SUR L'AGENT $AGENT_PID${NC}"
echo -e "${CYAN}========================================${NC}"

# Lancement de l'attaque mémoire
ATTACK_PID=""
if command -v stress &> /dev/null; then
    echo -e "${YELLOW}💣 Utilisation de 'stress' : allocation de 800 Mo mémoire${NC}"
    stress --vm 1 --vm-bytes 800M --timeout 30s &
    ATTACK_PID=$!
else
    echo -e "${YELLOW}💣 'stress' non trouvé, fallback Python${NC}"
    python3 -c "
import time
print('\033[1;33m[ATTACK] Allocation mémoire progressive...\033[0m')
memory_hog = []
try:
    for i in range(150):
        memory_hog.append('x' * 10_000_000)
        time.sleep(0.3)
except:
    pass
" &
    ATTACK_PID=$!
fi

echo -e "${YELLOW}⏳ Surveillance de la détection (C2 & P2P)...${NC}"
echo ""

# 🔥 LE FIX : On scanne les deux fichiers de vérité (C2 et IA) en fusionnant les sorties
DETECTED=false
for i in {30..1}; do
    if cat api.json api_react.json 2>/dev/null | grep -q '"COMPROMIS"'; then
        DETECTED=true
        break
    fi
    echo -ne "\r   Détection dans : $i secondes...   "
    sleep 1
done

# Si non détecté et mode forcé, on envoie SIGUSR1
if [ "$DETECTED" = false ] && [ "$FORCE_ISOLATE" = true ]; then
    echo -e "\n${YELLOW}⚡ Aucune détection IA, isolation forcée par signal...${NC}"
    kill -SIGUSR1 "$AGENT_PID" 2>/dev/null
    sleep 2
    if cat api.json api_react.json 2>/dev/null | grep -q '"COMPROMIS"'; then
        DETECTED=true
        echo -e "${GREEN}✅ Isolation forcée réussie${NC}"
    fi
elif [ "$DETECTED" = true ]; then
    echo -e "\n${GREEN}✅ IA a détecté l'attaque ! Isolation automatique.${NC}"
else
    echo -e "\n${RED}⚠️ Aucune détection (seuils peut-être trop élevés).${NC}"
fi

# Nettoyage
kill $ATTACK_PID 2>/dev/null

echo -e "${CYAN}========================================${NC}"
if [ "$DETECTED" = true ]; then
    echo -e "${GREEN}✅ Vérifications :${NC}"
    echo -e "   - Dashboard React : agent en ${RED}COMPROMIS${NC} (ligne rouge)"
    echo -e "   - Radar : ${RED}rouge${NC}"
    echo -e "   - Timeline : événement d'attaque visible"
else
    echo -e "${RED}❌ Aucune détection. Vérifiez les logs.${NC}"
fi
echo -e "${CYAN}========================================${NC}"

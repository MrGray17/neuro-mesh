#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}💉 NEURO-MESH ADMIN: INJECTING VACCINE${NC}"
echo -e "${CYAN}========================================${NC}"

echo -e "📡 Broadcasting CURE signal (SIGUSR2) to the mesh..."

# Send the heal signal. Only the compromised node will actually react to it on the dashboard.
killall -SIGUSR2 client 2>/dev/null

echo -e "${GREEN}✅ Threat eradicated & Nodes healed.${NC}"
echo -e "👀 The compromised node will return to STABLE (GREEN) instantly."
echo -e "${CYAN}========================================${NC}"

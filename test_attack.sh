#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${RED}🔥 NEURO-MESH: TARGETED POSIX ATTACK${NC}"
echo -e "${CYAN}========================================${NC}"

# Find EXACTLY ONE agent process
TARGET_PID=$(pgrep -f "./client" | head -n 1)

if [ -z "$TARGET_PID" ]; then
    echo -e "${RED}❌ ERROR: No agent running. Launch ./start_demo.sh first.${NC}"
    exit 1
fi

echo -e "${YELLOW}💣 Injecting localized threat signal into Agent PID: $TARGET_PID...${NC}"

# Send the threat signal to ONLY this specific process
kill -SIGUSR1 "$TARGET_PID"

echo -e "${GREEN}✅ Attack successful.${NC}"
echo -e "👀 Watch the Dashboard. EXACTLY ONE node will turn RED (COMPROMIS)."
echo -e "${CYAN}========================================${NC}"

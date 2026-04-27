# ============================================================
# NEURO-MESH FORGE : ULTIME EDITION (GCM + cross-platform)
# ============================================================
# Auteur : El Yazid
# Description : Compilation de l'écosystème complet NEURO-MESH
# ============================================================

CXX = g++
CXXFLAGS = -Wall -std=c++17 -O3 -s -fno-ident
LDFLAGS = -pthread -lssl -lcrypto -lcurl

TARGETS = listener client packer

all: banner $(TARGETS) size_report

banner:
	@echo ""
	@echo -e "\033[0;36m========================================\033[0m"
	@echo -e "\033[0;36m🧬 NEURO-MESH : COMPILATION ULTIME\033[0m"
	@echo -e "\033[0;36m========================================\033[0m"
	@echo -e "\033[1;33m📦 CXXFLAGS : $(CXXFLAGS)\033[0m"
	@echo -e "\033[1;33m🔗 LDFLAGS  : $(LDFLAGS)\033[0m"
	@echo -e "\033[0;36m========================================\033[0m"
	@echo ""

listener: listener.cpp
	@echo -e "\033[1;33m🧠 Compilation du C2 (listener)...\033[0m"
	$(CXX) $(CXXFLAGS) listener.cpp -o listener $(LDFLAGS)
	@echo -e "\033[0;32m✅ C2 généré\033[0m"

client: client.cpp
	@echo -e "\033[1;33m🛡️ Compilation de l'agent...\033[0m"
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LDFLAGS)
	@echo -e "\033[0;32m✅ Agent généré\033[0m"

packer: packer.cpp
	@echo -e "\033[1;33m📦 Compilation du packer...\033[0m"
	$(CXX) $(CXXFLAGS) packer.cpp -o packer $(LDFLAGS)
	@echo -e "\033[0;32m✅ Packer généré\033[0m"

size_report:
	@echo ""
	@echo -e "\033[0;36m========================================\033[0m"
	@echo -e "\033[0;36m📊 TAILLE DES BINAIRES\033[0m"
	@echo -e "\033[0;36m========================================\033[0m"
	@for bin in $(TARGETS); do \
		if [ -f $$bin ]; then \
			SIZE=$$(ls -lh $$bin | awk '{print $$5}'); \
			echo -e "\033[0;32m✅ $$bin : $$SIZE\033[0m"; \
		else \
			echo -e "\033[0;31m❌ $$bin : non trouvé\033[0m"; \
		fi \
	done
	@echo -e "\033[0;36m========================================\033[0m"
	@echo ""

clean:
	@echo -e "\033[1;33m🧹 Nettoyage des binaires et fichiers temporaires...\033[0m"
	rm -f $(TARGETS) api.json api_tmp.json ia_commands.txt incident_report.txt *.log
	@echo -e "\033[0;32m✅ Nettoyage effectué\033[0m"

distclean: clean
	@echo -e "\033[1;33m🧹 Nettoyage complet (y compris modèles IA)...\033[0m"
	rm -f *.o *.so core core.*
	rm -rf trained_models/
	@echo -e "\033[0;32m✅ Nettoyage complet terminé\033[0m"

rebuild: clean all

.PHONY: all clean distclean rebuild

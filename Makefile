# ⚙️ NEURO-MESH FORGE : VERSION ABSOLUTE SUPREME (PHASE 2 COMPLÈTE)
# Variables : On définit nos outils
CXX = g++

# 🛡️ FLAGS D'ÉLITE (Polymorphisme et Silence) :
# -O3 : Optimisation maximale (réorganise le flux pour perturber la lecture)
# -s : STRIP (Détruit les tables de symboles, rendant 'strings' aveugle)
# -fno-ident : Efface la signature de ton compilateur GCC
# -DSEED=$(shell date +%s) : Change le hash du binaire à chaque seconde
CXXFLAGS = -Wall -std=c++17 -O3 -s -fno-ident -DSEED=$(shell date +%s)
LDFLAGS = -lpthread -lcrypto

# Cibles : L'écosystème complet
TARGETS = client listener packer

all: $(TARGETS)

# Construction de l'Agent (Le Fantôme)
client: client.cpp
	$(CXX) $(CXXFLAGS) client.cpp -o client $(LDFLAGS)
	@echo "🛡️ Agent Sentinel généré et durci."

# Construction du Cerveau (Le C2)
listener: listener.cpp
	$(CXX) $(CXXFLAGS) listener.cpp -o listener $(LDFLAGS)
	@echo "🧠 Cerveau C2 généré."

# Construction de l'Enveloppe (L'Armure)
packer: packer.cpp
	$(CXX) $(CXXFLAGS) packer.cpp -o packer $(LDFLAGS)
	@echo "📦 Packer généré."

# Nettoyage chirurgical
clean:
	rm -f $(TARGETS)

# Réinitialisation totale de la forge
rebuild: clean all

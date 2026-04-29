import { useState, useCallback } from 'react';

export const useAgentDiscovery = (startPort = 8082, maxPorts = 1000) => {
    const [isScanning, setIsScanning] = useState(false);

    const discoverAgent = useCallback(async () => {
        setIsScanning(true);
        console.log(`[SONAR] Début du scan P2P sur localhost (Plage: ${startPort} - ${startPort + maxPorts})...`);

        return new Promise((resolve, reject) => {
            let found = false;

            const scanBatch = async (currentPort) => {
                if (found) return;
                if (currentPort > startPort + maxPorts) {
                    setIsScanning(false);
                    reject(new Error("Aucun agent P2P survivant trouvé."));
                    return;
                }

                const batchPromises = [];
                for (let i = 0; i < 20; i++) {
                    const port = currentPort + i;
                    if (port > startPort + maxPorts) break;

                    batchPromises.push(new Promise((res) => {
                        const wsUrl = `ws://127.0.0.1:${port}/?token=NEURO_MESH_SECRET`;
                        const ws = new WebSocket(wsUrl);

                        // FIX : On donne 1.5 seconde au C++ pour accepter la connexion
                        const timeout = setTimeout(() => {
                            if (ws.readyState === WebSocket.CONNECTING) {
                                ws.close();
                                res(null);
                            }
                        }, 1500);

                        ws.onopen = () => {
                            clearTimeout(timeout);
                            if (!found) {
                                found = true;
                                console.log(`[SONAR] 🎯 Agent P2P trouvé sur le port ${port} !`);
                                ws.close(); 
                                res(wsUrl);
                            } else {
                                ws.close();
                                res(null);
                            }
                        };

                        ws.onerror = () => {
                            clearTimeout(timeout);
                            res(null);
                        };
                    }));
                }

                const results = await Promise.all(batchPromises);
                const successfulUrl = results.find(url => url !== null);
                
                if (successfulUrl) {
                    setIsScanning(false);
                    resolve(successfulUrl);
                } else {
                    setTimeout(() => scanBatch(currentPort + 20), 50);
                }
            };

            scanBatch(startPort);
        });
    }, [startPort, maxPorts]);

    return { discoverAgent, isScanning };
};

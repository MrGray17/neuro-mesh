import { useState, useEffect, useRef } from 'react';

export const useResilientWebSocket = (wsUrl, fallbackUrl) => {
    const [data, setData] = useState({ active_nodes: [], logs: [] });
    // États : 'CONNECTED_C2', 'SEARCHING_P2P', 'CONNECTED_P2P'
    const [connectionState, setConnectionState] = useState('SEARCHING_P2P'); 
    const wsRef = useRef(null);
    const pollRef = useRef(null);

    useEffect(() => {
        let isMounted = true;

        const connectWS = () => {
            wsRef.current = new WebSocket(wsUrl);
            
            wsRef.current.onopen = () => {
                if (!isMounted) return;
                setConnectionState('CONNECTED_C2');
                if (pollRef.current) clearInterval(pollRef.current);
            };

            wsRef.current.onmessage = (e) => {
                if (!isMounted) return;
                try {
                    setData(JSON.parse(e.data));
                } catch (err) {}
            };

            wsRef.current.onclose = () => {
                if (!isMounted) return;
                setConnectionState('SEARCHING_P2P');
                startPolling();
            };
        };

        const startPolling = () => {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = setInterval(async () => {
                try {
                    // Cherche d'abord le fichier de l'IA (Survie)
                    let res = await fetch(`${fallbackUrl}api_react.json?t=${Date.now()}`);
                    if (!res.ok) {
                        // Secours : le fichier brut du C++
                        res = await fetch(`${fallbackUrl}api.json?t=${Date.now()}`);
                    }
                    
                    if (res.ok) {
                        const json = await res.json();
                        if (isMounted) {
                            setData(json);
                            setConnectionState('CONNECTED_P2P');
                        }
                    }
                } catch (err) {
                    if (isMounted) setConnectionState('SEARCHING_P2P');
                }
            }, 2000);
        };

        // Démarre la séquence
        connectWS();

        return () => {
            isMounted = false;
            if (wsRef.current) wsRef.current.close();
            if (pollRef.current) clearInterval(pollRef.current);
        };
    }, [wsUrl, fallbackUrl]);

    return { data, connectionState };
};

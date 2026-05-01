import { useState, useEffect, useRef } from 'react';

export const useWebSocket = (wsUrl = 'ws://localhost:8081', httpUrl = 'http://localhost:8000/api.json') => {
    const [data, setData] = useState({ active_nodes: [], logs: [], system_status: 'AWAITING' });
    const [connectionState, setConnectionState] = useState('SEARCHING_P2P');
    const pollRef = useRef(null);

    useEffect(() => {
        let isMounted = true;
        let ws = new WebSocket(wsUrl);

        const startPolling = () => {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = setInterval(async () => {
                try {
                    const res = await fetch(`${httpUrl}?t=${Date.now()}`);
                    if (res.ok && isMounted) {
                        const json = await res.json();
                        setData(json);
                        setConnectionState('AGENT_P2P');
                    }
                } catch (err) {
                    if (isMounted) setConnectionState('DISCONNECTED');
                }
            }, 2000);
        };

        ws.onopen = () => {
            if (!isMounted) return;
            setConnectionState('C2_CENTRAL');
            if (pollRef.current) clearInterval(pollRef.current);
        };

        ws.onmessage = (event) => {
            if (!isMounted) return;
            try {
                setData(JSON.parse(event.data));
            } catch (e) {}
        };

        ws.onclose = () => {
            if (!isMounted) return;
            setConnectionState('SEARCHING_P2P');
            startPolling(); 
        };

        return () => {
            isMounted = false;
            ws.close();
            if (pollRef.current) clearInterval(pollRef.current);
        };
    }, [wsUrl, httpUrl]);

    return { data, connectionState };
};

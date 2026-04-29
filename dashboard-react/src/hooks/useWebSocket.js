import { useState, useEffect, useRef } from 'react';

const useWebSocket = (onDataReceived, addLog, addEvent) => {
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    const connect = () => {
      // 🔥 CORRECTION : On utilise 127.0.0.1 au lieu de localhost pour contourner le blocage IPv6
      const ws = new WebSocket('ws://127.0.0.1:8081');
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        if (addLog) addLog("Connexion WebSocket établie avec succès.", "success");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onDataReceived) onDataReceived(data);
        } catch (error) {}
      };

      ws.onclose = () => {
        setIsConnected(false);
        setTimeout(connect, 2000); // Reconnexion automatique
      };
      
      ws.onerror = () => ws.close();
    };

    connect();
    return () => wsRef.current?.close();
  }, [onDataReceived, addLog, addEvent]);

  return isConnected;
};

export default useWebSocket;

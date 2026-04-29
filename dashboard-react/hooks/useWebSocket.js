import { useState, useEffect, useRef } from 'react';

export const useWebSocket = (url) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const connect = () => {
      wsRef.current = new WebSocket(url);
      
      wsRef.current.onopen = () => {
        setIsConnected(true);
        console.log('WebSocket connected');
      };
      
      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
        } catch(e) {}
      };
      
      wsRef.current.onclose = () => {
        setIsConnected(false);
        setTimeout(connect, 3000);
      };
    };
    
    connect();
    
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [url]);

  return { isConnected, lastMessage };
};

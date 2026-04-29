// ============================================================
// NEURO-MESH POLLING FALLBACK : ABSOLUTE RESOLUTION
// ============================================================
import { useEffect, useRef } from 'react';

const usePollingFallback = (isWsConnected, setDashboardData, addLog) => {
  const fallbackRef = useRef(null);

  useEffect(() => {
    if (!isWsConnected) {
      addLog('WebSocket indisponible, fallback polling HTTP activé', 'alert');
      
      fallbackRef.current = setInterval(() => {
        // 🔥 CORRECTION : Cibler explicitement le port 8000 du serveur Python
        const targetUrl = `http://${window.location.hostname}:8000/api.json?t=${Date.now()}`;
        
        fetch(targetUrl)
          .then(res => {
            if (!res.ok) throw new Error("HTTP Status " + res.status);
            return res.json();
          })
          .then(data => setDashboardData(data))
          .catch(err => {
             // Silencieux pour ne pas spammer la console si le backend est totalement éteint
          });
      }, 2000);
    } else {
      if (fallbackRef.current) {
        clearInterval(fallbackRef.current);
        fallbackRef.current = null;
      }
    }

    return () => {
      if (fallbackRef.current) clearInterval(fallbackRef.current);
    };
  }, [isWsConnected, setDashboardData, addLog]);
};

export default usePollingFallback;

// ============================================================
// NEURO-MESH COMPONENT : SECURITY LOGS PANEL
// ============================================================
import React, { useEffect, useRef } from 'react';

const LogsPanel = ({ logs = [], events = [] }) => {
  const containerRef = useRef(null);

  // Auto-scroll vers le bas quand un nouveau log arrive
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, events]);

  return (
    <div className="panel p-logs">
      <div className="panel-header">📜 SECURITY AUDIT LOGS</div>
      <div className="logs-container" ref={containerRef} style={{ padding: '15px', height: '280px', overflowY: 'auto', fontSize: '0.85rem' }}>
        
        {/* --- 1. LOGS DU BACKEND (C++) --- */}
        {logs.map((log, index) => (
          <div key={`back-${index}`} className="log-entry" style={{ marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '4px' }}>
            <span style={{ color: '#00ffcc' }}>{log}</span>
          </div>
        ))}

        {/* --- 2. ÉVÉNEMENTS DU FRONTEND (React) --- */}
        {events.map((ev, index) => {
          // Coloration sémantique
          let color = '#a0aec0'; // Gris par défaut
          if (ev.type === 'alert') color = '#ff003c'; // Rouge
          if (ev.type === 'ia') color = '#ff00ff';    // Fuchsia
          
          return (
            <div key={`front-${index}`} className="log-entry" style={{ marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '4px' }}>
              <span className="log-time" style={{ color: '#565f89', marginRight: '10px' }}>[{ev.time}]</span>
              <span style={{ color: color }}>{ev.msg}</span>
            </div>
          );
        })}

        {/* Si aucun log */}
        {logs.length === 0 && events.length === 0 && (
          <div style={{ color: '#565f89', fontStyle: 'italic', textAlign: 'center', marginTop: '20px' }}>
            Aucune anomalie détectée pour le moment...
          </div>
        )}
      </div>
    </div>
  );
};

export default LogsPanel;

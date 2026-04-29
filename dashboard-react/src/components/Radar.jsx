import React from 'react';
import './Radar.css'; // On va créer ce fichier juste après

const Radar = ({ isThreat }) => {
  return (
    <div className={`radar-container ${isThreat ? 'threat-detected' : ''}`}>
      {/* Le balayage rotatif */}
      <div className="radar-sweep"></div>
      
      {/* Les cercles concentriques */}
      <div className="radar-circle c1"></div>
      <div className="radar-circle c2"></div>
      <div className="radar-circle c3"></div>
      
      {/* Les axes */}
      <div className="radar-axis h"></div>
      <div className="radar-axis v"></div>

      {/* Le point d'alerte IA (visible seulement si isThreat est true) */}
      {isThreat && <div className="radar-blip"></div>}
      
      <div className="radar-status-text">
        {isThreat ? "⚠️ THREAT DETECTED" : "SCANNING..."}
      </div>
    </div>
  );
};

export default Radar;

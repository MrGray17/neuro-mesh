import React from 'react';
import './Header.css';

export const Header = ({ connectionState }) => {
    const getStatusConfig = () => {
        switch (connectionState) {
            case "C2_CENTRAL":
                return { text: "C2 CENTRAL (MAÎTRE)", color: "#00ff00", pulse: false };
            case "AGENT_P2P":
                return { text: "AGENT P2P DIRECT (MODE SURVIE)", color: "#00bfff", pulse: false };
            case "SEARCHING_P2P":
                return { text: "SONAR ACTIF... RECHERCHE MAILLAGE P2P", color: "#ffa500", pulse: true };
            case "CONNECTING_C2":
                return { text: "CONNEXION AU C2...", color: "#ffff00", pulse: true };
            case "DISCONNECTED":
            default:
                return { text: "HORS LIGNE - RUPTURE TOTALE", color: "#ff0000", pulse: true };
        }
    };

    const config = getStatusConfig();

    return (
        <header className="dashboard-header" style={{ borderBottom: `2px solid ${config.color}` }}>
            <h1 style={{ margin: 0, fontSize: '1.5rem' }}>🛡️ NEURO-MESH DASHBOARD</h1>
            <div className={`status-indicator ${config.pulse ? 'pulse' : ''}`}>
                <span className="dot" style={{ backgroundColor: config.color }}></span>
                <span className="text" style={{ color: config.color, fontWeight: 'bold' }}>
                    SOURCE : {config.text}
                </span>
            </div>
        </header>
    );
};

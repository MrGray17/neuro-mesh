import React, { useState, useEffect } from 'react';
import { useResilientWebSocket } from './hooks/useResilientWebSocket';
import Radar from './components/Radar';
import AgentsTable from './components/AgentsTable';
import ForceGraph from './components/ForceGraph';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend } from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend);

const chartOptions = {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { display: false } },
    scales: { 
        x: { display: false }, 
        y: { grid: { color: '#2A303F' }, ticks: { color: '#94A3B8' } } 
    }
};

function App() {
    const { data, connectionState } = useResilientWebSocket(
        'ws://localhost:8081/?token=NEURO_MESH_SECRET', 
        'http://localhost:8000/'
    );

    const [timeLabels, setTimeLabels] = useState([]);
    const [ramData, setRamData] = useState([]);
    const [cpuData, setCpuData] = useState([]);
    const [sysTime, setSysTime] = useState(new Date().toLocaleTimeString('fr-FR'));

    useEffect(() => {
        const timer = setInterval(() => setSysTime(new Date().toLocaleTimeString('fr-FR')), 1000);
        return () => clearInterval(timer);
    }, []);

    const agents = (data && Array.isArray(data.active_nodes)) ? data.active_nodes : [];
    const logs = data?.logs || [];

    useEffect(() => {
        if (agents.length > 0) {
            const avgRam = Math.round(agents.reduce((a, b) => a + (b.ram_mb || 0), 0) / agents.length);
            const avgCpu = agents.reduce((a, b) => a + ((b.cpu_load || 0) / (b.procs || 1)), 0) / agents.length;
            const now = new Date().toLocaleTimeString('fr-FR', { hour12: false });
            
            setTimeLabels(prev => [...prev.slice(-24), now]);
            setRamData(prev => [...prev.slice(-24), avgRam]);
            setCpuData(prev => [...prev.slice(-24), avgCpu * 100]); 
        }
    }, [data]);

    const stableCount = agents.filter(n => (n.status || '').toUpperCase() === 'STABLE').length;
    const compCount = agents.filter(n => (n.status || '').toUpperCase() === 'COMPROMIS').length;
    const currentAvgCpu = cpuData.length > 0 ? cpuData[cpuData.length - 1].toFixed(1) : 0;
    const currentAvgRam = ramData.length > 0 ? ramData[ramData.length - 1] : 0;

    const edges = [];
    agents.forEach(node => {
        if (node.neighbors) {
            node.neighbors.split(',').forEach(neighbor => {
                if (neighbor && neighbor !== node.id) {
                    edges.push({ from: node.id, to: neighbor });
                }
            });
        }
    });

    // 🔥 LOGIQUE ULTIME : Génération d'un fichier .log système
    const exportLogs = () => {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        let content = "========================================================\n";
        content += "🛡️ NEURO-MESH : RAPPORT D'OPÉRATIONS DE SÉCURITÉ (SOC)\n";
        content += `🕒 HORODATAGE : ${new Date().toLocaleString('fr-FR')}\n`;
        content += "========================================================\n\n";
        
        content += "--- 📊 ÉTAT DU MAILLAGE DES AGENTS ---\n";
        if (agents.length === 0) content += "Aucun agent détecté dans le maillage.\n";
        agents.forEach(a => {
            const cpuFormatted = a.cpu_load ? a.cpu_load.toFixed(2) : "0.00";
            content += `[${a.id}] HOST: ${a.hostname} | STATUS: ${a.status} | P2P_STATE: ${a.p2p_state} | RAM: ${a.ram_mb} MB | CPU: ${cpuFormatted}%\n`;
        });

        content += "\n--- 🚨 REGISTRE DES ÉVÉNEMENTS (LOGS) ---\n";
        if (logs.length === 0) {
            content += "Aucun événement enregistré.\n";
        } else {
            logs.forEach(l => content += `${l}\n`);
        }

        content += "\n========================================================\n";
        content += "FIN DU RAPPORT\n";

        // Déclenchement du téléchargement côté client
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `NeuroMesh_Report_${timestamp}.log`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    // 🔥 LOGIQUE ULTIME : Appel au micro-service Python
    const triggerAttack = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/attack', { method: 'POST' });
            if (!response.ok) {
                alert("⚠️ Erreur lors de l'injection. L'API a répondu avec une erreur.");
            }
        } catch(e) {
            alert("❌ Échec de la connexion. Assure-toi que le script 'bridge_api.py' tourne dans un terminal (Port 5000) !");
        }
    };

    const renderBannerState = () => {
        if (connectionState === 'CONNECTED_C2') return <div className="status-indicator status-green"><div className="pulse-dot"></div>SOURCE: C2 CENTRAL</div>;
        if (connectionState === 'SEARCHING_P2P') return <div className="status-indicator status-orange"><div className="pulse-dot"></div>SONAR: RECHERCHE P2P...</div>;
        if (connectionState === 'CONNECTED_P2P') return <div className="status-indicator status-blue"><div className="pulse-dot"></div>SOURCE: P2P CORTEX IA</div>;
    };

    return (
        <div id="dashboard-root" className="app">
            <div className="status-banner">
                <div className="banner-title">
                    <span className="shield-icon">🛡️</span> NEURO-MESH COMMAND CENTER
                    <span className="banner-clock">🕒 {sysTime}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                    {renderBannerState()}
                    <div className="button-group">
                        <button onClick={exportLogs}>📄 EXPORT LOGS</button>
                        <button id="btn-attack" onClick={triggerAttack}>💣 INJECT THREAT</button>
                    </div>
                </div>
            </div>

            <div className="soc-grid">
                <div className="kpi-card">
                    <div className="kpi-header">Agents Déployés</div>
                    <div className="kpi-value val-blue">{agents.length}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">Menaces Actives</div>
                    <div className={compCount > 0 ? "kpi-value val-red" : "kpi-value val-green"}>{compCount}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">Charge CPU Réseau</div>
                    <div className={currentAvgCpu > 50 ? "kpi-value val-red" : "kpi-value val-purple"}>{currentAvgCpu}%</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">RAM Allouée</div>
                    <div className="kpi-value val-green">{currentAvgRam} MB</div>
                </div>

                <div className="grid-col-1">
                    <div className="panel">
                        <div className="panel-title">NETWORK RADAR</div>
                        <div className="panel-content" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                            <Radar isThreat={compCount > 0} />
                        </div>
                    </div>
                    <div className="panel">
                        <div className="panel-title">THREAT DISTRIBUTION</div>
                        <div className="panel-content">
                            <Doughnut 
                                data={{ labels: ['STABLE', 'COMPROMISED'], datasets: [{ data: [stableCount, compCount], backgroundColor: ['#10B981', '#EF4444'], borderWidth: 0 }] }} 
                                options={{ cutout: '75%', plugins: { legend: { position: 'bottom', labels: { color: '#94A3B8' } } } }} 
                            />
                        </div>
                    </div>
                </div>

                <div className="grid-col-2">
                    <div className="panel" style={{ flexGrow: 1, marginBottom: '15px' }}>
                        <div className="panel-title">TACTICAL AGENT GRID</div>
                        <div className="panel-content" style={{ padding: 0 }}>
                            <AgentsTable agents={agents} />
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '15px', height: '200px' }}>
                        <div className="panel" style={{ flex: 1 }}>
                            <div className="panel-title">CPU LOAD TREND</div>
                            <div className="panel-content">
                                <Line data={{ labels: timeLabels, datasets: [{ label: 'CPU%', data: cpuData, borderColor: '#8B5CF6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} />
                            </div>
                        </div>
                        <div className="panel" style={{ flex: 1 }}>
                            <div className="panel-title">RAM USAGE TREND</div>
                            <div className="panel-content">
                                <Line data={{ labels: timeLabels, datasets: [{ label: 'RAM', data: ramData, borderColor: '#3B82F6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} />
                            </div>
                        </div>
                    </div>
                </div>

                <div className="grid-col-3">
                    <div className="panel">
                        <div className="panel-title">P2P TOPOLOGY</div>
                        <div className="panel-content" style={{ padding: 0 }}>
                            <ForceGraph nodes={agents.map(a => ({ id: a.id, label: a.id, hostname: a.hostname }))} edges={edges} />
                        </div>
                    </div>
                    <div className="panel">
                        <div className="panel-title">SECURITY EVENT LOGS</div>
                        <div className="panel-content" style={{ padding: '10px' }}>
                            <div className="terminal">
                                {logs.length === 0 ? <span style={{color: '#565f89'}}>Awaiting events...</span> : logs.slice(-30).map((log, i) => {
                                    let logClass = "log-entry";
                                    if (log.includes("ALERTE") || log.includes("COMPROMIS")) logClass += " log-alert";
                                    if (log.includes("CORTEX IA")) logClass += " log-ia";
                                    return (
                                        <div key={i} className={logClass}>
                                            <span className="log-time">[{new Date().toLocaleTimeString()}]</span>
                                            {log}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App;

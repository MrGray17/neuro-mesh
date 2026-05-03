import React, { useState, useEffect } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
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
        y: { grid: { color: '#2A303F' }, ticks: { color: '#94A3B8' }, suggestedMin: 0 }
    }
};

function App() {
    const { data, connectionState } = useWebSocket();
    const [timeLabels, setTimeLabels] = useState([]);
    const [ramData, setRamData] = useState([]);
    const [cpuData, setCpuData] = useState([]);
    const [sysTime, setSysTime] = useState(new Date().toLocaleTimeString('fr-FR'));

    const activeNodes = data.active_nodes || [];
    const logs = data.logs || [];
    
    // 🛡️ THE FIX: Accurate node calculation ensuring no phantom stable nodes
    const agentCount = activeNodes.length;
    const compCount = activeNodes.filter(n => n.status === 'COMPROMIS' || n.status === 'DISCONNECTED_ALERT' || n.status === 'SELF_ISOLATED').length;
    const stableCount = agentCount === 0 ? 0 : agentCount - compCount; 
    
    const totalRam = activeNodes.reduce((acc, curr) => acc + (curr.ram_mb || 0), 0);
    const avgRam = agentCount > 0 ? Math.round(totalRam / agentCount) : 0;
    
    const totalCpu = activeNodes.reduce((acc, curr) => acc + ((curr.cpu_load || 0) / (curr.procs || 1)), 0);
    const avgCpu = agentCount > 0 ? (totalCpu / agentCount) : 0;

    useEffect(() => {
        const timer = setInterval(() => setSysTime(new Date().toLocaleTimeString('fr-FR')), 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        if (agentCount > 0) {
            const now = new Date().toLocaleTimeString('fr-FR', { hour12: false });
            setTimeLabels(prev => [...prev.slice(-24), now]);
            setRamData(prev => [...prev.slice(-24), avgRam]);
            setCpuData(prev => [...prev.slice(-24), avgCpu * 100]); 
        }
    }, [agentCount, avgRam, avgCpu]);

    const edges = [];
    activeNodes.forEach(node => {
        if (node.neighbors) {
            node.neighbors.split(',').forEach(neighbor => {
                if (neighbor && neighbor !== node.id && neighbor !== "NEIGHBORS:") {
                    edges.push({ from: node.id, to: neighbor });
                }
            });
        }
    });

    const renderBannerState = () => {
        if (connectionState === 'C2_CENTRAL') return <div className="status-indicator status-green"><div className="pulse-dot"></div>C2 CENTRAL (CONNECTED)</div>;
        if (connectionState === 'DISCONNECTED') return <div className="status-indicator status-red" style={{color: '#ff003c'}}><div className="pulse-dot"></div>CONNEXION PERDUE</div>;
        return <div className="status-indicator status-orange"><div className="pulse-dot"></div>RECHERCHE C2...</div>;
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
                        <button id="btn-attack" onClick={() => alert("Exécutez ./test_attack.sh dans le terminal")}>💣 INJECT THREAT</button>
                    </div>
                </div>
            </div>

            <div className="soc-grid">
                <div className="kpi-card">
                    <div className="kpi-header">Agents Déployés</div>
                    <div className="kpi-value val-blue">{agentCount}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">Menaces Actives</div>
                    <div className={compCount > 0 ? "kpi-value val-red" : "kpi-value val-green"}>{compCount}</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">Charge CPU Réseau</div>
                    <div className={avgCpu > 0.5 ? "kpi-value val-red" : "kpi-value val-purple"}>{(avgCpu * 100).toFixed(1)}%</div>
                </div>
                <div className="kpi-card">
                    <div className="kpi-header">RAM Allouée</div>
                    <div className="kpi-value val-green">{avgRam} MB</div>
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
                            <Doughnut data={{ labels: ['STABLE', 'COMPROMISED'], datasets: [{ data: [stableCount, compCount], backgroundColor: ['#10B981', '#EF4444'], borderWidth: 0 }] }} options={{ cutout: '75%', plugins: { legend: { position: 'bottom', labels: { color: '#94A3B8' } } } }} />
                        </div>
                    </div>
                </div>

                <div className="grid-col-2">
                    <div className="panel" style={{ flexGrow: 1, marginBottom: '15px' }}>
                        <div className="panel-title">TACTICAL AGENT GRID</div>
                        <div className="panel-content" style={{ padding: 0 }}>
                            <AgentsTable agents={activeNodes} />
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: '15px', height: '200px' }}>
                        <div className="panel" style={{ flex: 1 }}><div className="panel-title">CPU LOAD</div><div className="panel-content"><Line data={{ labels: timeLabels, datasets: [{ label: 'CPU%', data: cpuData, borderColor: '#8B5CF6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} /></div></div>
                        <div className="panel" style={{ flex: 1 }}><div className="panel-title">RAM USAGE</div><div className="panel-content"><Line data={{ labels: timeLabels, datasets: [{ label: 'RAM', data: ramData, borderColor: '#3B82F6', borderWidth: 2, tension: 0.4 }] }} options={chartOptions} /></div></div>
                    </div>
                </div>

                <div className="grid-col-3">
                    <div className="panel"><div className="panel-title">P2P TOPOLOGY</div><div className="panel-content" style={{ padding: 0 }}><ForceGraph nodes={activeNodes.map(a => ({ id: a.id, label: a.id, hostname: a.hostname }))} edges={edges} /></div></div>
                    <div className="panel"><div className="panel-title">SECURITY EVENT LOGS</div><div className="panel-content" style={{ padding: '10px' }}><div className="terminal">
                        {logs.length === 0 ? <span style={{color: '#565f89'}}>Awaiting events...</span> : logs.map((log, i) => (
                            <div key={i} className={`log-entry ${log.includes('CRITICAL') || log.includes('INTRUSION') ? 'log-alert' : ''}`}>{log}</div>
                        ))}
                    </div></div></div>
                </div>
            </div>
        </div>
    );
}
export default App;

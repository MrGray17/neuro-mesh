import React, { useState, useEffect } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import Radar from './components/Radar';
import AgentsTable from './components/AgentsTable';
import ForceGraph from './components/ForceGraph';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend } from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import html2pdf from 'html2pdf.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend);

function App() {
  const [agentUrl, setAgentUrl] = useState(localStorage.getItem('lastAgent') || 'localhost:8081');
  const { isConnected, lastMessage } = useWebSocket(`ws://${agentUrl}/?token=NEURO_MESH_SECRET`);
  const [dashboardData, setDashboardData] = useState({ active_nodes: [], logs: [] });
  const [timeLabels, setTimeLabels] = useState([]);
  const [ramData, setRamData] = useState([]);
  const [cpuData, setCpuData] = useState([]);

  useEffect(() => {
    if (lastMessage) {
      setDashboardData(lastMessage);
      const nodes = lastMessage.active_nodes || [];
      if (nodes.length > 0) {
        const avgRam = Math.round(nodes.reduce((a, b) => a + (b.ram_mb || 0), 0) / nodes.length);
        const avgCpu = nodes.reduce((a, b) => a + ((b.cpu_load || 0) / (b.procs || 1)), 0) / nodes.length;
        const now = new Date().toLocaleTimeString('fr-FR', { hour12: false });
        setTimeLabels(prev => [...prev.slice(-24), now]);
        setRamData(prev => [...prev.slice(-24), avgRam]);
        setCpuData(prev => [...prev.slice(-24), avgCpu]);
      }
    }
  }, [lastMessage]);

  const nodes = dashboardData.active_nodes || [];
  const logs = dashboardData.logs || [];
  const stableCount = nodes.filter(n => (n.status || '').toUpperCase() === 'STABLE').length;
  const compCount = nodes.filter(n => (n.status || '').toUpperCase() === 'COMPROMIS').length;

  // Construire les arêtes pour le force graph
  const edges = [];
  nodes.forEach(node => {
    if (node.neighbors) {
      node.neighbors.split(',').forEach(neighbor => {
        if (neighbor && neighbor !== node.id) {
          edges.push({ from: node.id, to: neighbor });
        }
      });
    }
  });

  const exportPDF = () => {
    const element = document.getElementById('dashboard-content');
    html2pdf().set({ margin: 0.5, filename: 'neuro_mesh_report.pdf', image: { type: 'jpeg', quality: 0.98 }, jsPDF: { unit: 'in', format: 'a2', orientation: 'landscape' } }).from(element).save();
  };

  const triggerAttack = async () => {
    try {
      await fetch('/api/attack', { method: 'POST' });
    } catch(e) {
      console.error('Attack API error', e);
    }
  };

  return (
    <div className="app">
      <div className="header">
        <div className="title">🧬 NEURO-MESH // P2P DECENTRALIZED</div>
        <div className="button-group">
          <input type="text" value={agentUrl} onChange={(e) => setAgentUrl(e.target.value)} placeholder="Agent IP:PORT" />
          <button onClick={() => { localStorage.setItem('lastAgent', agentUrl); window.location.reload(); }}>🔌 CONNECT</button>
          <button onClick={exportPDF}>📄 EXPORT PDF</button>
          <button onClick={triggerAttack}>💣 TRIGGER ATTACK</button>
        </div>
        <div className="sys-metrics">
          <div className="metric-box"><div>AGENTS</div><div className="metric-val">{nodes.length}</div></div>
          <div className="metric-box"><div>PEER</div><div className="metric-val" style={{ color: isConnected ? '#00ff66' : '#ff003c' }}>{isConnected ? 'LIVE' : 'OFFLINE'}</div></div>
          <div className="metric-box"><div>STATE</div><div className="metric-val" style={{ color: compCount > 0 ? '#ff003c' : '#00ff66' }}>{compCount > 0 ? 'THREAT' : 'SECURE'}</div></div>
        </div>
      </div>

      <div id="dashboard-content" className="siem-grid">
        <div className="panel p-radar"><div className="panel-header">📡 NETWORK RADAR</div><Radar isThreat={compCount > 0} /></div>
        <div className="panel p-threat"><div className="panel-header">⚠️ THREAT DISTRIBUTION</div><Doughnut data={{ labels: ['STABLE', 'COMPROMISED'], datasets: [{ data: [stableCount, compCount], backgroundColor: ['#00ff66', '#ff003c'] }] }} options={{ cutout: '65%' }} /></div>
        <div className="panel p-ram"><div className="panel-header">📈 AVG RAM (MB)</div><Line data={{ labels: timeLabels, datasets: [{ label: 'RAM', data: ramData, borderColor: '#00e5ff', fill: true, tension: 0.3 }] }} options={{ responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } } }} /></div>
        
        <div className="panel p-table"><div className="panel-header">🛡️ TACTICAL GRID</div><AgentsTable agents={nodes} /></div>
        
        <div className="panel p-cpu"><div className="panel-header">🧠 AVG CPU LOAD</div><Line data={{ labels: timeLabels, datasets: [{ label: 'CPU/core', data: cpuData, borderColor: '#b100ff', fill: true, tension: 0.3 }] }} options={{ responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } } }} /></div>
        <div className="panel p-graph"><div className="panel-header">🌐 P2P MESH</div><ForceGraph nodes={nodes} edges={edges} /></div>
        <div className="panel p-logs"><div className="panel-header">📜 SECURITY LOGS</div><div className="terminal">{logs.slice(-50).map((log, i) => <div key={i} className="log-entry">{log}</div>)}</div></div>
      </div>
    </div>
  );
}

export default App;

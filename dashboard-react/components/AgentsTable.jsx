import React from 'react';

const AgentsTable = ({ agents }) => {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>HOST</th><th>ROLE</th><th>CPU%</th><th>RAM</th><th>NET_OUT</th><th>LAT</th><th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          {agents.map(agent => {
            const status = (agent.status || 'UNKNOWN').toUpperCase();
            const cpuNorm = (agent.cpu_load || 0) / (agent.procs || 1);
            const cpuColor = cpuNorm > 0.7 ? '#ff003c' : (cpuNorm > 0.4 ? '#ffaa00' : '#00ff66');
            const netOut = agent.net_out_bytes_s || 0;
            const role = agent.p2p_state === 'COORDINATOR' ? '👑' : '🔗';
            return (
              <tr key={agent.id} className={status === 'COMPROMIS' ? 'row-COMPROMIS' : ''}>
                <td style={{ fontWeight: 'bold' }}>{agent.id}</td>
                <td>{agent.hostname}</td>
                <td>{role}</td>
                <td style={{ color: cpuColor }}>{cpuNorm.toFixed(2)}</td>
                <td>{agent.ram_mb || 0}</td>
                <td style={{ color: netOut > 5000 ? '#ff003c' : '#00e5ff' }}>{(netOut / 1024).toFixed(1)}</td>
                <td>{agent.latency || 0}ms</td>
                <td className={`status-${status}`}>{status}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default AgentsTable;

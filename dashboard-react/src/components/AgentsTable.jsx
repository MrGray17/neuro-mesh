import React from 'react';

const AgentsTable = ({ agents = [] }) => {
  return (
    <div className="panel p-table" style={{ flexGrow: 1 }}>
      <div className="panel-header">🌐 General Statistics (Nodes)</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID NODE</th>
              <th>HOST</th>
              <th>CPU (%)</th>
              <th>RAM (MB)</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {agents?.length > 0 ? (
              agents.map(agent => {
                const status = (agent.status || agent.STATUS || 'UNKNOWN').toUpperCase();
                const isAlert = status === 'COMPROMIS' || status === 'SELF_ISOLATED' || status === 'DISCONNECTED_ALERT';

                return (
                  <tr key={agent.id} className={isAlert ? 'row-alert' : ''}>
                    <td style={{ fontWeight: 'bold' }}>{agent.id}</td>
                    <td style={{ color: '#cbd5e0' }}>{agent.hostname || agent.HOST}</td>
                    <td style={{ color: '#00e676' }}>{((agent.cpu_load || 0) / (agent.procs || 1)).toFixed(2)}%</td>
                    <td style={{ color: '#63b3ed' }}>{agent.ram_mb || agent.RAM_MB}</td>
                    <td style={{ color: isAlert ? '#ff3d71' : '#00e676', fontWeight: 'bold' }}>
                      {status}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '30px', color: '#718096' }}>
                  No agents connected. Awaiting telemetry...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AgentsTable;

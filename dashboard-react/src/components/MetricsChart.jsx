import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export const CpuChart = ({ nodes }) => (
  <div className="panel">
    <div className="panel-header">⚡ CPU Overview</div>
    <div style={{ width: '100%', height: 180 }}>
      <ResponsiveContainer>
        <AreaChart data={nodes} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#b066fe" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#b066fe" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <XAxis dataKey="id" stroke="#718096" fontSize={10} tickLine={false} axisLine={false} />
          <YAxis stroke="#718096" fontSize={10} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={{ background: 'rgba(15,15,30,0.9)', border: 'none', borderRadius: '8px', color: '#fff' }} />
          <Area type="monotone" dataKey="cpu_load" stroke="#b066fe" strokeWidth={3} fillOpacity={1} fill="url(#colorCpu)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </div>
);

export const RamChart = ({ nodes }) => (
  <div className="panel">
    <div className="panel-header">🧠 RAM Consumption</div>
    <div style={{ width: '100%', height: 180 }}>
      <ResponsiveContainer>
        <AreaChart data={nodes} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorRam" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00f2fe" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#00f2fe" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <XAxis dataKey="id" stroke="#718096" fontSize={10} tickLine={false} axisLine={false} />
          <YAxis stroke="#718096" fontSize={10} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={{ background: 'rgba(15,15,30,0.9)', border: 'none', borderRadius: '8px', color: '#fff' }} />
          <Area type="monotone" dataKey="ram_mb" stroke="#00f2fe" strokeWidth={3} fillOpacity={1} fill="url(#colorRam)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </div>
);

const MetricsChart = ({ nodes, type }) => {
  if (type === 'cpu') return <CpuChart nodes={nodes} />;
  if (type === 'ram') return <RamChart nodes={nodes} />;
  return null;
};
export default MetricsChart;

import React, { useEffect, useRef } from 'react';
import { Network } from 'vis-network';

const ForceGraph = ({ nodes, edges }) => {
  const containerRef = useRef(null);
  const networkRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;
    
    const data = {
      nodes: nodes.map(n => ({ id: n.id, label: n.id, title: n.hostname })),
      edges: edges.map(e => ({ from: e.from, to: e.to }))
    };
    
    const options = {
      nodes: { shape: 'dot', size: 12, font: { size: 9, color: '#c0caf5' } },
      edges: { color: '#565f89', arrows: { to: false }, smooth: true },
      physics: { stabilization: false, solver: 'forceAtlas2Based' }
    };
    
    if (networkRef.current) {
      networkRef.current.setData(data);
    } else {
      networkRef.current = new Network(containerRef.current, data, options);
    }
  }, [nodes, edges]);

  return <div ref={containerRef} style={{ width: '100%', height: '170px', background: '#00000066', borderRadius: '4px' }} />;
};

export default ForceGraph;

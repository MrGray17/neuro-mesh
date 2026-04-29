import React, { useEffect, useRef } from 'react';

const SecurityLogs = ({ logs }) => {
  const terminalRef = useRef(null);
  const autoScrollRef = useRef(true);

  useEffect(() => {
    if (terminalRef.current && autoScrollRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const handleScroll = () => {
    if (terminalRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = terminalRef.current;
      autoScrollRef.current = scrollHeight - clientHeight <= scrollTop + 10;
    }
  };

  return (
    <div className="panel p-logs">
      <div className="panel-header">📜 SECURITY LOGS</div>
      <div className="terminal" ref={terminalRef} onScroll={handleScroll}>
        {logs.map(log => (
          <div key={log.id} className={`log-entry ${log.type === 'alert' ? 'log-alert' : log.type === 'ia' ? 'log-ia' : log.type === 'resilience' ? 'log-resilience' : ''}`}>
            {log.text}
          </div>
        ))}
      </div>
    </div>
  );
};
export default SecurityLogs;

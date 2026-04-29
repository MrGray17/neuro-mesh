import React, { useEffect, useRef } from 'react';

const Radar = ({ isThreat }) => {
  const radarRef = useRef(null);

  useEffect(() => {
    if (radarRef.current) {
      if (isThreat) {
        radarRef.current.classList.add('radar-alert');
      } else {
        radarRef.current.classList.remove('radar-alert');
      }
    }
  }, [isThreat]);

  return (
    <div className="radar-container">
      <div className="radar" ref={radarRef}>
        <div className="radar-threat" style={{ display: isThreat ? 'block' : 'none' }} />
      </div>
    </div>
  );
};

export default Radar;

import React from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

// Enregistrement de l'élément Arc indispensable pour le Doughnut
ChartJS.register(ArcElement, Tooltip, Legend);

const ThreatChart = ({ stableCount, compCount }) => {
  const data = {
    labels: ['STABLE', 'COMPROMISED'],
    datasets: [{
      data: [stableCount, compCount],
      backgroundColor: ['#00ff66', '#ff003c'],
      borderWidth: 1
    }]
  };
  const options = {
    cutout: '65%',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#565f89', font: { size: 9, family: 'Courier New' } }
      }
    }
  };
  return (
    <div className="panel p-threat">
      <div className="panel-header">⚠️ THREAT DISTRIBUTION</div>
      <div className="chart-container" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '120px' }}>
        <Doughnut data={data} options={options} />
      </div>
    </div>
  );
};

export default ThreatChart;

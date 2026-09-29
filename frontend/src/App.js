import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';
import './App.css';

function App() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = () => {
    axios.get('http://127.0.0.1:8000/api/alerts')
      .then(response => {
        if(response.data.status === 'success') {
          setAlerts(response.data.data);
        }
      })
      .catch(error => console.error("Error fetching alerts:", error));
  };

  // NEW FUNCTION: Send the updated status to the backend
  const handleStatusChange = (alertId, newStatus) => {
    axios.put(`http://127.0.0.1:8000/api/alerts/${alertId}/status`, { status: newStatus })
      .then(response => {
        if(response.data.status === 'success') {
          // Update the UI immediately without reloading the page
          setAlerts(alerts.map(alert => 
            alert.id === alertId ? { ...alert, status: newStatus } : alert
          ));
        }
      })
      .catch(error => console.error("Error updating status:", error));
  };

  return (
    <div className="dashboard">
      <header className="header">
        <h1>SOC Dashboard: DNS Tunneling Detection</h1>
      </header>
      
      <div className="content">
        <div className="chart-container">
          <h2>Risk Score Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={alerts.slice(0, 10)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#444" />
              <XAxis dataKey="domain" tick={{fill: '#ccc', fontSize: 10}} />
              <YAxis tick={{fill: '#ccc'}} />
              <Tooltip contentStyle={{backgroundColor: '#333', border: 'none'}} />
              <Bar dataKey="risk_score" fill="#ff4d4d" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="table-container">
          <h2>Recent Security Alerts</h2>
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Detection Reason</th>
                <th>Status (Action)</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.domain}</td>
                  <td>{alert.source_ip}</td>
                  <td>
                    <span className={`badge ${alert.severity.toLowerCase()}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>{alert.risk_score} / 100</td>
                  <td>{alert.detection_reason}</td>
                  <td>
                    {/* NEW DROPDOWN MENU */}
                    <select 
                      className="status-dropdown"
                      value={alert.status || 'OPEN'} 
                      onChange={(e) => handleStatusChange(alert.id, e.target.value)}
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="CONTAINED">CONTAINED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="FALSE POSITIVE">FALSE POSITIVE</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default App;

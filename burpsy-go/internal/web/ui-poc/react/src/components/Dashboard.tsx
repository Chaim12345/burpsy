import React from 'react';
import { api } from '../services/api';
import { useToast } from './ToastContainer';
import type { Stats } from '../types';

const Dashboard: React.FC = () => {
  const toast = useToast();
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [error, setError] = React.useState<string | null>(null);
  
  // Fetch dashboard data
  React.useEffect(() => {
    const fetchDashboard = async () => {
      try {
        setLoading(true);
        const data = await api.getDashboard();
        setStats({
          exchanges: data.exchanges,
          messages: data.messages,
          stored_bytes: data.stored_bytes,
        });
      } catch (e) {
        setError((e as Error).message);
        toast((e as Error).message, 'error');
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboard();
    
    // Poll every 5 seconds
    const interval = setInterval(fetchDashboard, 5000);
    return () => clearInterval(interval);
  }, [toast]);
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };
  
  if (loading) {
    return (
      <section className="dashboard-tab">
        <div className="loading-state">
          <span className="spinner" /> Loading dashboard...
        </div>
      </section>
    );
  }
  
  if (error) {
    return (
      <section className="dashboard-tab">
        <div className="error-message">{error}</div>
      </section>
    );
  }
  
  return (
    <section className="dashboard-tab">
      <div className="stat-tiles four">
        <div className="stat-tile">
          <div className="label">Exchanges captured</div>
          <div className="value">{stats?.exchanges.toLocaleString() || '0'}</div>
        </div>
        <div className="stat-tile">
          <div className="label">Storage used</div>
          <div className="value">{stats ? formatBytes(stats.stored_bytes) : '0'}</div>
        </div>
        <div className="stat-tile">
          <div className="label">Messages</div>
          <div className="value">{stats?.messages.toLocaleString() || '0'}</div>
        </div>
        <div className="stat-tile">
          <div className="label">Tasks running</div>
          <div className="value">0</div>
        </div>
      </div>
      
      <div className="card">
        <div className="card-title">Counts, and what they do not account for</div>
        <p className="hint">
          A count with a caveat is a floor, not a total. Nothing here reports a number
          without reporting the work that produced no verdict.
        </p>
        <div className="four">
          {/* Placeholder for summary cards */}
          <div className="stat-tile">
            <div className="label">Passive Checks</div>
            <div className="value">0</div>
            <div className="hint">No caveats</div>
          </div>
          <div className="stat-tile">
            <div className="label">Active Checks</div>
            <div className="value">0</div>
            <div className="hint">No caveats</div>
          </div>
          <div className="stat-tile">
            <div className="label">Findings</div>
            <div className="value">0</div>
            <div className="hint">No caveats</div>
          </div>
          <div className="stat-tile">
            <div className="label">Requests Sent</div>
            <div className="value">0</div>
            <div className="hint">No caveats</div>
          </div>
        </div>
      </div>
      
      <div className="two">
        <div className="card">
          <div className="card-title">Tasks</div>
          <p className="hint">Active scanning tasks and their status</p>
          <table className="table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Target</th>
                <th>State</th>
                <th>Progress</th>
                <th>Result</th>
                <th>Elapsed</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={6} className="empty-state">
                  <div className="empty-icon">🛠️</div>
                  <div className="empty-title">No tasks running</div>
                  <div className="empty-hint">Start a scan or crawl to see tasks here</div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        
        <div className="card">
          <div className="card-title">Live Active Audit</div>
          <p className="hint">Auditing new in-scope traffic. Active checks are never sent automatically while this is off.</p>
          <div className="row">
            <label className="switch">
              <input type="checkbox" />
              <span className="slider" />
            </label>
            <span>Intercept is on</span>
          </div>
          <div className="row" style={{ marginTop: '8px' }}>
            <div className="stat-tile grow">
              <div className="label">Exchanges swept</div>
              <div className="value">0</div>
            </div>
            <div className="stat-tile grow">
              <div className="label">Findings</div>
              <div className="value">0</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Dashboard;

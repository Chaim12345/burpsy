import React from 'react';
import { useUIStore, selectCurrentTab, selectTheme } from '../store';
import { api } from '../services/api';
import type { Stats, ScopeInfo } from '../types';

interface HeaderProps {
  onShortcutHelp: () => void;
}

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'history', label: 'History' },
  { id: 'wshistory', label: 'WS History' },
  { id: 'sitemap', label: 'Site map' },
  { id: 'repeater', label: 'Repeater' },
  { id: 'intruder', label: 'Intruder' },
  { id: 'intercept', label: 'Intercept' },
  { id: 'scanner', label: 'Scanner' },
  { id: 'decoder', label: 'Decoder' },
  { id: 'comparer', label: 'Comparer' },
  { id: 'logger', label: 'Logger' },
  { id: 'organizer', label: 'Organizer' },
  { id: 'matchreplace', label: 'Match/Replace' },
  { id: 'session', label: 'Session' },
  { id: 'sequencer', label: 'Sequencer' },
];

const Header: React.FC<HeaderProps> = ({ onShortcutHelp }) => {
  const currentTab = useUIStore(selectCurrentTab);
  const theme = useUIStore(selectTheme);
  const setCurrentTab = useUIStore(state => state.setCurrentTab);
  const toggleTheme = useUIStore(state => state.toggleTheme);
  
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [scopeInfo, setScopeInfo] = React.useState<ScopeInfo | null>(null);
  const [caAvailable, setCaAvailable] = React.useState<boolean>(false);
  
  // Fetch stats
  React.useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await api.getStats();
        setStats(data);
      } catch (e) {
        console.error('Failed to fetch stats:', e);
      }
    };
    
    fetchStats();
    const interval = setInterval(fetchStats, 4000);
    return () => clearInterval(interval);
  }, []);
  
  // Fetch scope info
  React.useEffect(() => {
    const fetchScope = async () => {
      try {
        const data = await api.getScope();
        setScopeInfo(data);
      } catch (e) {
        console.error('Failed to fetch scope:', e);
      }
    };
    
    fetchScope();
  }, []);
  
  // Check CA availability
  React.useEffect(() => {
    const checkCA = async () => {
      try {
        await api.getCACert();
        setCaAvailable(true);
      } catch (e) {
        setCaAvailable(false);
      }
    };
    
    checkCA();
  }, []);
  
  const handleNavClick = (id: string) => {
    setCurrentTab(id);
  };
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };
  
  return (
    <header className="header">
      <h1 className="logo">burpsy</h1>
      
      <nav className="nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-button ${currentTab === item.id ? 'active' : ''}`}
            onClick={() => handleNavClick(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      
      {caAvailable && (
        <a 
          href="/ca.crt" 
          download 
          className="ca-link"
        >
          CA cert
        </a>
      )}
      
      {scopeInfo && (
        <span className="scope-badge" title={JSON.stringify(scopeInfo.rules)}>
          scope: {scopeInfo.allow_all ? 'everything' : `${scopeInfo.rules.length} rule(s)`}
        </span>
      )}
      
      {stats && (
        <span className="stats">
          {stats.exchanges} exchanges · {stats.messages} msgs · {formatBytes(stats.stored_bytes)} stored
        </span>
      )}
      
      <div className="header-actions">
        <button 
          className="theme-toggle" 
          onClick={toggleTheme}
          title="Toggle theme"
        >
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
        <button 
          className="shortcut-help" 
          onClick={onShortcutHelp}
          title="Keyboard Shortcuts (?)"
        >
          <kbd>?</kbd>
        </button>
      </div>
    </header>
  );
};

export default Header;

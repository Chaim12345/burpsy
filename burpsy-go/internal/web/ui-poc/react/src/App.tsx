import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useUIStore, selectTheme } from './store';
import { ToastProvider } from './components/ToastContainer';
import { ShortcutHelpProvider } from './components/ShortcutHelp';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import History from './components/History';
import Scanner from './components/Scanner';
import Repeater from './components/Repeater';
import Intruder from './components/Intruder';
import Intercept from './components/Intercept';
import Decoder from './components/Decoder';
import Comparer from './components/Comparer';
import Logger from './components/Logger';
import Organizer from './components/Organizer';
import Session from './components/Session';
import Sequencer from './components/Sequencer';
import WSHistory from './components/WSHistory';
import Sitemap from './components/Sitemap';
import MatchReplace from './components/MatchReplace';

// Theme provider component
const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const theme = useUIStore(selectTheme);
  
  React.useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);
  
  return <div className={`theme-${theme}`}>{children}</div>;
};

// Main App component
const App: React.FC = () => {
  return (
    <ToastProvider>
      <ShortcutHelpProvider>
        <ThemeProvider>
          <div className="app">
            <Header />
            <main className="main-content">
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/history" element={<History />} />
                <Route path="/wshistory" element={<WSHistory />} />
                <Route path="/sitemap" element={<Sitemap />} />
                <Route path="/repeater" element={<Repeater />} />
                <Route path="/intruder" element={<Intruder />} />
                <Route path="/intercept" element={<Intercept />} />
                <Route path="/scanner" element={<Scanner />} />
                <Route path="/decoder" element={<Decoder />} />
                <Route path="/comparer" element={<Comparer />} />
                <Route path="/logger" element={<Logger />} />
                <Route path="/organizer" element={<Organizer />} />
                <Route path="/session" element={<Session />} />
                <Route path="/sequencer" element={<Sequencer />} />
                <Route path="/matchreplace" element={<MatchReplace />} />
              </Routes>
            </main>
          </div>
        </ThemeProvider>
      </ShortcutHelpProvider>
    </ToastProvider>
  );
};

export default App;

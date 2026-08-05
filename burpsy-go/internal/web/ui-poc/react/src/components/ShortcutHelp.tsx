import React from 'react';
import { createPortal } from 'react-dom';

interface ShortcutHelpProps {
  isOpen: boolean;
  onClose: () => void;
}

const SHORTCUTS = [
  { keys: ['Ctrl+R'], action: 'Send to Repeater', context: 'History, Scanner, Site map, WS History' },
  { keys: ['Ctrl+I'], action: 'Send to Intruder', context: 'History, Scanner, Site map, WS History' },
  { keys: ['Ctrl+A'], action: 'Send to Comparer (A)', context: 'History, Scanner, Site map, WS History' },
  { keys: ['Ctrl+B'], action: 'Send to Comparer (B)', context: 'History, Scanner, Site map, WS History' },
  { keys: ['↑', '↓'], action: 'Navigate rows', context: 'All tables' },
  { keys: ['Enter'], action: 'Open/Select row', context: 'All tables' },
  { keys: ['Esc'], action: 'Close modal/deselect', context: 'All' },
  { keys: ['?'], action: 'Show this help', context: 'All' },
];

const ShortcutHelp: React.FC<ShortcutHelpProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;
  
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };
  
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  };
  
  return createPortal(
    <div 
      className="sheet-backdrop" 
      onClick={handleBackdropClick}
      onKeyDown={handleKeyDown}
      tabIndex={-1}
    >
      <div className="sheet" role="dialog" aria-modal="true">
        <h2>Keyboard Shortcuts</h2>
        <p className="hint">Available globally when not typing in an input field</p>
        
        <table className="shortcuts-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Action</th>
              <th>Context</th>
            </tr>
          </thead>
          <tbody>
            {SHORTCUTS.map((shortcut, index) => (
              <tr key={index}>
                <td>
                  {shortcut.keys.map((key, i) => (
                    <kbd key={i}>{key}</kbd>
                  ))}
                </td>
                <td>{shortcut.action}</td>
                <td>{shortcut.context}</td>
              </tr>
            ))}
          </tbody>
        </table>
        
        <div className="sheet-actions">
          <button className="go" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};

// Create a shortcut help context
interface ShortcutHelpContextType {
  isOpen: boolean;
  open: () => void;
  close: () => void;
  toggle: () => void;
}

const ShortcutHelpContext = React.createContext<ShortcutHelpContextType | null>(null);

interface ShortcutHelpProviderProps {
  children: React.ReactNode;
}

const ShortcutHelpProvider: React.FC<ShortcutHelpProviderProps> = ({ children }) => {
  const [isOpen, setIsOpen] = React.useState(false);
  
  const open = () => setIsOpen(true);
  const close = () => setIsOpen(false);
  const toggle = () => setIsOpen((prev) => !prev);
  
  return (
    <ShortcutHelpContext.Provider value={{ isOpen, open, close, toggle }}>
      {children}
      <ShortcutHelp isOpen={isOpen} onClose={close} />
    </ShortcutHelpContext.Provider>
  );
};

// Hook to use shortcut help
export const useShortcutHelp = (): ShortcutHelpContextType => {
  const context = React.useContext(ShortcutHelpContext);
  if (!context) {
    throw new Error('useShortcutHelp must be used within a ShortcutHelpProvider');
  }
  return context;
};

export { ShortcutHelpProvider, ShortcutHelp as default };

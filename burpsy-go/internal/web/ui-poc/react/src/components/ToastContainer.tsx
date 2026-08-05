import React from 'react';
import { createPortal } from 'react-dom';
import type { Toast, ToastType } from '../types';

interface ToastProps {
  toast: Toast;
  onDismiss: (id: string) => void;
}

const ToastComponent: React.FC<ToastProps> = ({ toast, onDismiss }) => {
  const icons: Record<ToastType, string> = {
    info: 'ℹ️',
    success: '✅',
    warning: '⚠️',
    error: '❌',
  };
  
  const colors: Record<ToastType, string> = {
    info: '--acc',
    success: '--http-2xx',
    warning: '--http-4xx',
    error: '--http-5xx',
  };
  
  React.useEffect(() => {
    if (toast.duration && toast.duration > 0) {
      const timer = setTimeout(() => {
        onDismiss(toast.id);
      }, toast.duration);
      return () => clearTimeout(timer);
    }
  }, [toast.id, toast.duration, onDismiss]);
  
  const style = {
    borderColor: `var(${colors[toast.type]})`,
    color: `var(${colors[toast.type]})`,
  };
  
  return (
    <div className={`toast ${toast.type}`} style={style}>
      <span className="toast-icon">{icons[toast.type]}</span>
      <span className="toast-message">{toast.message}</span>
      {toast.dismissible && (
        <button 
          className="toast-dismiss" 
          onClick={() => onDismiss(toast.id)}
          aria-label="Dismiss"
        >
          &times;
        </button>
      )}
    </div>
  );
};

interface ToastContainerProps {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

const ToastContainerContent: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;
  
  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <ToastComponent 
          key={toast.id} 
          toast={toast} 
          onDismiss={onDismiss} 
        />
      ))}
    </div>
  );
};

// Create a toast context
interface ToastContextType {
  addToast: (message: string, type?: ToastType, options?: Partial<Toast>) => string;
  dismissToast: (id: string) => void;
  clearToasts: () => void;
}

const ToastContext = React.createContext<ToastContextType | null>(null);

interface ToastProviderProps {
  children: React.ReactNode;
}

const ToastProvider: React.FC<ToastProviderProps> = ({ children }) => {
  const [toasts, setToasts] = React.useState<Toast[]>([]);
  
  const addToast = (
    message: string,
    type: ToastType = 'info',
    options: Partial<Toast> = {}
  ): string => {
    const id = Date.now().toString();
    const toast: Toast = {
      id,
      type,
      message,
      dismissible: true,
      duration: type === 'error' ? 6000 : 4000,
      ...options,
    };
    setToasts((prev) => [...prev, toast]);
    return id;
  };
  
  const dismissToast = (id: string) => {
    setToasts((prev) => prev.filter(t => t.id !== id));
  };
  
  const clearToasts = () => {
    setToasts([]);
  };
  
  return (
    <ToastContext.Provider value={{ addToast, dismissToast, clearToasts }}>
      {children}
      {createPortal(
        <ToastContainerContent toasts={toasts} onDismiss={dismissToast} />,
        document.body
      )}
    </ToastContext.Provider>
  );
};

// Hook to use toasts
export const useToast = (): ToastContextType => {
  const context = React.useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};

// Main export
const ToastContainer: React.FC = () => {
  const { toasts, dismissToast } = useToast();
  return <ToastContainerContent toasts={toasts} onDismiss={dismissToast} />;
};

export { ToastProvider, ToastContainer as default };

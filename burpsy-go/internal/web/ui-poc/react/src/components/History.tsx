import React from 'react';
import { useHistoryStore, selectFilteredExchanges, selectSelectedExchange, selectSelectedCount, selectHasSelection } from '../store';
import { api } from '../services/api';
import { useToast } from './ToastContainer';
import Table from './Table';
import type { Exchange } from '../types';

const History: React.FC = () => {
  const toast = useToast();
  const {
    exchanges,
    loading,
    error,
    selectedId,
    searchQuery,
    statusFilters,
    scopeOnly,
    selectedRows,
    setExchanges,
    setLoading,
    setError,
    setSelectedId,
    setSearchQuery,
    toggleStatusFilter,
    setScopeOnly,
    toggleRowSelection,
    selectAllRows,
    clearSelection,
  } = useHistoryStore();
  
  const filteredExchanges = useHistoryStore(selectFilteredExchanges);
  const selectedExchange = useHistoryStore(selectSelectedExchange);
  const selectedCount = useHistoryStore(selectSelectedCount);
  const hasSelection = useHistoryStore(selectHasSelection);
  
  // Fetch history on mount
  React.useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const data = await api.getHistory(300);
        setExchanges(data);
      } catch (e) {
        setError((e as Error).message);
        toast((e as Error).message, 'error');
      } finally {
        setLoading(false);
      }
    };
    
    fetchHistory();
  }, [setExchanges, setLoading, setError, toast]);
  
  // Set up live updates via EventSource
  React.useEffect(() => {
    const eventSource = new EventSource('/api/events');
    
    eventSource.onmessage = (e) => {
      try {
        const frame = JSON.parse(e.data);
        if (frame.kind === 'history') {
          // Refresh history when new data arrives
          api.getHistory(300).then(setExchanges).catch(console.error);
        }
      } catch {
        // Ignore malformed frames
      }
    };
    
    return () => eventSource.close();
  }, [setExchanges]);
  
  // Load selected exchange details
  React.useEffect(() => {
    if (selectedId) {
      const fetchExchange = async () => {
        try {
          const exchange = await api.getExchange(selectedId);
          // In a real implementation, we'd store this or use it directly
        } catch (e) {
          toast((e as Error).message, 'error');
        }
      };
      fetchExchange();
    }
  }, [selectedId, toast]);
  
  const handleRowClick = (exchange: Exchange) => {
    setSelectedId(exchange.id);
  };
  
  const handleBulkSendToIntruder = () => {
    if (selectedRows.size === 0) {
      toast('Please select at least one row', 'warning');
      return;
    }
    toast(`Sending ${selectedRows.size} items to Intruder`, 'info');
    clearSelection();
  };
  
  const handleBulkSaveToOrganizer = () => {
    if (selectedRows.size === 0) {
      toast('Please select at least one row', 'warning');
      return;
    }
    toast(`Saving ${selectedRows.size} items to Organizer`, 'info');
    clearSelection();
  };
  
  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };
  
  const statusBadge = (status: number | null): React.ReactNode => {
    if (status === null) return '-';
    const className = `s${String(status)[0]}`;
    return <span className={className}>{status}</span>;
  };
  
  const columns = [
    { key: 'id', header: '#', sortable: true, width: '40px' },
    { key: 'method', header: 'Method', sortable: true, width: '80px' },
    { key: 'host', header: 'Host', sortable: true },
    { key: 'path', header: 'Path', sortable: true },
    { key: 'status', header: 'Status', sortable: true, width: '60px', render: (item: Exchange) => statusBadge(item.status) },
    { key: 'response_len', header: 'Len', sortable: true, width: '80px', render: (item: Exchange) => formatBytes(item.response_len) },
    { key: 'duration_ms', header: 'ms', sortable: true, width: '60px' },
    { key: 'tls', header: 'TLS', width: '40px', render: (item: Exchange) => item.tls ? '✓' : '' },
  ];
  
  return (
    <section className="history-tab">
      <div className="tab-header">
        <div className="hint">
          right-click a row for send-to actions · Ctrl+R Repeater · Ctrl+I Intruder · ? for all shortcuts
        </div>
        {error && <div className="error-message">{error}</div>}
      </div>
      
      <div className="filters">
        <div className="filter-group">
          <label>
            <input
              type="checkbox"
              checked={statusFilters.has('2')}
              onChange={() => toggleStatusFilter('2')}
            /> 2xx
          </label>
          <label>
            <input
              type="checkbox"
              checked={statusFilters.has('3')}
              onChange={() => toggleStatusFilter('3')}
            /> 3xx
          </label>
          <label>
            <input
              type="checkbox"
              checked={statusFilters.has('4')}
              onChange={() => toggleStatusFilter('4')}
            /> 4xx
          </label>
          <label>
            <input
              type="checkbox"
              checked={statusFilters.has('5')}
              onChange={() => toggleStatusFilter('5')}
            /> 5xx
          </label>
          <label>
            <input
              type="checkbox"
              checked={scopeOnly}
              onChange={(e) => setScopeOnly(e.target.checked)}
            /> in scope only
          </label>
        </div>
        
        <div className="filter-group">
          <input
            type="text"
            placeholder="filter method/host/path"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
      </div>
      
      {hasSelection && (
        <div className="bulk-actions">
          <span className="count">{selectedCount} selected</span>
          <div className="actions">
            <button className="ghost small" onClick={handleBulkSendToIntruder}>
              Send to Intruder
            </button>
            <button className="ghost small" onClick={handleBulkSaveToOrganizer}>
              Save to Organizer
            </button>
            <button className="ghost small" onClick={clearSelection}>
              Clear
            </button>
          </div>
        </div>
      )}
      
      <Table
        data={filteredExchanges}
        columns={columns}
        keyExtractor={(item) => item.id}
        onRowClick={handleRowClick}
        onRowSelect={toggleRowSelection}
        selectedRows={selectedRows}
        emptyMessage="No traffic captured yet. Configure your browser to use burpsy as proxy: http://localhost:8080"
        loading={loading}
      />
      
      {selectedExchange && (
        <div className="detail-panel two">
          <div>
            <div className="viewer-header">
              <b className="muted">Request</b>
              <button className="ghost small">Copy</button>
            </div>
            <div className="code-viewer">
              <pre>{selectedExchange?.request?.toString()}</pre>
            </div>
          </div>
          <div>
            <div className="viewer-header">
              <b className="muted">Response</b>
              <button className="ghost small">Copy</button>
            </div>
            <div className="code-viewer">
              <pre>{selectedExchange?.response?.toString()}</pre>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export default History;

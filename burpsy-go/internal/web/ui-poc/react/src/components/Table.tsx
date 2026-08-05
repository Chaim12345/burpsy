import React from 'react';
import type { TableProps, Column } from '../types';

interface TableHeaderProps<T> {
  columns: Column<T>[];
  onSort?: (key: string) => void;
  sortBy?: string;
  sortDirection?: 'asc' | 'desc';
}

const TableHeader = <T,>({ 
  columns, 
  onSort, 
  sortBy, 
  sortDirection 
}: TableHeaderProps<T>): React.ReactElement => {
  return (
    <thead>
      <tr>
        {columns.map((column) => (
          <th
            key={column.key}
            className={column.className}
            style={{ width: column.width }}
            onClick={() => onSort?.(column.key)}
          >
            <div className="table-header-content">
              {column.header}
              {onSort && column.sortable && (
                <span className="sort-indicator">
                  {sortBy === column.key && (
                    sortDirection === 'asc' ? ' ↑' : ' ↓'
                  )}
                </span>
              )}
            </div>
          </th>
        ))}
      </tr>
    </thead>
  );
};

interface TableBodyProps<T> {
  data: T[];
  columns: Column<T>[];
  keyExtractor: (item: T) => string | number;
  onRowClick?: (item: T) => void;
  onRowSelect?: (selected: Set<string | number>) => void;
  selectedRows?: Set<string | number>;
  emptyMessage?: string;
  loading?: boolean;
}

const TableBody = <T,>({ 
  data, 
  columns, 
  keyExtractor,
  onRowClick,
  onRowSelect,
  selectedRows = new Set(),
  emptyMessage = 'No data available',
  loading = false,
}: TableBodyProps<T>): React.ReactElement => {
  const handleRowClick = (item: T) => {
    if (onRowClick) {
      onRowClick(item);
    }
  };
  
  const handleCheckboxChange = (key: string | number) => {
    if (onRowSelect) {
      const newSelection = new Set(selectedRows);
      if (newSelection.has(key)) {
        newSelection.delete(key);
      } else {
        newSelection.add(key);
      }
      onRowSelect(newSelection);
    }
  };
  
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (onRowSelect) {
      if (e.target.checked) {
        onRowSelect(new Set(data.map(keyExtractor)));
      } else {
        onRowSelect(new Set());
      }
    }
  };
  
  const hasSelection = selectedRows.size > 0;
  const allSelected = data.length > 0 && selectedRows.size === data.length;
  
  if (loading) {
    return (
      <tbody>
        <tr>
          <td colSpan={columns.length + (onRowSelect ? 1 : 0)} className="loading-state">
            <span className="spinner" /> Loading...
          </td>
        </tr>
      </tbody>
    );
  }
  
  if (data.length === 0) {
    return (
      <tbody>
        <tr>
          <td colSpan={columns.length + (onRowSelect ? 1 : 0)} className="empty-state">
            <div className="empty-icon">📭</div>
            <div className="empty-title">No data available</div>
            <div className="empty-hint">{emptyMessage}</div>
          </td>
        </tr>
      </tbody>
    );
  }
  
  return (
    <tbody>
      {data.map((item) => {
        const key = keyExtractor(item);
        const isSelected = selectedRows.has(key);
        
        return (
          <tr
            key={key}
            className={isSelected ? 'selected' : ''}
            onClick={() => handleRowClick(item)}
          >
            {onRowSelect && (
              <td className="select-col">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => handleCheckboxChange(key)}
                  onClick={(e) => e.stopPropagation()}
                />
              </td>
            )}
            {columns.map((column) => (
              <td key={column.key} className={column.className}>
                {column.render 
                  ? column.render(item) 
                  : (item as any)[column.key]}
              </td>
            ))}
          </tr>
        );
      })}
    </tbody>
  );
};

const Table = <T,>({ 
  data, 
  columns, 
  keyExtractor,
  onRowClick,
  onRowSelect,
  selectedRows,
  emptyMessage,
  loading,
}: TableProps<T>): React.ReactElement => {
  const [sortBy, setSortBy] = React.useState<string | null>(null);
  const [sortDirection, setSortDirection] = React.useState<'asc' | 'desc'>('asc');
  
  const handleSort = (key: string) => {
    if (sortBy === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(key);
      setSortDirection('asc');
    }
  };
  
  // Sort data if sorting is enabled
  const sortedData = React.useMemo(() => {
    if (!sortBy) return data;
    
    return [...data].sort((a, b) => {
      const aVal = (a as any)[sortBy];
      const bVal = (b as any)[sortBy];
      
      if (aVal === null || aVal === undefined) return sortDirection === 'asc' ? 1 : -1;
      if (bVal === null || bVal === undefined) return sortDirection === 'asc' ? -1 : 1;
      
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }
      
      const aStr = String(aVal);
      const bStr = String(bVal);
      return sortDirection === 'asc' 
        ? aStr.localeCompare(bStr)
        : bStr.localeCompare(aStr);
    });
  }, [data, sortBy, sortDirection]);
  
  return (
    <div className="table-container">
      <table className="table">
        <TableHeader
          columns={columns}
          onSort={handleSort}
          sortBy={sortBy}
          sortDirection={sortDirection}
        />
        <TableBody
          data={sortedData}
          columns={columns}
          keyExtractor={keyExtractor}
          onRowClick={onRowClick}
          onRowSelect={onRowSelect}
          selectedRows={selectedRows}
          emptyMessage={emptyMessage}
          loading={loading}
        />
      </table>
      {onRowSelect && data.length > 0 && (
        <div className="bulk-actions">
          <span className="count">{selectedRows?.size || 0} selected</span>
          <div className="actions">
            <button className="ghost small" onClick={() => onRowSelect?.(new Set())}>
              Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Table;

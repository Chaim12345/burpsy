import React from 'react';

interface PlaceholderProps {
  title: string;
  description: string;
  icon?: string;
}

const Placeholder: React.FC<PlaceholderProps> = ({ 
  title, 
  description, 
  icon = '🚧' 
}) => {
  return (
    <section className="placeholder-tab">
      <div className="placeholder-content">
        <div className="placeholder-icon">{icon}</div>
        <h2 className="placeholder-title">{title}</h2>
        <p className="placeholder-description">{description}</p>
        <p className="placeholder-hint">
          This component would be implemented in a full React migration.
        </p>
      </div>
    </section>
  );
};

export default Placeholder;

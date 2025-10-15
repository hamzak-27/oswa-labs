import React from 'react';

const Alert = ({ children, variant = 'default', className = '' }) => {
  const variants = {
    default: 'border-gray-200 bg-gray-50 text-gray-900',
    destructive: 'border-red-200 bg-red-50 text-red-900',
    warning: 'border-yellow-200 bg-yellow-50 text-yellow-900',
    info: 'border-blue-200 bg-blue-50 text-blue-900'
  };

  return (
    <div className={`relative w-full rounded-lg border px-4 py-3 text-sm ${variants[variant]} ${className}`}>
      {children}
    </div>
  );
};

const AlertDescription = ({ children, className = '' }) => {
  return (
    <div className={`text-sm [&_p]:leading-relaxed ${className}`}>
      {children}
    </div>
  );
};

const AlertTitle = ({ children, className = '' }) => {
  return (
    <h5 className={`mb-1 font-medium leading-none tracking-tight ${className}`}>
      {children}
    </h5>
  );
};

export { Alert, AlertDescription, AlertTitle };
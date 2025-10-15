import { useState, useEffect, useContext, createContext, ReactNode } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider = ({ children }: { children: ReactNode }) => {
  const [theme, setThemeState] = useState<Theme>('light');

  // Initialize theme from localStorage or system preference
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') as Theme;
    const systemPreference = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    
    const initialTheme = savedTheme || systemPreference;
    setThemeState(initialTheme);
    
    // Apply theme to document
    if (initialTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme);
    localStorage.setItem('theme', newTheme);
    
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
  };

  const value: ThemeContextType = {
    theme,
    toggleTheme,
    setTheme
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

// Theme utility functions
export const getSystemTheme = (): Theme => {
  if (typeof window !== 'undefined') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return 'light';
};

export const getSavedTheme = (): Theme | null => {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('theme') as Theme | null;
  }
  return null;
};

// Theme-specific color utilities
export const getThemeColors = (theme: Theme) => {
  const colors = {
    light: {
      background: '#ffffff',
      foreground: '#000000',
      card: '#f8fafc',
      cardForeground: '#0f172a',
      popover: '#ffffff',
      popoverForeground: '#0f172a',
      primary: '#0f172a',
      primaryForeground: '#f8fafc',
      secondary: '#f1f5f9',
      secondaryForeground: '#0f172a',
      muted: '#f1f5f9',
      mutedForeground: '#64748b',
      accent: '#f1f5f9',
      accentForeground: '#0f172a',
      destructive: '#ef4444',
      destructiveForeground: '#f8fafc',
      border: '#e2e8f0',
      input: '#e2e8f0',
      ring: '#0f172a',
    },
    dark: {
      background: '#0f172a',
      foreground: '#f8fafc',
      card: '#1e293b',
      cardForeground: '#f8fafc',
      popover: '#1e293b',
      popoverForeground: '#f8fafc',
      primary: '#f8fafc',
      primaryForeground: '#0f172a',
      secondary: '#1e293b',
      secondaryForeground: '#f8fafc',
      muted: '#1e293b',
      mutedForeground: '#94a3b8',
      accent: '#1e293b',
      accentForeground: '#f8fafc',
      destructive: '#ef4444',
      destructiveForeground: '#f8fafc',
      border: '#1e293b',
      input: '#1e293b',
      ring: '#94a3b8',
    }
  };

  return colors[theme];
};
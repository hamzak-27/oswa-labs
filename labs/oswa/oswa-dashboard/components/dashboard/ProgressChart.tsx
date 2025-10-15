import { motion } from 'framer-motion';
import { useState } from 'react';

interface ProgressData {
  date: string;
  flags: number;
  labs: number;
  points: number;
}

const mockProgressData: ProgressData[] = [
  { date: '2024-01-01', flags: 0, labs: 0, points: 0 },
  { date: '2024-01-02', flags: 2, labs: 0, points: 200 },
  { date: '2024-01-03', flags: 3, labs: 1, points: 350 },
  { date: '2024-01-04', flags: 5, labs: 1, points: 550 },
  { date: '2024-01-05', flags: 8, labs: 2, points: 850 },
  { date: '2024-01-06', flags: 12, labs: 2, points: 1250 },
  { date: '2024-01-07', flags: 15, labs: 3, points: 1550 }
];

export default function ProgressChart() {
  const [activeTab, setActiveTab] = useState<'flags' | 'labs' | 'points'>('flags');
  
  const maxValue = Math.max(...mockProgressData.map(d => {
    switch (activeTab) {
      case 'flags': return d.flags;
      case 'labs': return d.labs;
      case 'points': return d.points;
      default: return d.flags;
    }
  }));

  const getColor = () => {
    switch (activeTab) {
      case 'flags': return 'cyber';
      case 'labs': return 'flag';
      case 'points': return 'warn';
      default: return 'cyber';
    }
  };

  const color = getColor();

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6 border border-gray-200 dark:border-dark-700"
    >
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Progress Overview
        </h3>
        
        {/* Tab Selector */}
        <div className="flex bg-gray-100 dark:bg-dark-700 rounded-lg p-1">
          {(['flags', 'labs', 'points'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1 text-sm font-medium rounded-md transition-colors ${
                activeTab === tab
                  ? 'bg-white dark:bg-dark-600 text-gray-900 dark:text-white shadow-sm'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Chart Area */}
      <div className="relative h-64">
        <div className="absolute inset-0 flex items-end justify-between space-x-2">
          {mockProgressData.map((data, index) => {
            const value = (() => {
              switch (activeTab) {
                case 'flags': return data.flags;
                case 'labs': return data.labs;
                case 'points': return data.points;
                default: return data.flags;
              }
            })();
            
            const height = maxValue > 0 ? (value / maxValue) * 100 : 0;
            
            return (
              <motion.div
                key={data.date}
                initial={{ height: 0 }}
                animate={{ height: `${height}%` }}
                transition={{ duration: 0.8, delay: index * 0.1 }}
                className="flex-1 relative group"
              >
                <div className={`w-full rounded-t-lg bg-gradient-to-t from-${color}-500 to-${color}-400 hover:from-${color}-600 hover:to-${color}-500 transition-colors`}>
                  {/* Tooltip */}
                  <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <div className="bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 text-xs rounded-lg px-2 py-1 whitespace-nowrap">
                      <div className="font-medium">{new Date(data.date).toLocaleDateString()}</div>
                      <div>
                        {activeTab === 'flags' && `${value} flags`}
                        {activeTab === 'labs' && `${value} labs`}
                        {activeTab === 'points' && `${value} points`}
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Date Label */}
                <div className="text-xs text-gray-500 dark:text-gray-400 text-center mt-2">
                  {new Date(data.date).toLocaleDateString('en-US', { 
                    month: 'short', 
                    day: 'numeric' 
                  })}
                </div>
              </motion.div>
            );
          })}
        </div>
        
        {/* Y-Axis Labels */}
        <div className="absolute left-0 top-0 h-full flex flex-col justify-between text-xs text-gray-500 dark:text-gray-400">
          <span>{maxValue}</span>
          <span>{Math.round(maxValue * 0.75)}</span>
          <span>{Math.round(maxValue * 0.5)}</span>
          <span>{Math.round(maxValue * 0.25)}</span>
          <span>0</span>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-3 gap-4 mt-6 pt-6 border-t border-gray-200 dark:border-dark-700">
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {mockProgressData[mockProgressData.length - 1]?.flags || 0}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">Total Flags</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {mockProgressData[mockProgressData.length - 1]?.labs || 0}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">Labs Completed</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {mockProgressData[mockProgressData.length - 1]?.points || 0}
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">Total Points</div>
        </div>
      </div>
    </motion.div>
  );
}
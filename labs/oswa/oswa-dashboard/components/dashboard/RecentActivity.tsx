import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import {
  FlagIcon,
  TrophyIcon,
  PlayIcon,
  StopIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

interface Activity {
  id: string;
  type: 'flag_found' | 'lab_completed' | 'lab_started' | 'lab_stopped' | 'achievement';
  title: string;
  description: string;
  timestamp: Date;
  icon: any;
  color: string;
}

const mockActivities: Activity[] = [
  {
    id: '1',
    type: 'flag_found',
    title: 'Flag Captured',
    description: 'Found XSS_BASIC_REFLECTED in XSS Lab',
    timestamp: new Date(Date.now() - 2 * 60 * 1000),
    icon: FlagIcon,
    color: 'cyber'
  },
  {
    id: '2',
    type: 'lab_started',
    title: 'Lab Started',
    description: 'Started JWT Attacks Lab',
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
    icon: PlayIcon,
    color: 'flag'
  },
  {
    id: '3',
    type: 'achievement',
    title: 'Achievement Unlocked',
    description: 'First Blood - Completed your first lab',
    timestamp: new Date(Date.now() - 45 * 60 * 1000),
    icon: TrophyIcon,
    color: 'warn'
  },
  {
    id: '4',
    type: 'flag_found',
    title: 'Flag Captured',
    description: 'Found JWT_WEAK_SECRET in JWT Lab',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    icon: FlagIcon,
    color: 'cyber'
  },
  {
    id: '5',
    type: 'lab_completed',
    title: 'Lab Completed',
    description: 'Completed XSS Vulnerabilities Lab',
    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000),
    icon: TrophyIcon,
    color: 'flag'
  }
];

const formatTimeAgo = (date: Date): string => {
  const now = new Date();
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
  
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
};

export default function RecentActivity() {
  const [mounted, setMounted] = useState(false);
  
  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6 border border-gray-200 dark:border-dark-700"
    >
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
          <ClockIcon className="w-5 h-5 mr-2 text-cyber-600" />
          Recent Activity
        </h3>
        <button className="text-sm text-cyber-600 hover:text-cyber-700 dark:text-cyber-400 dark:hover:text-cyber-300">
          View All
        </button>
      </div>

      <div className="space-y-4">
        {mockActivities.map((activity, index) => {
          const Icon = activity.icon;
          
          return (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
              className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-700 transition-colors"
            >
              {/* Icon */}
              <div className={`flex-shrink-0 p-2 rounded-lg bg-${activity.color}-100 dark:bg-${activity.color}-900/20`}>
                <Icon className={`w-4 h-4 text-${activity.color}-600 dark:text-${activity.color}-400`} />
              </div>
              
              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {activity.title}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {mounted ? formatTimeAgo(activity.timestamp) : 'Just now'}
                  </p>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {activity.description}
                </p>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Activity Summary */}
      <div className="mt-6 pt-6 border-t border-gray-200 dark:border-dark-700">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {mockActivities.filter(a => a.type === 'flag_found').length}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Flags Today</div>
          </div>
          <div>
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {mockActivities.filter(a => a.type === 'lab_started').length}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Labs Started</div>
          </div>
          <div>
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {mockActivities.filter(a => a.type === 'achievement').length}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Achievements</div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
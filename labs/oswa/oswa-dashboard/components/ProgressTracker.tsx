import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  TrophyIcon,
  FireIcon,
  ChartBarIcon,
  FlagIcon,
  ClockIcon,
  CalendarIcon,
  StarIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';
import { TrophyIcon as TrophySolidIcon } from '@heroicons/react/24/solid';
import { useQuery } from 'react-query';
import { CircularProgressbar, CircularProgressbarWithChildren, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';

interface UserProgress {
  totalLabs: number;
  completedLabs: number;
  totalFlags: number;
  foundFlags: number;
  totalTime: string;
  rank: number;
  streak: number;
  achievements: Array<{
    id: string;
    name: string;
    description: string;
    icon: string;
    unlockedAt?: Date;
  }>;
  recentActivity: Array<{
    id: string;
    type: 'lab_completed' | 'flag_found' | 'achievement_unlocked';
    description: string;
    timestamp: Date;
    labName?: string;
    flagName?: string;
  }>;
}

export default function ProgressTracker() {
  const [selectedTab, setSelectedTab] = useState<'overview' | 'achievements' | 'activity'>('overview');

  // Fetch user progress
  const { data: userProgress, isLoading } = useQuery<UserProgress>(
    'user-progress',
    async () => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/user/progress`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch progress');
      return response.json();
    },
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  );

  // Mock data for development
  const mockProgress: UserProgress = {
    totalLabs: 8,
    completedLabs: 3,
    totalFlags: 24,
    foundFlags: 12,
    totalTime: '14h 32m',
    rank: 157,
    streak: 7,
    achievements: [
      {
        id: 'first_blood',
        name: 'First Blood',
        description: 'Complete your first lab',
        icon: '🩸',
        unlockedAt: new Date('2024-01-15')
      },
      {
        id: 'xss_master',
        name: 'XSS Master',
        description: 'Find all XSS vulnerabilities',
        icon: '⚡',
        unlockedAt: new Date('2024-01-20')
      },
      {
        id: 'jwt_hunter',
        name: 'JWT Hunter',
        description: 'Complete JWT Attacks lab',
        icon: '🔐',
        unlockedAt: new Date('2024-01-22')
      },
      {
        id: 'speed_runner',
        name: 'Speed Runner',
        description: 'Complete a lab in under 2 hours',
        icon: '🏃',
      },
      {
        id: 'night_owl',
        name: 'Night Owl',
        description: 'Complete a lab after midnight',
        icon: '🦉',
      }
    ],
    recentActivity: [
      {
        id: '1',
        type: 'flag_found',
        description: 'Found flag: SQL_INJECTION_MASTER',
        labName: 'SQL Injection Lab',
        flagName: 'SQL_INJECTION_MASTER',
        timestamp: new Date('2024-01-22T14:30:00')
      },
      {
        id: '2',
        type: 'achievement_unlocked',
        description: 'Unlocked achievement: JWT Hunter',
        timestamp: new Date('2024-01-22T13:15:00')
      },
      {
        id: '3',
        type: 'lab_completed',
        description: 'Completed JWT Attacks Lab',
        labName: 'JWT Attacks Lab',
        timestamp: new Date('2024-01-22T13:10:00')
      }
    ]
  };

  const progress = userProgress || mockProgress;
  const labCompletionPercentage = Math.round((progress.completedLabs / progress.totalLabs) * 100);
  const flagCompletionPercentage = Math.round((progress.foundFlags / progress.totalFlags) * 100);

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'lab_completed': return TrophySolidIcon;
      case 'flag_found': return FlagIcon;
      case 'achievement_unlocked': return StarIcon;
      default: return CheckCircleIcon;
    }
  };

  const getActivityColor = (type: string) => {
    switch (type) {
      case 'lab_completed': return 'text-flag-600 bg-flag-100 dark:bg-flag-900/20';
      case 'flag_found': return 'text-cyber-600 bg-cyber-100 dark:bg-cyber-900/20';
      case 'achievement_unlocked': return 'text-warn-600 bg-warn-100 dark:bg-warn-900/20';
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-700';
    }
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
    
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  };

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-300 rounded w-1/4 mb-4"></div>
          <div className="space-y-3">
            <div className="h-3 bg-gray-300 rounded w-full"></div>
            <div className="h-3 bg-gray-300 rounded w-3/4"></div>
            <div className="h-3 bg-gray-300 rounded w-1/2"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-dark-800 rounded-xl shadow-lg border border-gray-200 dark:border-dark-700">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200 dark:border-dark-700">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center">
          <ChartBarIcon className="w-6 h-6 mr-2 text-cyber-600" />
          Progress Tracker
        </h2>
        
        {/* Tab Navigation */}
        <div className="flex space-x-1 mt-4">
          {[
            { key: 'overview', label: 'Overview' },
            { key: 'achievements', label: 'Achievements' },
            { key: 'activity', label: 'Recent Activity' }
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setSelectedTab(tab.key as any)}
              className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                selectedTab === tab.key
                  ? 'bg-cyber-100 text-cyber-700 dark:bg-cyber-900/20 dark:text-cyber-300'
                  : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6">
        {selectedTab === 'overview' && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <motion.div
                whileHover={{ scale: 1.05 }}
                className="bg-gradient-to-r from-flag-500 to-flag-600 rounded-lg p-4 text-white"
              >
                <TrophyIcon className="w-8 h-8 mb-2" />
                <p className="text-2xl font-bold">{progress.completedLabs}</p>
                <p className="text-flag-100 text-sm">Labs Completed</p>
              </motion.div>

              <motion.div
                whileHover={{ scale: 1.05 }}
                className="bg-gradient-to-r from-cyber-500 to-cyber-600 rounded-lg p-4 text-white"
              >
                <FlagIcon className="w-8 h-8 mb-2" />
                <p className="text-2xl font-bold">{progress.foundFlags}</p>
                <p className="text-cyber-100 text-sm">Flags Found</p>
              </motion.div>

              <motion.div
                whileHover={{ scale: 1.05 }}
                className="bg-gradient-to-r from-warn-500 to-warn-600 rounded-lg p-4 text-white"
              >
                <ClockIcon className="w-8 h-8 mb-2" />
                <p className="text-2xl font-bold">{progress.totalTime}</p>
                <p className="text-warn-100 text-sm">Time Spent</p>
              </motion.div>

              <motion.div
                whileHover={{ scale: 1.05 }}
                className="bg-gradient-to-r from-vuln-500 to-vuln-600 rounded-lg p-4 text-white"
              >
                <FireIcon className="w-8 h-8 mb-2" />
                <p className="text-2xl font-bold">{progress.streak}</p>
                <p className="text-vuln-100 text-sm">Day Streak</p>
              </motion.div>
            </div>

            {/* Progress Circles */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="text-center">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Lab Completion</h3>
                <div className="w-32 h-32 mx-auto">
                  <CircularProgressbarWithChildren
                    value={labCompletionPercentage}
                    styles={buildStyles({
                      pathColor: '#10B981',
                      textColor: '#10B981',
                      trailColor: '#E5E7EB'
                    })}
                  >
                    <div className="text-center">
                      <div className="text-2xl font-bold text-flag-600">{labCompletionPercentage}%</div>
                      <div className="text-xs text-gray-500">{progress.completedLabs}/{progress.totalLabs}</div>
                    </div>
                  </CircularProgressbarWithChildren>
                </div>
              </div>

              <div className="text-center">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">Flag Progress</h3>
                <div className="w-32 h-32 mx-auto">
                  <CircularProgressbarWithChildren
                    value={flagCompletionPercentage}
                    styles={buildStyles({
                      pathColor: '#3B82F6',
                      textColor: '#3B82F6',
                      trailColor: '#E5E7EB'
                    })}
                  >
                    <div className="text-center">
                      <div className="text-2xl font-bold text-cyber-600">{flagCompletionPercentage}%</div>
                      <div className="text-xs text-gray-500">{progress.foundFlags}/{progress.totalFlags}</div>
                    </div>
                  </CircularProgressbarWithChildren>
                </div>
              </div>
            </div>

            {/* Rank Info */}
            <div className="bg-gradient-to-r from-gray-50 to-gray-100 dark:from-dark-700 dark:to-dark-600 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">Global Rank</h3>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">Your position on the leaderboard</p>
                </div>
                <div className="text-right">
                  <p className="text-3xl font-bold text-cyber-600">#{progress.rank}</p>
                  <p className="text-sm text-green-600">↗ +12 this week</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'achievements' && (
          <div className="space-y-4">
            {progress.achievements.map((achievement) => (
              <motion.div
                key={achievement.id}
                whileHover={{ scale: 1.02 }}
                className={`flex items-center space-x-4 p-4 rounded-lg border ${
                  achievement.unlockedAt
                    ? 'bg-flag-50 border-flag-200 dark:bg-flag-900/10 dark:border-flag-800'
                    : 'bg-gray-50 border-gray-200 dark:bg-dark-700 dark:border-dark-600 opacity-60'
                }`}
              >
                <div className={`text-3xl ${achievement.unlockedAt ? '' : 'grayscale'}`}>
                  {achievement.icon}
                </div>
                <div className="flex-1">
                  <h3 className={`font-semibold ${
                    achievement.unlockedAt ? 'text-gray-900 dark:text-white' : 'text-gray-500 dark:text-gray-400'
                  }`}>
                    {achievement.name}
                  </h3>
                  <p className={`text-sm ${
                    achievement.unlockedAt ? 'text-gray-600 dark:text-gray-300' : 'text-gray-400 dark:text-gray-500'
                  }`}>
                    {achievement.description}
                  </p>
                  {achievement.unlockedAt && (
                    <p className="text-xs text-flag-600 mt-1">
                      Unlocked {formatTimeAgo(new Date(achievement.unlockedAt))}
                    </p>
                  )}
                </div>
                {achievement.unlockedAt && (
                  <CheckCircleIcon className="w-6 h-6 text-flag-500" />
                )}
              </motion.div>
            ))}
          </div>
        )}

        {selectedTab === 'activity' && (
          <div className="space-y-3">
            {progress.recentActivity.map((activity) => {
              const ActivityIcon = getActivityIcon(activity.type);
              const colorClasses = getActivityColor(activity.type);
              
              return (
                <motion.div
                  key={activity.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center space-x-3 p-3 bg-gray-50 dark:bg-dark-700 rounded-lg"
                >
                  <div className={`p-2 rounded-full ${colorClasses}`}>
                    <ActivityIcon className="w-4 h-4" />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm text-gray-900 dark:text-white">
                      {activity.description}
                    </p>
                    {activity.labName && (
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Lab: {activity.labName}
                      </p>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 dark:text-gray-500">
                    {formatTimeAgo(new Date(activity.timestamp))}
                  </p>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
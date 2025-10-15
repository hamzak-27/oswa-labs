import { motion } from 'framer-motion';
import {
  PlayIcon,
  StopIcon,
  FlagIcon,
  ClockIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';

interface LabStatus {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'starting' | 'stopping';
  url?: string;
  vpnIP?: string;
  vpnPort?: number;
  flags: number;
  totalFlags: number;
  difficulty: 'easy' | 'medium' | 'hard';
  description: string;
  category: string;
}

interface LabCardProps {
  lab: LabStatus;
  onStart: () => void;
  onStop: () => void;
  onSelectForFlag: () => void;
  delay?: number;
}

export default function LabCard({
  lab,
  onStart,
  onStop,
  onSelectForFlag,
  delay = 0
}: LabCardProps) {
  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'flag';
      case 'medium': return 'warn';
      case 'hard': return 'vuln';
      default: return 'cyber';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-flag-600 bg-flag-100 dark:bg-flag-900/20';
      case 'starting': return 'text-warn-600 bg-warn-100 dark:bg-warn-900/20';
      case 'stopping': return 'text-warn-600 bg-warn-100 dark:bg-warn-900/20';
      case 'stopped': return 'text-gray-600 bg-gray-100 dark:bg-gray-700';
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-700';
    }
  };

  const difficultyColor = getDifficultyColor(lab.difficulty);
  const statusColor = getStatusColor(lab.status);
  const progressPercentage = Math.round((lab.flags / lab.totalFlags) * 100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5 }}
      className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6 border border-gray-200 dark:border-dark-700 hover:shadow-xl transition-all duration-300"
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-2">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white">
              {lab.name}
            </h3>
            <span className={`px-2 py-1 text-xs font-medium rounded-full bg-${difficultyColor}-100 text-${difficultyColor}-700 dark:bg-${difficultyColor}-900/20 dark:text-${difficultyColor}-300`}>
              {lab.difficulty}
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
            {lab.description}
          </p>
          <div className="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
            <span className="flex items-center">
              <ShieldCheckIcon className="w-4 h-4 mr-1" />
              {lab.category}
            </span>
            {lab.status === 'running' && lab.vpnIP && (
              <span className="flex items-center font-mono bg-flag-50 dark:bg-flag-900/10 px-2 py-1 rounded text-flag-700 dark:text-flag-300">
                🌐 {lab.vpnIP}:{lab.vpnPort || 80}
              </span>
            )}
          </div>
        </div>
        
        <div className={`flex items-center space-x-1 px-2 py-1 rounded-lg ${statusColor}`}>
          <div className={`w-2 h-2 rounded-full ${
            lab.status === 'running' ? 'bg-flag-500' :
            lab.status === 'starting' || lab.status === 'stopping' ? 'bg-warn-500 animate-pulse' :
            'bg-gray-400'
          }`} />
          <span className="text-xs font-medium capitalize">
            {lab.status}
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      {progressPercentage > 0 && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {lab.flags}/{lab.totalFlags} flags
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2 dark:bg-dark-700">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressPercentage}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              className="bg-gradient-to-r from-flag-500 to-flag-600 h-2 rounded-full"
            />
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex space-x-2">
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={lab.status === 'running' ? onStop : onStart}
          disabled={lab.status === 'starting' || lab.status === 'stopping'}
          className={`
            flex-1 flex items-center justify-center space-x-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors
            ${lab.status === 'running' 
              ? 'bg-vuln-100 text-vuln-700 hover:bg-vuln-200 dark:bg-vuln-900/20 dark:text-vuln-300'
              : 'bg-flag-100 text-flag-700 hover:bg-flag-200 dark:bg-flag-900/20 dark:text-flag-300'
            }
            disabled:opacity-50 disabled:cursor-not-allowed
          `}
        >
          {lab.status === 'starting' ? (
            <>
              <div className="w-4 h-4 border-2 border-flag-600 border-t-transparent rounded-full animate-spin" />
              <span>Starting...</span>
            </>
          ) : lab.status === 'stopping' ? (
            <>
              <div className="w-4 h-4 border-2 border-vuln-600 border-t-transparent rounded-full animate-spin" />
              <span>Stopping...</span>
            </>
          ) : lab.status === 'running' ? (
            <>
              <StopIcon className="w-4 h-4" />
              <span>Stop Lab</span>
            </>
          ) : (
            <>
              <PlayIcon className="w-4 h-4" />
              <span>Start Lab</span>
            </>
          )}
        </motion.button>

        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={onSelectForFlag}
          className="flex items-center justify-center px-4 py-2 rounded-lg font-medium text-sm bg-cyber-100 text-cyber-700 hover:bg-cyber-200 dark:bg-cyber-900/20 dark:text-cyber-300"
        >
          <FlagIcon className="w-4 h-4" />
        </motion.button>

        {lab.status === 'running' && lab.url && (
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => window.open(lab.url, '_blank')}
            className="flex items-center justify-center px-4 py-2 rounded-lg font-medium text-sm bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </motion.button>
        )}
      </div>
    </motion.div>
  );
}
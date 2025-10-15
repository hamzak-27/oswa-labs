import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  PlayIcon,
  StopIcon,
  ArrowTopRightOnSquareIcon,
  DocumentIcon,
  CodeBracketIcon,
  BoltIcon,
  ClockIcon,
  ChartBarIcon,
  LockClosedIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { toast } from 'react-hot-toast';

interface Lab {
  id: string;
  name: string;
  category: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  status: 'stopped' | 'starting' | 'running' | 'stopping';
  url?: string;
  estimatedTime: string;
  flags: {
    total: number;
    found: number;
  };
  objectives: string[];
  technologies: string[];
}

interface LabCardProps {
  lab: Lab;
}

export default function LabCard({ lab }: LabCardProps) {
  const [showModal, setShowModal] = useState(false);
  const queryClient = useQueryClient();

  // Lab deployment mutation
  const deployMutation = useMutation(
    async (labId: string) => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/labs/${labId}/deploy`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });
      if (!response.ok) throw new Error('Failed to deploy lab');
      return response.json();
    },
    {
      onSuccess: (data) => {
        queryClient.invalidateQueries(['lab', lab.id]);
        toast.success(`Lab "${lab.name}" is starting up!`);
      },
      onError: (error) => {
        toast.error(`Failed to start lab: ${error}`);
      }
    }
  );

  // Lab stop mutation
  const stopMutation = useMutation(
    async (labId: string) => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/labs/${labId}/stop`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });
      if (!response.ok) throw new Error('Failed to stop lab');
      return response.json();
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['lab', lab.id]);
        toast.success(`Lab "${lab.name}" has been stopped.`);
      },
      onError: (error) => {
        toast.error(`Failed to stop lab: ${error}`);
      }
    }
  );

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'flag';
      case 'intermediate': return 'warn';
      case 'advanced': return 'vuln';
      default: return 'cyber';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'flag';
      case 'starting': return 'warn';
      case 'stopping': return 'warn';
      case 'stopped': return 'cyber';
      default: return 'gray';
    }
  };

  const getStatusIcon = () => {
    switch (lab.status) {
      case 'running': return StopIcon;
      case 'starting': return BoltIcon;
      case 'stopping': return BoltIcon;
      case 'stopped': return PlayIcon;
      default: return PlayIcon;
    }
  };

  const handleAction = () => {
    if (lab.status === 'running') {
      stopMutation.mutate(lab.id);
    } else if (lab.status === 'stopped') {
      deployMutation.mutate(lab.id);
    }
  };

  const StatusIcon = getStatusIcon();
  const difficultyColor = getDifficultyColor(lab.difficulty);
  const statusColor = getStatusColor(lab.status);
  const progressPercentage = Math.round((lab.flags.found / lab.flags.total) * 100);

  return (
    <>
      <motion.div
        whileHover={{ y: -5 }}
        className="bg-white dark:bg-dark-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 border border-gray-200 dark:border-dark-700"
      >
        <div className="p-6">
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
              <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
                {lab.description}
              </p>
            </div>
            
            <div className="flex items-center space-x-2 ml-4">
              {/* Status Badge */}
              <div className={`flex items-center space-x-1 px-2 py-1 rounded-lg bg-${statusColor}-100 dark:bg-${statusColor}-900/20`}>
                <div className={`w-2 h-2 rounded-full bg-${statusColor}-500 ${
                  lab.status === 'starting' || lab.status === 'stopping' ? 'animate-pulse' : ''
                }`} />
                <span className={`text-xs font-medium text-${statusColor}-700 dark:text-${statusColor}-300 capitalize`}>
                  {lab.status}
                </span>
              </div>
            </div>
          </div>

          {/* Progress Bar */}
          {progressPercentage > 0 && (
            <div className="mb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {lab.flags.found}/{lab.flags.total} flags
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

          {/* Meta Information */}
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
              <ClockIcon className="w-4 h-4" />
              <span>{lab.estimatedTime}</span>
            </div>
            <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
              <ChartBarIcon className="w-4 h-4" />
              <span>{lab.category}</span>
            </div>
          </div>

          {/* Technologies */}
          <div className="mb-4">
            <div className="flex flex-wrap gap-2">
              {lab.technologies.slice(0, 3).map((tech, index) => (
                <span
                  key={index}
                  className="px-2 py-1 text-xs font-medium bg-cyber-100 text-cyber-700 rounded dark:bg-cyber-900/20 dark:text-cyber-300"
                >
                  {tech}
                </span>
              ))}
              {lab.technologies.length > 3 && (
                <span className="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-600 rounded dark:bg-dark-700 dark:text-gray-400">
                  +{lab.technologies.length - 3} more
                </span>
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex space-x-2">
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={handleAction}
              disabled={lab.status === 'starting' || lab.status === 'stopping' || deployMutation.isLoading || stopMutation.isLoading}
              className={`
                flex-1 flex items-center justify-center space-x-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors
                ${lab.status === 'running' 
                  ? 'bg-vuln-100 text-vuln-700 hover:bg-vuln-200 dark:bg-vuln-900/20 dark:text-vuln-300'
                  : 'bg-flag-100 text-flag-700 hover:bg-flag-200 dark:bg-flag-900/20 dark:text-flag-300'
                }
                disabled:opacity-50 disabled:cursor-not-allowed
              `}
            >
              <StatusIcon className="w-4 h-4" />
              <span>
                {lab.status === 'starting' ? 'Starting...' : 
                 lab.status === 'stopping' ? 'Stopping...' :
                 lab.status === 'running' ? 'Stop Lab' : 'Start Lab'}
              </span>
            </motion.button>

            {lab.status === 'running' && lab.url && (
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => window.open(lab.url, '_blank')}
                className="flex items-center justify-center px-4 py-2 rounded-lg font-medium text-sm bg-cyber-100 text-cyber-700 hover:bg-cyber-200 dark:bg-cyber-900/20 dark:text-cyber-300"
              >
                <ArrowTopRightOnSquareIcon className="w-4 h-4" />
              </motion.button>
            )}

            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => setShowModal(true)}
              className="flex items-center justify-center px-4 py-2 rounded-lg font-medium text-sm bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300"
            >
              <DocumentIcon className="w-4 h-4" />
            </motion.button>
          </div>
        </div>
      </motion.div>

      {/* Lab Details Modal */}
      <AnimatePresence>
        {showModal && (
          <div className="fixed inset-0 z-50 overflow-y-auto">
            <div className="flex min-h-screen items-center justify-center p-4">
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 bg-gray-500 bg-opacity-75"
                onClick={() => setShowModal(false)}
              />
              
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="relative w-full max-w-2xl transform overflow-hidden rounded-xl bg-white dark:bg-dark-800 shadow-2xl transition-all"
              >
                <div className="px-6 py-4 border-b border-gray-200 dark:border-dark-700">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                      {lab.name} - Lab Details
                    </h3>
                    <button
                      onClick={() => setShowModal(false)}
                      className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div className="px-6 py-4 space-y-6">
                  {/* Description */}
                  <div>
                    <h4 className="font-medium text-gray-900 dark:text-white mb-2">Description</h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {lab.description}
                    </p>
                  </div>

                  {/* Learning Objectives */}
                  <div>
                    <h4 className="font-medium text-gray-900 dark:text-white mb-3">Learning Objectives</h4>
                    <ul className="space-y-2">
                      {lab.objectives.map((objective, index) => (
                        <li key={index} className="flex items-start space-x-2">
                          <CheckCircleIcon className="w-5 h-5 text-flag-500 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-400">
                            {objective}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Technologies */}
                  <div>
                    <h4 className="font-medium text-gray-900 dark:text-white mb-3">Technologies Covered</h4>
                    <div className="flex flex-wrap gap-2">
                      {lab.technologies.map((tech, index) => (
                        <span
                          key={index}
                          className="px-3 py-1 text-sm font-medium bg-cyber-100 text-cyber-700 rounded-lg dark:bg-cyber-900/20 dark:text-cyber-300"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Lab Info Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">Lab Information</h4>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Difficulty:</span>
                          <span className={`font-medium text-${difficultyColor}-700 dark:text-${difficultyColor}-300 capitalize`}>
                            {lab.difficulty}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Category:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{lab.category}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Est. Time:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{lab.estimatedTime}</span>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <h4 className="font-medium text-gray-900 dark:text-white">Progress</h4>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Flags Found:</span>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {lab.flags.found} / {lab.flags.total}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Completion:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{progressPercentage}%</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600 dark:text-gray-400">Status:</span>
                          <span className={`font-medium text-${statusColor}-700 dark:text-${statusColor}-300 capitalize`}>
                            {lab.status}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex space-x-3 pt-4">
                    <button
                      onClick={handleAction}
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
                      <StatusIcon className="w-4 h-4" />
                      <span>
                        {lab.status === 'starting' ? 'Starting...' : 
                         lab.status === 'stopping' ? 'Stopping...' :
                         lab.status === 'running' ? 'Stop Lab' : 'Start Lab'}
                      </span>
                    </button>

                    {lab.status === 'running' && lab.url && (
                      <button
                        onClick={() => {
                          window.open(lab.url, '_blank');
                          setShowModal(false);
                        }}
                        className="btn-primary flex items-center space-x-2"
                      >
                        <ArrowTopRightOnSquareIcon className="w-4 h-4" />
                        <span>Access Lab</span>
                      </button>
                    )}
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}
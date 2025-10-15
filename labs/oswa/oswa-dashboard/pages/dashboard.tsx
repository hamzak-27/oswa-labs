import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import Head from 'next/head';
import { 
  ChartBarIcon, 
  CodeBracketIcon,
  ShieldCheckIcon,
  TrophyIcon,
  PlayIcon,
  StopIcon,
  CloudArrowDownIcon,
  WifiIcon,
  FlagIcon
} from '@heroicons/react/24/outline';
import { 
  ChartBarIcon as ChartBarSolidIcon,
  ShieldCheckIcon as ShieldCheckSolidIcon 
} from '@heroicons/react/24/solid';

import Layout from '../components/Layout';
import StatsCard from '../components/dashboard/StatsCard';
import LabCard from '../components/dashboard/LabCard';
import ProgressChart from '../components/dashboard/ProgressChart';
import RecentActivity from '../components/dashboard/RecentActivity';
import FlagSubmissionForm from '../components/FlagSubmissionForm';
import VPNStatus from '../components/VPNStatus';
import { useAuth } from '../utils/auth';
import { useQuery } from 'react-query';
import { toast } from 'react-hot-toast';

interface UserStats {
  totalPoints: number;
  flagsSubmitted: number;
  labsCompleted: number;
  currentStreak: number;
  rank: number;
}

interface LabStatus {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'starting' | 'stopping';
  url?: string;
  flags: number;
  totalFlags: number;
  difficulty: 'easy' | 'medium' | 'hard';
  description: string;
  category: string;
}

export default function Dashboard() {
  const { user } = useAuth();
  const [showFlagForm, setShowFlagForm] = useState(false);
  const [selectedLab, setSelectedLab] = useState<string | null>(null);

  // Fetch user statistics
  const { data: stats, isLoading: statsLoading } = useQuery<UserStats>(
    'user-stats',
    async () => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/progress/stats`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch stats');
      return response.json();
    }
  );

  // Fetch lab status
  const { data: labs, isLoading: labsLoading } = useQuery<LabStatus[]>(
    'lab-status',
    async () => {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/labs`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch labs');
      return response.json();
    },
    {
      refetchInterval: 30000 // Refetch every 30 seconds
    }
  );

  const mockStats: UserStats = {
    totalPoints: stats?.totalPoints || 0,
    flagsSubmitted: stats?.flagsSubmitted || 0,
    labsCompleted: stats?.labsCompleted || 0,
    currentStreak: stats?.currentStreak || 0,
    rank: stats?.rank || 0
  };

  const mockLabs: LabStatus[] = labs || [
    {
      id: 'xss-lab',
      name: 'XSS Attacks Lab',
      status: 'stopped',
      flags: 0,
      totalFlags: 3,
      difficulty: 'medium',
      description: 'Learn Cross-Site Scripting vulnerabilities including reflected, stored, and DOM-based XSS.',
      category: 'Web Security',
      url: 'http://localhost:3000', // XSS Lab Frontend
      vpnIP: '172.20.1.10',
      vpnPort: 3000
    },
    {
      id: 'jwt-attacks-lab', 
      name: 'JWT Attacks Lab',
      status: 'stopped',
      flags: 0,
      totalFlags: 4,
      difficulty: 'hard',
      description: 'Master JWT security flaws including none algorithm, weak secrets, and algorithm confusion.',
      category: 'Authentication',
      url: 'http://localhost:3001', // JWT Lab Frontend
      vpnIP: '172.20.2.10',
      vpnPort: 3000
    },
    {
      id: 'sql-injection-lab',
      name: 'SQL Injection Lab',
      status: 'stopped', 
      flags: 0,
      totalFlags: 5,
      difficulty: 'hard',
      description: 'Master SQL injection techniques including authentication bypass, blind injection, and data extraction.',
      category: 'Database Security',
      url: 'http://localhost:61505', // SQL Lab Frontend (PHP)
      vpnIP: '172.20.3.10',
      vpnPort: 80
    }
  ];

  const handleStartLab = async (labId: string) => {
    try {
      toast.loading(`Starting ${labId}...`);
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/labs/${labId}/start`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error('Failed to start lab');
      
      toast.dismiss();
      toast.success(`${labId} started successfully!`);
    } catch (error) {
      toast.dismiss();
      toast.error(`Failed to start ${labId}`);
    }
  };

  const handleStopLab = async (labId: string) => {
    try {
      toast.loading(`Stopping ${labId}...`);
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/labs/${labId}/stop`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) throw new Error('Failed to stop lab');
      
      toast.dismiss();
      toast.success(`${labId} stopped successfully!`);
    } catch (error) {
      toast.dismiss();
      toast.error(`Failed to stop ${labId}`);
    }
  };

  return (
    <>
      <Head>
        <title>Dashboard - OSWA Lab Platform</title>
        <meta name="description" content="Cybersecurity lab management dashboard" />
      </Head>

      <Layout>
        <div className="space-y-8">
          {/* Header */}
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="min-w-0 flex-1"
            >
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Welcome back, {user?.username || 'Student'}! 👨‍💻
              </h1>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Continue your cybersecurity journey and capture some flags
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="mt-4 flex lg:ml-4 lg:mt-0 space-x-3"
            >
              <button
                onClick={() => setShowFlagForm(true)}
                className="btn-primary flex items-center"
              >
                <FlagIcon className="w-4 h-4 mr-2" />
                Submit Flag
              </button>
              <VPNStatus />
            </motion.div>
          </div>

          {/* Statistics Cards */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4"
          >
            <StatsCard
              title="Total Points"
              value={mockStats.totalPoints.toLocaleString()}
              icon={TrophyIcon}
              color="flag"
              trend={{ value: 12, isPositive: true }}
            />
            <StatsCard
              title="Flags Captured"
              value={mockStats.flagsSubmitted.toString()}
              icon={FlagIcon}
              color="cyber"
              trend={{ value: 2, isPositive: true }}
            />
            <StatsCard
              title="Labs Completed"
              value={`${mockStats.labsCompleted}/2`}
              icon={ShieldCheckSolidIcon}
              color="vuln"
              trend={{ value: 0, isPositive: true }}
            />
            <StatsCard
              title="Current Streak"
              value={`${mockStats.currentStreak} days`}
              icon={ChartBarSolidIcon}
              color="warn"
              trend={{ value: mockStats.currentStreak, isPositive: true }}
            />
          </motion.div>

          {/* Labs Grid */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="grid grid-cols-1 gap-6 lg:grid-cols-2"
          >
            {mockLabs.map((lab, index) => (
              <LabCard
                key={lab.id}
                lab={lab}
                onStart={() => handleStartLab(lab.id)}
                onStop={() => handleStopLab(lab.id)}
                onSelectForFlag={() => {
                  setSelectedLab(lab.id);
                  setShowFlagForm(true);
                }}
                delay={index * 0.1}
              />
            ))}
          </motion.div>

          {/* Progress and Activity */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="lg:col-span-2"
            >
              <ProgressChart />
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <RecentActivity />
            </motion.div>
          </div>

          {/* Quick Actions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="card p-6"
          >
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
              Quick Actions
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <button
                onClick={() => window.open('/leaderboard', '_blank')}
                className="btn-secondary flex items-center justify-center"
              >
                <TrophyIcon className="w-5 h-5 mr-2" />
                View Leaderboard
              </button>
              <button
                onClick={() => window.open('/progress', '_blank')}
                className="btn-secondary flex items-center justify-center"
              >
                <ChartBarIcon className="w-5 h-5 mr-2" />
                Progress Report
              </button>
              <button
                onClick={() => window.open('/help', '_blank')}
                className="btn-secondary flex items-center justify-center"
              >
                <CodeBracketIcon className="w-5 h-5 mr-2" />
                Documentation
              </button>
            </div>
          </motion.div>
        </div>

        {/* Flag Submission Modal */}
        {showFlagForm && (
          <FlagSubmissionForm
            isOpen={showFlagForm}
            onClose={() => {
              setShowFlagForm(false);
              setSelectedLab(null);
            }}
            selectedLab={selectedLab}
          />
        )}
      </Layout>
    </>
  );
}
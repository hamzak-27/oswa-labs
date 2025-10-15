import { motion } from 'framer-motion';

interface StatsCardProps {
  title: string;
  value: string;
  icon: any;
  color: 'flag' | 'cyber' | 'vuln' | 'warn';
  trend?: {
    value: number;
    isPositive: boolean;
  };
  delay?: number;
}

export default function StatsCard({
  title,
  value,
  icon: Icon,
  color,
  trend,
  delay = 0
}: StatsCardProps) {
  const colorClasses = {
    flag: 'from-flag-500 to-flag-600',
    cyber: 'from-cyber-500 to-cyber-600', 
    vuln: 'from-vuln-500 to-vuln-600',
    warn: 'from-warn-500 to-warn-600'
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5 }}
      className="relative overflow-hidden rounded-xl bg-white dark:bg-dark-800 p-6 shadow-lg border border-gray-200 dark:border-dark-700"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
            {title}
          </p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white">
            {value}
          </p>
          {trend && (
            <div className={`flex items-center text-sm ${
              trend.isPositive ? 'text-green-600' : 'text-red-600'
            }`}>
              <span className="mr-1">
                {trend.isPositive ? '↗' : '↘'}
              </span>
              <span>{trend.value}%</span>
            </div>
          )}
        </div>
        <div className={`rounded-lg bg-gradient-to-r ${colorClasses[color]} p-3`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
      
      {/* Background decoration */}
      <div className={`absolute top-0 right-0 -mr-4 -mt-4 h-16 w-16 rounded-full bg-gradient-to-r ${colorClasses[color]} opacity-10`} />
      <div className={`absolute bottom-0 left-0 -ml-4 -mb-4 h-12 w-12 rounded-full bg-gradient-to-r ${colorClasses[color]} opacity-5`} />
    </motion.div>
  );
}
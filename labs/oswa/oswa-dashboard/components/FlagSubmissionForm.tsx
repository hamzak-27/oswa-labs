import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FlagIcon,
  XMarkIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';

interface FlagSubmissionFormProps {
  isOpen: boolean;
  onClose: () => void;
  selectedLab?: string | null;
}

export default function FlagSubmissionForm({
  isOpen,
  onClose,
  selectedLab
}: FlagSubmissionFormProps) {
  const [flag, setFlag] = useState('');
  const [labId, setLabId] = useState(selectedLab || '');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionResult, setSubmissionResult] = useState<{
    success: boolean;
    message: string;
    points?: number;
  } | null>(null);

  const availableLabs = [
    { id: 'xss-lab', name: 'XSS Vulnerabilities Lab' },
    { id: 'jwt-attacks-lab', name: 'JWT Attacks Lab' }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!flag.trim() || !labId) return;

    setIsSubmitting(true);
    setSubmissionResult(null);

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Mock validation logic
      const mockFlags = {
        'xss-lab': [
          'XSS_BASIC_REFLECTED',
          'XSS_STORED_COMMENTS', 
          'XSS_DOM_ADVANCED',
          'XSS_FILTER_BYPASS',
          'XSS_ADMIN_COOKIES'
        ],
        'jwt-attacks-lab': [
          'JWT_NONE_BYPASS',
          'JWT_WEAK_SECRET',
          'JWT_ALGO_CONFUSION',
          'JWT_KID_INJECTION',
          'JWT_ADMIN_TOKEN',
          'JWT_MASTER_KEY'
        ]
      };

      const validFlags = mockFlags[labId as keyof typeof mockFlags] || [];
      const isValid = validFlags.includes(flag.trim().toUpperCase());

      if (isValid) {
        const points = Math.floor(Math.random() * 300) + 100;
        setSubmissionResult({
          success: true,
          message: `Congratulations! Flag accepted.`,
          points
        });
        toast.success(`🎉 Flag accepted! +${points} points`);
        
        // Auto-close after success
        setTimeout(() => {
          onClose();
          setFlag('');
          setSubmissionResult(null);
        }, 3000);
      } else {
        setSubmissionResult({
          success: false,
          message: 'Flag not found. Double-check your submission.'
        });
        toast.error('❌ Invalid flag');
      }
    } catch (error) {
      setSubmissionResult({
        success: false,
        message: 'Submission failed. Please try again.'
      });
      toast.error('Submission failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      onClose();
      setFlag('');
      setLabId(selectedLab || '');
      setSubmissionResult(null);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-screen items-center justify-center p-4">
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-gray-500 bg-opacity-75"
              onClick={handleClose}
            />
            
            {/* Modal */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="relative w-full max-w-md transform overflow-hidden rounded-xl bg-white dark:bg-dark-800 shadow-2xl transition-all"
            >
              <div className="px-6 py-4 border-b border-gray-200 dark:border-dark-700">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
                    <FlagIcon className="w-5 h-5 mr-2 text-cyber-600" />
                    Submit Flag
                  </h3>
                  <button
                    onClick={handleClose}
                    disabled={isSubmitting}
                    className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 disabled:opacity-50"
                  >
                    <XMarkIcon className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="px-6 py-4">
                <div className="space-y-4">
                  {/* Lab Selection */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Lab
                    </label>
                    <select
                      value={labId}
                      onChange={(e) => setLabId(e.target.value)}
                      required
                      disabled={isSubmitting}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-cyber-500 focus:border-cyber-500 disabled:opacity-50"
                    >
                      <option value="">Select a lab...</option>
                      {availableLabs.map((lab) => (
                        <option key={lab.id} value={lab.id}>
                          {lab.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Flag Input */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Flag
                    </label>
                    <input
                      type="text"
                      value={flag}
                      onChange={(e) => setFlag(e.target.value)}
                      placeholder="e.g., XSS_BASIC_REFLECTED"
                      required
                      disabled={isSubmitting}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-dark-600 rounded-lg bg-white dark:bg-dark-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-cyber-500 focus:border-cyber-500 disabled:opacity-50 font-mono"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Enter the flag exactly as you found it
                    </p>
                  </div>

                  {/* Submission Result */}
                  <AnimatePresence>
                    {submissionResult && (
                      <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className={`p-3 rounded-lg flex items-start space-x-2 ${
                          submissionResult.success
                            ? 'bg-flag-100 text-flag-800 dark:bg-flag-900/20 dark:text-flag-200'
                            : 'bg-vuln-100 text-vuln-800 dark:bg-vuln-900/20 dark:text-vuln-200'
                        }`}
                      >
                        {submissionResult.success ? (
                          <CheckCircleIcon className="w-5 h-5 flex-shrink-0 mt-0.5" />
                        ) : (
                          <ExclamationTriangleIcon className="w-5 h-5 flex-shrink-0 mt-0.5" />
                        )}
                        <div>
                          <p className="text-sm font-medium">
                            {submissionResult.message}
                          </p>
                          {submissionResult.points && (
                            <p className="text-sm">
                              +{submissionResult.points} points earned!
                            </p>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={!flag.trim() || !labId || isSubmitting}
                    className="w-full flex items-center justify-center px-4 py-2 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-cyber-600 hover:bg-cyber-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isSubmitting ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                        Validating...
                      </>
                    ) : (
                      <>
                        <FlagIcon className="w-4 h-4 mr-2" />
                        Submit Flag
                      </>
                    )}
                  </button>
                </div>
              </form>

              {/* Help Text */}
              <div className="px-6 py-3 bg-gray-50 dark:bg-dark-900 border-t border-gray-200 dark:border-dark-700">
                <p className="text-xs text-gray-600 dark:text-gray-400">
                  💡 <strong>Tip:</strong> Flags are usually in the format LAB_DESCRIPTION_TYPE (e.g., XSS_BASIC_REFLECTED).
                  Look for unique strings or messages when you successfully exploit a vulnerability.
                </p>
              </div>
            </motion.div>
          </div>
        </div>
      )}
    </AnimatePresence>
  );
}
// MongoDB initialization script for OSWA Platform
// This script sets up the main database with collections and sample data

db = db.getSiblingDB('oswa_platform');

// Create collections
db.createCollection('users');
db.createCollection('labs');
db.createCollection('flags');
db.createCollection('submissions');
db.createCollection('progress');
db.createCollection('sessions');

// Create indexes for performance
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });
db.submissions.createIndex({ "userId": 1, "timestamp": -1 });
db.progress.createIndex({ "userId": 1 });
db.sessions.createIndex({ "userId": 1 });
db.flags.createIndex({ "labId": 1 });

// Insert default admin user
db.users.insertOne({
  _id: ObjectId(),
  username: 'admin',
  email: 'admin@oswa.local',
  password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeijkTzCDOo7sZDOW', // admin123
  role: 'admin',
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  profile: {
    firstName: 'Admin',
    lastName: 'User',
    avatar: null
  },
  settings: {
    theme: 'dark',
    notifications: true,
    language: 'en'
  }
});

// Insert sample student user
db.users.insertOne({
  _id: ObjectId(),
  username: 'student',
  email: 'student@oswa.local',
  password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeijkTzCDOo7sZDOW', // student123
  role: 'student',
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  profile: {
    firstName: 'Test',
    lastName: 'Student',
    avatar: null
  },
  settings: {
    theme: 'light',
    notifications: true,
    language: 'en'
  }
});

// Insert lab definitions
db.labs.insertMany([
  {
    _id: ObjectId(),
    labId: 'xss-lab',
    name: 'Cross-Site Scripting Lab',
    description: 'Learn XSS vulnerabilities including reflected, stored, and DOM-based XSS attacks.',
    category: 'Web Security',
    difficulty: 'intermediate',
    estimatedTime: '2-3 hours',
    points: 150,
    flags: [
      { flagId: 'XSS_REFLECTED_BASIC', value: 'FLAG{R3FL3CT3D_XSS_M4ST3R}', points: 50, hint: 'Try reflecting user input in the search functionality' },
      { flagId: 'XSS_STORED_COMMENT', value: 'FLAG{ST0R3D_XSS_PWND}', points: 50, hint: 'Look for places where user input is stored and displayed' },
      { flagId: 'XSS_DOM_BASED', value: 'FLAG{D0M_XSS_CSP_BYP4SS_L33T}', points: 50, hint: 'Check URL fragments and client-side JavaScript processing' }
    ],
    isActive: true,
    containerConfig: {
      image: 'oswa/xss-lab:latest',
      ports: ['5000:5000'],
      environment: ['NODE_ENV=development']
    },
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    _id: ObjectId(),
    labId: 'jwt-attacks-lab',
    name: 'JWT Attacks Lab',
    description: 'Explore JWT vulnerabilities including weak secrets, algorithm confusion, and bypasses.',
    category: 'Authentication',
    difficulty: 'advanced',
    estimatedTime: '1-2 hours',
    points: 200,
    flags: [
      { flagId: 'JWT_NONE_ALG', value: 'FLAG{JWT_N0N3_4LG0R1THM_BYPASS}', points: 50, hint: 'Try changing the algorithm to "none"' },
      { flagId: 'JWT_WEAK_SECRET', value: 'FLAG{JWT_W34K_S3CR3T_CR4CK3D}', points: 50, hint: 'The signing secret might be weak enough to brute force' },
      { flagId: 'JWT_ALGO_CONFUSION', value: 'FLAG{JWT_4LG0_C0NFUS10N_PWND}', points: 50, hint: 'Try confusing the algorithm verification' },
      { flagId: 'JWT_KID_INJECTION', value: 'FLAG{JWT_K1D_P4R4M_1NJ3CT10N}', points: 50, hint: 'The kid parameter might be vulnerable to injection' }
    ],
    isActive: true,
    containerConfig: {
      image: 'oswa/jwt-lab:latest',
      ports: ['5001:5001'],
      environment: ['NODE_ENV=development']
    },
    createdAt: new Date(),
    updatedAt: new Date()
  },
  {
    _id: ObjectId(),
    labId: 'sql-injection-lab',
    name: 'SQL Injection Lab',
    description: 'Master SQL injection techniques including union-based, blind, and time-based attacks.',
    category: 'Web Security',
    difficulty: 'intermediate',
    estimatedTime: '2-3 hours',
    points: 175,
    flags: [
      { flagId: 'SQL_BASIC_UNION', value: 'FLAG{SQL_UN10N_M4ST3R}', points: 50, hint: 'Try using UNION SELECT to extract data' },
      { flagId: 'SQL_BLIND_BOOLEAN', value: 'FLAG{BL1ND_B00L34N_SQL1}', points: 75, hint: 'Use boolean conditions to extract data bit by bit' },
      { flagId: 'SQL_TIME_BASED', value: 'FLAG{T1M3_B4S3D_SQL_PWND}', points: 50, hint: 'Time delays can help confirm injection points' }
    ],
    isActive: true,
    containerConfig: {
      image: 'oswa/sql-lab:latest',
      ports: ['3000:3000'],
      environment: ['NODE_ENV=development']
    },
    createdAt: new Date(),
    updatedAt: new Date()
  }
]);

// Create sample progress records
const studentUserId = db.users.findOne({username: 'student'})._id;

db.progress.insertOne({
  _id: ObjectId(),
  userId: studentUserId,
  totalPoints: 100,
  flagsSubmitted: 2,
  labsCompleted: 0,
  labsInProgress: ['xss-lab'],
  currentStreak: 1,
  rank: 'Beginner',
  level: 1,
  achievements: ['first_flag'],
  statistics: {
    timeSpent: 3600000, // 1 hour in ms
    favoriteCategory: 'Web Security',
    lastActive: new Date(),
    joinDate: new Date()
  },
  createdAt: new Date(),
  updatedAt: new Date()
});

print('OSWA Platform database initialized successfully!');
print('Default users created:');
print('  - admin@oswa.local / admin123 (Admin)');
print('  - student@oswa.local / student123 (Student)');
print('Labs configured: XSS Lab, JWT Attacks Lab, SQL Injection Lab');
print('Database setup complete!');
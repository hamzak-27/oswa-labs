// MongoDB initialization script for OSWA XSS Lab
// Creates collections, users, and sample data

print('🔧 Initializing OSWA XSS Lab Database...');

// Switch to the xsslab database
db = db.getSiblingDB('xsslab');

// Create collections
db.createCollection('users');
db.createCollection('posts');
db.createCollection('comments');
db.createCollection('reports');
db.createCollection('sessions');

print('✅ Collections created');

// Create indexes for better performance
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.posts.createIndex({ "createdAt": -1 });
db.comments.createIndex({ "postId": 1 });

// Insert sample users
db.users.insertMany([
  {
    _id: ObjectId("507f1f77bcf86cd799439011"),
    username: "admin",
    email: "admin@xsslab.local",
    password: "$2b$10$8K1p/a0dbtxQyT8.4dRwvO8qWW6KzCHZe8sxNZrI8MbQ3GHXb4LN.", // admin123
    role: "admin",
    isAdmin: true,
    profile: {
      firstName: "Admin",
      lastName: "User",
      bio: "System Administrator - Flag: FLAG{XSS_ADMIN_ACCESS_GRANTED}",
      avatar: "/uploads/admin-avatar.png"
    },
    createdAt: new Date("2024-01-01T00:00:00Z"),
    lastLoginAt: new Date(),
    settings: {
      emailNotifications: true,
      twoFactorEnabled: false
    }
  },
  {
    _id: ObjectId("507f1f77bcf86cd799439012"),
    username: "alice",
    email: "alice@xsslab.local", 
    password: "$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDKJc5Y9HPDlqIiu", // alice123
    role: "user",
    isAdmin: false,
    profile: {
      firstName: "Alice",
      lastName: "Johnson",
      bio: "Web Developer passionate about security",
      avatar: "/uploads/alice-avatar.jpg"
    },
    createdAt: new Date("2024-02-15T10:30:00Z"),
    lastLoginAt: new Date()
  },
  {
    _id: ObjectId("507f1f77bcf86cd799439013"),
    username: "bob",
    email: "bob@xsslab.local",
    password: "$2b$10$HZjH2TeH6PQYAoVyKs1FPeH7tP7p4pTdJXOI.e9qNyh5q5w2QWqNa", // bob123
    role: "user", 
    isAdmin: false,
    profile: {
      firstName: "Bob",
      lastName: "Smith",
      bio: "Security researcher and bug hunter",
      avatar: "/uploads/bob-avatar.jpg"
    },
    createdAt: new Date("2024-03-01T14:20:00Z"),
    lastLoginAt: new Date()
  },
  {
    _id: ObjectId("507f1f77bcf86cd799439014"),
    username: "charlie",
    email: "charlie@xsslab.local",
    password: "$2b$10$nOUIs5kJ7naTuTFy5Bx07et7YTkq5w8q.WqRwmG.6ZwNAWXdQ8qse", // charlie123
    role: "user",
    isAdmin: false,
    profile: {
      firstName: "Charlie", 
      lastName: "Brown",
      bio: "Pentester learning web app security",
      avatar: "/uploads/charlie-avatar.jpg"
    },
    createdAt: new Date("2024-03-10T09:15:00Z"),
    lastLoginAt: new Date()
  }
]);

print('✅ Users inserted');

// Insert sample posts with some containing XSS vulnerabilities
db.posts.insertMany([
  {
    _id: ObjectId("608f1f77bcf86cd799439021"),
    title: "Welcome to SecureShare!",
    content: "<p>Welcome to our secure social platform! Share your thoughts and connect with others.</p><p>Remember to always sanitize your inputs... or maybe don't? 😉</p>",
    author: ObjectId("507f1f77bcf86cd799439011"),
    authorUsername: "admin",
    tags: ["welcome", "security", "social"],
    likes: 15,
    views: 234,
    reported: false,
    isSticky: true,
    createdAt: new Date("2024-01-01T12:00:00Z"),
    updatedAt: new Date("2024-01-01T12:00:00Z")
  },
  {
    _id: ObjectId("608f1f77bcf86cd799439022"), 
    title: "My First Post",
    content: "<p>Hello everyone! This is my first post on SecureShare.</p><p>Looking forward to connecting with fellow security enthusiasts!</p>",
    author: ObjectId("507f1f77bcf86cd799439012"),
    authorUsername: "alice",
    tags: ["introduction", "hello"],
    likes: 8,
    views: 156,
    reported: false,
    createdAt: new Date("2024-02-15T11:00:00Z"),
    updatedAt: new Date("2024-02-15T11:00:00Z")
  },
  {
    _id: ObjectId("608f1f77bcf86cd799439023"),
    title: "Web Security Tips",
    content: "<p>Here are some essential web security tips:</p><ul><li>Always validate input</li><li>Use HTTPS everywhere</li><li>Implement proper authentication</li><li>Don't trust user input!</li></ul><p>What other tips do you have?</p>",
    author: ObjectId("507f1f77bcf86cd799439013"),
    authorUsername: "bob", 
    tags: ["security", "tips", "webdev"],
    likes: 23,
    views: 445,
    reported: false,
    createdAt: new Date("2024-03-01T15:30:00Z"),
    updatedAt: new Date("2024-03-01T15:30:00Z")
  },
  {
    _id: ObjectId("608f1f77bcf86cd799439024"),
    title: "Testing XSS Vulnerabilities",
    content: "<p>I'm researching XSS vulnerabilities for educational purposes.</p><p>Anyone know good resources for learning about Cross-Site Scripting?</p><p><em>Hidden hint: Try searching for special characters...</em></p>",
    author: ObjectId("507f1f77bcf86cd799439014"),
    authorUsername: "charlie",
    tags: ["xss", "research", "learning"],
    likes: 12,
    views: 289,
    reported: false,
    createdAt: new Date("2024-03-10T10:45:00Z"),
    updatedAt: new Date("2024-03-10T10:45:00Z")
  }
]);

print('✅ Posts inserted');

// Insert sample comments (some with potential XSS vectors)
db.comments.insertMany([
  {
    _id: ObjectId("60bf1f77bcf86cd799439031"),
    postId: ObjectId("608f1f77bcf86cd799439021"),
    content: "Great platform! Looking forward to using it.",
    author: ObjectId("507f1f77bcf86cd799439012"),
    authorUsername: "alice",
    likes: 5,
    reported: false,
    createdAt: new Date("2024-01-01T12:30:00Z")
  },
  {
    _id: ObjectId("60bf1f77bcf86cd799439032"),
    postId: ObjectId("608f1f77bcf86cd799439023"),
    content: "Thanks for the tips! Also consider implementing Content Security Policy (CSP) headers.",
    author: ObjectId("507f1f77bcf86cd799439014"),
    authorUsername: "charlie",
    likes: 3,
    reported: false,
    createdAt: new Date("2024-03-01T16:00:00Z")
  },
  {
    _id: ObjectId("60bf1f77bcf86cd799439033"),
    postId: ObjectId("608f1f77bcf86cd799439024"),
    content: "OWASP has excellent resources on XSS. Check out their testing guide!",
    author: ObjectId("507f1f77bcf86cd799439013"),
    authorUsername: "bob",
    likes: 7,
    reported: false, 
    createdAt: new Date("2024-03-10T11:15:00Z")
  }
]);

print('✅ Comments inserted');

// Insert hidden flags in various locations
db.flags.insertMany([
  {
    _id: ObjectId("70cf1f77bcf86cd799439041"),
    name: "reflected_xss_flag",
    value: "FLAG{R3FL3CT3D_XSS_M4ST3R}",
    description: "Found through reflected XSS in search functionality",
    difficulty: "easy",
    category: "xss",
    location: "search parameter reflection",
    points: 100,
    hints: [
      "Try searching with special characters",
      "Look for unescaped output in search results",
      "The search functionality might be vulnerable..."
    ]
  },
  {
    _id: ObjectId("70cf1f77bcf86cd799439042"),
    name: "stored_xss_flag", 
    value: "FLAG{ST0R3D_XSS_C00K13_TH13F}",
    description: "Retrieved by stealing admin cookies through stored XSS",
    difficulty: "medium",
    category: "xss",
    location: "admin cookie after stored XSS exploitation",
    points: 250,
    hints: [
      "Comments might not be properly sanitized",
      "Admin users visit reported content", 
      "Cookies can be exfiltrated with JavaScript"
    ]
  },
  {
    _id: ObjectId("70cf1f77bcf86cd799439043"),
    name: "dom_xss_csp_bypass_flag",
    value: "FLAG{D0M_XSS_CSP_BYP4SS_L33T}",
    description: "Obtained through DOM XSS with CSP bypass techniques",
    difficulty: "hard", 
    category: "xss",
    location: "DOM manipulation with CSP evasion",
    points: 500,
    hints: [
      "Client-side JavaScript can be vulnerable too",
      "CSP might have weaknesses or misconfigurations",
      "Hash fragments and DOM properties are client-side"
    ]
  }
]);

print('✅ Flags inserted');

// Create admin session token for bot simulation
db.sessions.insertOne({
  _id: ObjectId("80df1f77bcf86cd799439051"),
  sessionId: "admin_session_xss_lab_2024",
  userId: ObjectId("507f1f77bcf86cd799439011"),
  username: "admin",
  isAdmin: true,
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
  ipAddress: "172.20.0.5",
  userAgent: "XSS-Lab-Admin-Bot/1.0"
});

print('✅ Admin session created');

print('🎉 OSWA XSS Lab database initialized successfully!');
print('');
print('📊 Database Statistics:');
print('- Users: ' + db.users.count());
print('- Posts: ' + db.posts.count()); 
print('- Comments: ' + db.comments.count());
print('- Flags: ' + db.flags.count());
print('- Sessions: ' + db.sessions.count());
print('');
print('🔐 Test Accounts:');
print('- Admin: admin / admin123 (admin privileges)');
print('- Alice: alice / alice123 (regular user)');  
print('- Bob: bob / bob123 (regular user)');
print('- Charlie: charlie / charlie123 (regular user)');
print('');
print('🎯 Hidden Flags:');
print('- Easy: Reflected XSS (100 pts)');
print('- Medium: Stored XSS + Cookie Theft (250 pts)');
print('- Hard: DOM XSS + CSP Bypass (500 pts)');
print('');
print('Ready for XSS exploitation! 🚀');
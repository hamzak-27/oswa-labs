// MongoDB initialization script for OSWA JWT Attacks Lab
// Creates collections, users, and sample data for JWT testing

print('🔧 Initializing OSWA JWT Attacks Lab Database...');

// Switch to the jwtlab database
db = db.getSiblingDB('jwtlab');

// Create collections
db.createCollection('users');
db.createCollection('sessions');
db.createCollection('api_keys');
db.createCollection('audit_logs');
db.createCollection('services');
db.createCollection('jwt_blacklist');

print('✅ Collections created');

// Create indexes
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.sessions.createIndex({ "token_id": 1 }, { unique: true });
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
db.jwt_blacklist.createIndex({ "jti": 1 }, { unique: true });
db.jwt_blacklist.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

// Insert sample users with different privilege levels
db.users.insertMany([
  {
    _id: ObjectId("607f1f77bcf86cd799439011"),
    username: "admin",
    email: "admin@jwtlab.local",
    password: "$2b$10$8K1p/a0dbtxQyT8.4dRwvO8qWW6KzCHZe8sxNZrI8MbQ3GHXb4LN.", // admin123
    role: "admin",
    permissions: ["read", "write", "delete", "admin", "jwt_debug"],
    is_active: true,
    secret_data: "FLAG{JWT_ADMIN_PRIVILEGE_ESCALATION}",
    profile: {
      firstName: "System",
      lastName: "Administrator", 
      bio: "System administrator with full access to JWT services",
      clearance_level: "TOP_SECRET"
    },
    created_at: new Date("2024-01-01T00:00:00Z"),
    last_login: new Date(),
    jwt_version: 2 // Higher version for admin
  },
  {
    _id: ObjectId("607f1f77bcf86cd799439012"),
    username: "alice",
    email: "alice@jwtlab.local",
    password: "$2b$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDKJc5Y9HPDlqIiu", // alice123
    role: "user",
    permissions: ["read", "write"],
    is_active: true,
    profile: {
      firstName: "Alice",
      lastName: "Johnson",
      bio: "Regular user testing JWT authentication",
      clearance_level: "PUBLIC"
    },
    created_at: new Date("2024-02-15T10:30:00Z"),
    last_login: new Date(),
    jwt_version: 1
  },
  {
    _id: ObjectId("607f1f77bcf86cd799439013"),
    username: "service_account",
    email: "service@jwtlab.local",
    password: "$2b$10$HZjH2TeH6PQYAoVyKs1FPeH7tP7p4pTdJXOI.e9qNyh5q5w2QWqNa", // service123
    role: "service",
    permissions: ["api_access", "service_to_service"],
    is_active: true,
    api_key: "jwt_service_api_key_2024",
    profile: {
      firstName: "Service",
      lastName: "Account",
      bio: "Service account for microservice authentication",
      clearance_level: "CONFIDENTIAL"
    },
    created_at: new Date("2024-01-01T08:00:00Z"),
    last_login: new Date(),
    jwt_version: 1
  },
  {
    _id: ObjectId("607f1f77bcf86cd799439014"),
    username: "guest",
    email: "guest@jwtlab.local", 
    password: "$2b$10$nOUIs5kJ7naTuTFy5Bx07et7YTkq5w8q.WqRwmG.6ZwNAWXdQ8qse", // guest123
    role: "guest",
    permissions: ["read"],
    is_active: true,
    profile: {
      firstName: "Guest",
      lastName: "User",
      bio: "Limited guest account for testing",
      clearance_level: "PUBLIC"
    },
    created_at: new Date("2024-03-01T12:00:00Z"),
    last_login: new Date(),
    jwt_version: 1
  },
  {
    _id: ObjectId("607f1f77bcf86cd799439015"),
    username: "disabled_user",
    email: "disabled@jwtlab.local",
    password: "$2b$10$someHashedPassword", // disabled123
    role: "user",
    permissions: ["read"],
    is_active: false, // Disabled account
    profile: {
      firstName: "Disabled",
      lastName: "Account",
      bio: "This account has been disabled",
      clearance_level: "PUBLIC"
    },
    created_at: new Date("2024-01-01T00:00:00Z"),
    last_login: new Date("2024-01-15T00:00:00Z"),
    jwt_version: 1,
    disabled_reason: "Security violation"
  }
]);

print('✅ Users inserted');

// Insert microservices configuration
db.services.insertMany([
  {
    _id: ObjectId("608f1f77bcf86cd799439021"),
    service_name: "payment_service",
    service_id: "pay_svc_001",
    api_key: "payment_api_key_2024",
    jwt_algorithm: "HS256",
    secret: "payment_service_secret",
    permissions: ["process_payments", "read_transactions"],
    is_active: true,
    created_at: new Date("2024-01-01T00:00:00Z")
  },
  {
    _id: ObjectId("608f1f77bcf86cd799439022"),
    service_name: "user_management",
    service_id: "user_svc_002", 
    api_key: "user_mgmt_api_key_2024",
    jwt_algorithm: "RS256",
    secret: null, // Uses RSA keys
    permissions: ["manage_users", "read_profiles"],
    is_active: true,
    created_at: new Date("2024-01-01T00:00:00Z")
  },
  {
    _id: ObjectId("608f1f77bcf86cd799439023"),
    service_name: "admin_panel",
    service_id: "admin_svc_003",
    api_key: "admin_panel_secret_2024",
    jwt_algorithm: "HS512",
    secret: "super_secret_admin_key",
    permissions: ["admin_access", "system_control"],
    is_active: true,
    created_at: new Date("2024-01-01T00:00:00Z")
  }
]);

print('✅ Services inserted');

// Insert sample API keys for testing
db.api_keys.insertMany([
  {
    _id: ObjectId("60af1f77bcf86cd799439031"),
    key_name: "development_key",
    api_key: "dev_jwt_key_12345",
    user_id: ObjectId("607f1f77bcf86cd799439012"),
    permissions: ["read", "write"],
    rate_limit: 1000,
    is_active: true,
    created_at: new Date("2024-01-01T00:00:00Z"),
    expires_at: new Date("2025-01-01T00:00:00Z")
  },
  {
    _id: ObjectId("60af1f77bcf86cd799439032"),
    key_name: "admin_debug_key",
    api_key: "admin_debug_jwt_key_secret",
    user_id: ObjectId("607f1f77bcf86cd799439011"),
    permissions: ["admin", "jwt_debug", "read", "write", "delete"],
    rate_limit: 10000,
    is_active: true,
    created_at: new Date("2024-01-01T00:00:00Z"),
    expires_at: new Date("2025-12-31T23:59:59Z")
  }
]);

print('✅ API Keys inserted');

// Insert hidden flags for JWT challenges
db.flags.insertMany([
  {
    _id: ObjectId("70cf1f77bcf86cd799439041"),
    name: "none_algorithm_flag",
    value: "FLAG{JWT_N0N3_4LG0R1THM_BYP4SS}",
    description: "Bypass JWT verification using 'none' algorithm",
    difficulty: "easy",
    category: "jwt",
    location: "none algorithm attack",
    points: 100,
    hints: [
      "JWT can be signed with 'none' algorithm",
      "Remove signature and change algorithm to 'none'",
      "Server might not validate the algorithm properly"
    ]
  },
  {
    _id: ObjectId("70cf1f77bcf86cd799439042"),
    name: "weak_secret_flag",
    value: "FLAG{JWT_W34K_S3CR3T_CR4CK3D}",
    description: "Crack weak JWT secret and forge token",
    difficulty: "medium",
    category: "jwt",
    location: "weak secret brute force",
    points: 250,
    hints: [
      "Some JWT secrets are easily guessable",
      "Try common passwords and dictionary attacks",
      "Look for patterns in error messages"
    ]
  },
  {
    _id: ObjectId("70cf1f77bcf86cd799439043"),
    name: "algorithm_confusion_flag",
    value: "FLAG{JWT_4LG0R1THM_C0NFUS10N_H4CK}",
    description: "Exploit algorithm confusion between RSA and HMAC",
    difficulty: "hard",
    category: "jwt",
    location: "RS256 to HS256 algorithm confusion",
    points: 500,
    hints: [
      "RSA public key can be used as HMAC secret",
      "Server might accept different algorithms than expected",
      "Algorithm confusion can bypass signature verification"
    ]
  },
  {
    _id: ObjectId("70cf1f77bcf86cd799439044"),
    name: "jwt_injection_flag",
    value: "FLAG{JWT_1NJ3CT10N_V1A_K1D_CL41M}",
    description: "Inject malicious kid claim to read arbitrary files",
    difficulty: "hard",
    category: "jwt",
    location: "kid parameter injection",
    points: 400,
    hints: [
      "The 'kid' parameter can reference external files",
      "Path traversal might be possible in kid claim",
      "Server might read files based on kid value"
    ]
  }
]);

print('✅ Flags inserted');

// Insert audit logs for testing
db.audit_logs.insertMany([
  {
    _id: ObjectId("61bf1f77bcf86cd799439051"),
    event_type: "login_attempt",
    user_id: ObjectId("607f1f77bcf86cd799439011"),
    username: "admin",
    success: true,
    jwt_algorithm: "HS256",
    ip_address: "127.0.0.1",
    user_agent: "JWT-Lab-Client/1.0",
    timestamp: new Date("2024-01-01T12:00:00Z"),
    details: {
      token_version: 2,
      permissions_granted: ["admin", "jwt_debug", "read", "write", "delete"]
    }
  },
  {
    _id: ObjectId("61bf1f77bcf86cd799439052"),
    event_type: "token_validation",
    user_id: ObjectId("607f1f77bcf86cd799439012"),
    username: "alice",
    success: false,
    jwt_algorithm: "none",
    ip_address: "192.168.1.100",
    user_agent: "Penetration-Testing-Tool",
    timestamp: new Date("2024-01-01T12:30:00Z"),
    details: {
      error: "Invalid signature",
      attempted_bypass: "none algorithm attack"
    }
  }
]);

print('✅ Audit logs inserted');

print('🎉 OSWA JWT Attacks Lab database initialized successfully!');
print('');
print('📊 Database Statistics:');
print('- Users: ' + db.users.count());
print('- Services: ' + db.services.count());
print('- API Keys: ' + db.api_keys.count());
print('- Flags: ' + db.flags.count());
print('- Audit Logs: ' + db.audit_logs.count());
print('');
print('🔐 Test Accounts:');
print('- Admin: admin / admin123 (full privileges)');
print('- Alice: alice / alice123 (regular user)');
print('- Service Account: service_account / service123 (API access)');
print('- Guest: guest / guest123 (read-only)');
print('- Disabled: disabled_user / disabled123 (inactive)');
print('');
print('🎯 JWT Attack Vectors:');
print('- None Algorithm Bypass (100 pts)');
print('- Weak Secret Cracking (250 pts)');
print('- Algorithm Confusion (500 pts)');
print('- Kid Parameter Injection (400 pts)');
print('');
print('🔑 Service API Keys:');
print('- Development: dev_jwt_key_12345');
print('- Admin Debug: admin_debug_jwt_key_secret');
print('');
print('Ready for JWT exploitation! 🚀');
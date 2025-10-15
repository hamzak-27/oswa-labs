-- OSWA SQL Injection Lab Database Initialization
-- This creates a vulnerable database for educational purposes

CREATE DATABASE IF NOT EXISTS oswa_sqli;
USE oswa_sqli;

-- Create users table with sample data
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    account_balance DECIMAL(10,2) DEFAULT 0.00
);

-- Create transactions table for more complex queries
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    transaction_type ENUM('deposit', 'withdrawal', 'transfer') NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create accounts table for additional data to extract
CREATE TABLE accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    account_type ENUM('checking', 'savings', 'business') DEFAULT 'checking',
    balance DECIMAL(12,2) DEFAULT 0.00,
    status ENUM('active', 'suspended', 'closed') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create admin_logs table (contains sensitive information)
CREATE TABLE admin_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT,
    action VARCHAR(255) NOT NULL,
    target_user_id INT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id)
);

-- Create flags table (hidden treasure for advanced users)
CREATE TABLE flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    flag_value VARCHAR(255) NOT NULL,
    difficulty_level ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users (passwords are intentionally weak for educational purposes)
INSERT INTO users (username, email, password, is_admin, account_balance) VALUES
('admin', 'admin@securebank.com', 'admin123', 1, 999999.99),
('john_doe', 'john@email.com', 'password123', 0, 5247.83),
('jane_smith', 'jane.smith@email.com', 'qwerty456', 0, 12350.40),
('bob_wilson', 'bob.wilson@company.com', 'letmein789', 0, 890.25),
('alice_brown', 'alice@example.com', 'password', 0, 3456.78),
('test_user', 'test@test.com', 'test123', 0, 100.00),
('demo_user', 'demo@demo.com', 'demo123', 0, 500.50);

-- Insert sample accounts
INSERT INTO accounts (user_id, account_number, account_type, balance) VALUES
(1, 'ACC-ADM-001', 'business', 999999.99),
(2, 'ACC-USR-1001', 'checking', 5247.83),
(2, 'ACC-USR-1002', 'savings', 15000.00),
(3, 'ACC-USR-2001', 'checking', 12350.40),
(4, 'ACC-USR-3001', 'checking', 890.25),
(5, 'ACC-USR-4001', 'savings', 3456.78),
(6, 'ACC-TST-5001', 'checking', 100.00),
(7, 'ACC-DMO-6001', 'checking', 500.50);

-- Insert sample transactions
INSERT INTO transactions (user_id, transaction_type, amount, description) VALUES
(2, 'deposit', 1000.00, 'Salary deposit'),
(2, 'withdrawal', 200.00, 'ATM withdrawal'),
(2, 'transfer', 150.00, 'Transfer to savings'),
(3, 'deposit', 2500.00, 'Business payment'),
(3, 'withdrawal', 300.00, 'Online purchase'),
(4, 'deposit', 500.00, 'Freelance payment'),
(5, 'withdrawal', 100.00, 'Grocery shopping');

-- Insert admin logs (sensitive information)
INSERT INTO admin_logs (admin_id, action, target_user_id, details, ip_address) VALUES
(1, 'USER_CREATED', 2, 'Created new user account', '192.168.1.100'),
(1, 'ACCOUNT_SUSPENDED', 4, 'Suspended account due to suspicious activity', '192.168.1.100'),
(1, 'PASSWORD_RESET', 3, 'Reset password for user jane_smith', '192.168.1.100'),
(1, 'BALANCE_ADJUSTMENT', 2, 'Adjusted balance for account reconciliation', '192.168.1.100');

-- Insert flags for the lab challenges
INSERT INTO flags (flag_name, flag_value, difficulty_level, description) VALUES
('basic_auth_bypass', 'OSWA{basic_sqli_authentication_bypass}', 'easy', 'Awarded for successfully bypassing authentication using SQL injection'),
('admin_access', 'OSWA{advanced_sqli_admin_access}', 'medium', 'Awarded for gaining admin access through SQL injection'),
('blind_data_extraction', 'OSWA{blind_sqli_data_extraction}', 'hard', 'Awarded for successfully extracting data using blind SQL injection techniques'),
('database_enumeration', 'OSWA{database_schema_enumeration}', 'medium', 'Awarded for enumerating database schema information'),
('sensitive_data_access', 'OSWA{admin_logs_data_breach}', 'hard', 'Awarded for accessing sensitive admin logs table');

-- Create a view for easier testing (this can be discovered via UNION attacks)
CREATE VIEW user_summary AS
SELECT 
    u.id,
    u.username,
    u.email,
    COUNT(t.id) as transaction_count,
    SUM(a.balance) as total_balance
FROM users u
LEFT JOIN transactions t ON u.id = t.user_id
LEFT JOIN accounts a ON u.id = a.user_id
WHERE u.is_admin = 0
GROUP BY u.id, u.username, u.email;

-- Create application user with limited privileges
CREATE USER IF NOT EXISTS 'webapp'@'%' IDENTIFIED BY 'webapp_password';
GRANT SELECT, INSERT, UPDATE ON oswa_sqli.users TO 'webapp'@'%';
GRANT SELECT ON oswa_sqli.transactions TO 'webapp'@'%';
GRANT SELECT ON oswa_sqli.accounts TO 'webapp'@'%';
GRANT SELECT ON oswa_sqli.user_summary TO 'webapp'@'%';

-- Note: webapp user intentionally does NOT have access to admin_logs and flags tables
-- This creates a challenge for advanced users to escalate privileges or use UNION attacks

FLUSH PRIVILEGES;

-- Display setup completion message
SELECT 'OSWA SQL Injection Lab Database Setup Complete!' as message;
SELECT COUNT(*) as total_users FROM users;
SELECT COUNT(*) as total_flags FROM flags;
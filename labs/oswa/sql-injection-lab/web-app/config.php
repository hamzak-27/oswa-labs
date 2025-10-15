<?php
// Database configuration for OSWA SQL Injection Lab
define('DB_HOST', $_ENV['MYSQL_HOST'] ?? 'mysql');
define('DB_NAME', $_ENV['MYSQL_DATABASE'] ?? 'oswa_sqli');
define('DB_USER', $_ENV['MYSQL_USER'] ?? 'webapp');
define('DB_PASS', $_ENV['MYSQL_PASSWORD'] ?? 'webapp_password');

// Create database connection
function getDBConnection() {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", 
                       DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch(PDOException $e) {
        die("Database connection failed: " . $e->getMessage());
    }
}

// Global database connection
$db = getDBConnection();

// Lab configuration
define('LAB_NAME', 'OSWA SQL Injection Mastery');
define('LAB_VERSION', '1.0');
define('FLAGS_DIRECTORY', '/var/www/html/flags/');

// Security configuration (intentionally weak for educational purposes)
define('ENABLE_DEBUG', true);
define('SHOW_ERRORS', true);

// Error reporting for debugging
if (ENABLE_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}
?>
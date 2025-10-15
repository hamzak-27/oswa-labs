<?php
// Helper functions for OSWA SQL Injection Lab

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Check if user is admin
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

/**
 * Redirect if not logged in
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: index.php?login=1');
        exit();
    }
}

/**
 * Redirect if not admin
 */
function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        header('Location: dashboard.php?error=access_denied');
        exit();
    }
}

/**
 * Log security events (SQL injection attempts, etc.)
 */
function logSecurityEvent($event_type, $description, $user_input = '') {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'description' => $description,
        'user_input' => $user_input,
        'user_id' => $_SESSION['user_id'] ?? 'anonymous',
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ];
    
    error_log("OSWA Security Event: " . json_encode($log_entry));
}

/**
 * Award flag to user
 */
function awardFlag($flag_name, $flag_value) {
    if (!isset($_SESSION['earned_flags'])) {
        $_SESSION['earned_flags'] = [];
    }
    
    if (!in_array($flag_name, $_SESSION['earned_flags'])) {
        $_SESSION['earned_flags'][] = $flag_name;
        $_SESSION['flags'][$flag_name] = $flag_value;
        
        logSecurityEvent('FLAG_EARNED', "User earned flag: $flag_name", $flag_value);
        return true;
    }
    
    return false;
}

/**
 * Get user's earned flags
 */
function getEarnedFlags() {
    return $_SESSION['earned_flags'] ?? [];
}

/**
 * Check if specific flag was earned
 */
function hasFlagBeenEarned($flag_name) {
    return in_array($flag_name, getEarnedFlags());
}

/**
 * Generate CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 */
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Sanitize output (but we'll intentionally not use this everywhere for educational purposes)
 */
function sanitizeOutput($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

/**
 * Get lab statistics for user
 */
function getLabStatistics($user_id) {
    $stats = [
        'total_flags' => 3,
        'earned_flags' => count(getEarnedFlags()),
        'completion_percentage' => round((count(getEarnedFlags()) / 3) * 100, 2),
        'sql_injection_attempts' => $_SESSION['blind_sqli_attempts'] ?? 0,
        'session_start_time' => $_SESSION['session_start'] ?? time(),
        'time_spent' => time() - ($_SESSION['session_start'] ?? time())
    ];
    
    return $stats;
}

/**
 * Initialize lab session
 */
function initializeLabSession() {
    if (!isset($_SESSION['session_start'])) {
        $_SESSION['session_start'] = time();
    }
    
    if (!isset($_SESSION['earned_flags'])) {
        $_SESSION['earned_flags'] = [];
    }
    
    if (!isset($_SESSION['flags'])) {
        $_SESSION['flags'] = [];
    }
}

// Initialize session on include
if (session_status() === PHP_SESSION_ACTIVE) {
    initializeLabSession();
}
?>
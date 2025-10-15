<?php
session_start();
require_once 'config.php';

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // VULNERABLE SQL QUERY - Intentionally vulnerable for educational purposes
    // This demonstrates a classic SQL injection vulnerability
    $query = "SELECT id, username, email, is_admin FROM users WHERE username = '$username' AND password = '$password'";
    
    if (ENABLE_DEBUG) {
        echo "<!-- DEBUG: Executing query: $query -->";
    }
    
    try {
        // Execute the vulnerable query
        $stmt = $db->query($query);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Successful login
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['is_admin'] = $user['is_admin'];
            
            // Award flag for successful authentication bypass
            if (strpos($username, "'") !== false || strpos($username, "--") !== false || strpos($username, "OR") !== false) {
                // User likely used SQL injection
                $_SESSION['flag_earned'] = 'OSWA{basic_sqli_authentication_bypass}';
                $_SESSION['flag_earned_time'] = time();
                
                // Log the flag earning event
                error_log("OSWA Lab: User earned authentication bypass flag using: " . $username);
                
                // Set flag display session
                $_SESSION['show_flag_modal'] = true;
            }
            
            // Redirect based on user role
            if ($user['is_admin']) {
                header('Location: admin.php');
            } else {
                header('Location: dashboard.php');
            }
            exit();
        } else {
            // Failed login
            header('Location: index.php?error=1');
            exit();
        }
        
    } catch (PDOException $e) {
        // Database error - might reveal useful information for SQL injection
        $error_message = "Database Error: " . $e->getMessage();
        
        if (ENABLE_DEBUG) {
            echo "<div class='alert alert-danger'>$error_message</div>";
            echo "<p><strong>Query executed:</strong> $query</p>";
        }
        
        // Check for common SQL injection attempts
        if (strpos($username, "'") !== false) {
            echo "<div class='alert alert-warning'>";
            echo "<strong>SQL Injection Detected!</strong><br>";
            echo "Your input: " . htmlspecialchars($username) . "<br>";
            echo "This would be a great place to try different payloads!";
            echo "</div>";
        }
        
        // Still redirect to avoid breaking the flow
        header('Location: index.php?error=1');
        exit();
    }
} else {
    // Direct access to login.php, redirect to home
    header('Location: index.php');
    exit();
}
?>
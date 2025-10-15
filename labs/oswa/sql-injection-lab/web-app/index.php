<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
$user_logged_in = isset($_SESSION['user_id']);
$is_admin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureBank - Online Banking Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .bg-gradient-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-custom { box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15); border: 0; background: rgba(255,255,255,0.95); }
        .navbar-brand { font-weight: bold; }
        .vulnerability-hint { 
            background: linear-gradient(135deg, #ff6b6b, #ee5a52); 
            color: white; 
            border-left: 4px solid #ffd700; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);
        }
        .vulnerability-hint code {
            background: rgba(0,0,0,0.2);
            color: #ffd700;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .flag-container {
            background: linear-gradient(45deg, #28a745, #20c997);
            border: 3px solid #ffd700;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
            box-shadow: 0 0 20px rgba(255, 215, 0, 0.5);
            animation: glow 2s ease-in-out infinite alternate;
            color: white;
        }
        .flag-container code {
            background: rgba(0,0,0,0.2);
            color: #ffd700;
            padding: 8px 15px;
            border-radius: 5px;
            font-size: 1.2rem;
            font-weight: bold;
        }
        @keyframes glow {
            from { box-shadow: 0 0 20px rgba(255, 215, 0, 0.5); }
            to { box-shadow: 0 0 30px rgba(255, 215, 0, 0.8); }
        }
        .challenge-card {
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 2px solid transparent;
        }
        .challenge-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        .lab-info {
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 8px 25px rgba(23, 162, 184, 0.3);
        }
    </style>
</head>
<body class="bg-light">
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-gradient-primary">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-shield-alt"></i> SecureBank
            </a>
            <div class="navbar-nav ms-auto">
                <?php if ($user_logged_in): ?>
                    <a class="nav-link" href="dashboard.php">Dashboard</a>
                    <a class="nav-link" href="search.php">Search</a>
                    <?php if ($is_admin): ?>
                        <a class="nav-link" href="admin.php">Admin Panel</a>
                    <?php endif; ?>
                    <a class="nav-link" href="logout.php">Logout</a>
                <?php else: ?>
                    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#loginModal">Login</a>
                    <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#registerModal">Register</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <?php if (!$user_logged_in): ?>
            <!-- Welcome Section -->
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card card-custom">
                        <div class="card-body text-center p-5">
                            <i class="fas fa-university fa-3x text-primary mb-4"></i>
                            <h1 class="card-title mb-4">Welcome to SecureBank</h1>
                            <p class="card-text lead mb-4">Your trusted online banking solution with advanced security features.</p>
                            <div class="row text-start">
                                <div class="col-md-6">
                                    <h5><i class="fas fa-lock text-success"></i> Secure Login</h5>
                                    <p>Advanced authentication system</p>
                                </div>
                                <div class="col-md-6">
                                    <h5><i class="fas fa-chart-line text-info"></i> Account Management</h5>
                                    <p>Comprehensive financial tracking</p>
                                </div>
                            </div>
                            <button class="btn btn-primary btn-lg" data-bs-toggle="modal" data-bs-target="#loginModal">
                                <i class="fas fa-sign-in-alt"></i> Login to Your Account
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Lab Information -->
            <div class="row justify-content-center mt-4">
                <div class="col-lg-8">
                    <div class="lab-info">
                        <h5><i class="fas fa-database me-2"></i>OSWA SQL Injection Mastery Lab</h5>
                        <p><strong>🎯 Objective:</strong> Master SQL injection techniques on this intentionally vulnerable banking application.</p>
                        
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <h6><i class="fas fa-list-check me-2"></i>Challenges Available:</h6>
                                <ul>
                                    <li><strong>Authentication Bypass</strong> - Login form exploitation</li>
                                    <li><strong>Admin Access</strong> - Privilege escalation attacks</li>
                                    <li><strong>Blind SQL Injection</strong> - Data extraction via search</li>
                                    <li><strong>Database Enumeration</strong> - Schema discovery</li>
                                    <li><strong>Sensitive Data Access</strong> - Admin logs breach</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6><i class="fas fa-flag me-2"></i>Flags to Capture:</h6>
                                <ul>
                                    <li><code>OSWA{basic_sqli_authentication_bypass}</code></li>
                                    <li><code>OSWA{advanced_sqli_admin_access}</code></li>
                                    <li><code>OSWA{blind_sqli_data_extraction}</code></li>
                                    <li><code>OSWA{database_schema_enumeration}</code></li>
                                    <li><code>OSWA{admin_logs_data_breach}</code></li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="mt-4 p-3" style="background: rgba(0,0,0,0.1); border-radius: 8px;">
                            <h6><i class="fas fa-tools me-2"></i>Suggested Tools:</h6>
                            <span class="badge bg-light text-dark me-2">Burp Suite</span>
                            <span class="badge bg-light text-dark me-2">sqlmap</span>
                            <span class="badge bg-light text-dark me-2">Manual Testing</span>
                            <span class="badge bg-light text-dark me-2">Browser DevTools</span>
                        </div>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <!-- Flag Display for Successful Attacks -->
            <?php if (isset($_SESSION['flag_earned']) && isset($_SESSION['show_flag_modal'])): ?>
                <div class="row justify-content-center mb-4">
                    <div class="col-lg-8">
                        <div class="flag-container">
                            <h4><i class="fas fa-flag me-2"></i>🎉 FLAG CAPTURED! 🎉</h4>
                            <code><?php echo htmlspecialchars($_SESSION['flag_earned']); ?></code>
                            <p class="mt-3 mb-0">
                                <i class="fas fa-check-circle me-2"></i>
                                <strong>Congratulations!</strong> You successfully exploited SQL injection for authentication bypass!
                            </p>
                            <small class="d-block mt-2">Flag earned: <?php echo date('Y-m-d H:i:s', $_SESSION['flag_earned_time'] ?? time()); ?></small>
                        </div>
                    </div>
                </div>
                <?php unset($_SESSION['show_flag_modal']); ?>
            <?php endif; ?>
            
            <!-- Dashboard Preview for Logged In Users -->
            <div class="row">
                <div class="col-12">
                    <h2 class="text-white mb-4">Welcome back, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
                    <div class="row mt-4">
                        <div class="col-md-4">
                            <div class="card card-custom">
                                <div class="card-body">
                                    <h5 class="card-title"><i class="fas fa-credit-card"></i> Account Balance</h5>
                                    <h3 class="text-success">$5,247.83</h3>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card card-custom">
                                <div class="card-body">
                                    <h5 class="card-title"><i class="fas fa-exchange-alt"></i> Recent Transactions</h5>
                                    <p>3 new transactions</p>
                                    <a href="dashboard.php" class="btn btn-sm btn-outline-primary">View Details</a>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card card-custom">
                                <div class="card-body">
                                    <h5 class="card-title"><i class="fas fa-search"></i> Search Users</h5>
                                    <p>Find other bank customers</p>
                                    <a href="search.php" class="btn btn-sm btn-outline-primary">Search Now</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Login Modal -->
    <div class="modal fade" id="loginModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Login to SecureBank</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="login.php">
                    <div class="modal-body">
                        <?php if (isset($_GET['error'])): ?>
                            <div class="alert alert-danger">Invalid credentials. Please try again.</div>
                        <?php endif; ?>
                        
                        <div class="vulnerability-hint">
                            <i class="fas fa-bug"></i> <strong>Hint:</strong> Try common SQL injection payloads in the username field. 
                            Examples: <code>' OR '1'='1' --</code> or <code>admin' --</code>
                        </div>
                        
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Login</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Register Modal -->
    <div class="modal fade" id="registerModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Register New Account</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="register.php">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="reg_username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="reg_username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="reg_email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="reg_email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="reg_password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="reg_password" name="password" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-success">Register</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <?php if (isset($_GET['login'])): ?>
    <script>
        var loginModal = new bootstrap.Modal(document.getElementById('loginModal'));
        loginModal.show();
    </script>
    <?php endif; ?>
</body>
</html>
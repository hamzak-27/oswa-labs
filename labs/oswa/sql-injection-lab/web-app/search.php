<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Redirect if not logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php?login=1');
    exit();
}

$search_results = [];
$search_query = '';
$search_performed = false;

// Handle search request
if (isset($_GET['search'])) {
    $search_query = $_GET['search'];
    $search_performed = true;
    
    // VULNERABLE TO BLIND SQL INJECTION
    // This query is vulnerable to boolean-based blind SQL injection
    $sql = "SELECT username, email FROM users WHERE username LIKE '%$search_query%'";
    
    if (ENABLE_DEBUG) {
        echo "<!-- DEBUG: Search query: $sql -->";
    }
    
    try {
        $stmt = $db->query($sql);
        $search_results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Hidden flag for successful blind SQL injection data extraction
        if (strpos($search_query, ' AND ') !== false || 
            strpos($search_query, ' OR ') !== false ||
            strpos($search_query, 'UNION') !== false) {
            
            // User is attempting SQL injection - provide feedback
            if (!isset($_SESSION['blind_sqli_attempts'])) {
                $_SESSION['blind_sqli_attempts'] = 0;
            }
            $_SESSION['blind_sqli_attempts']++;
            
            // Award flag after successful extraction attempt
            if ($_SESSION['blind_sqli_attempts'] >= 3) {
                $_SESSION['blind_flag_earned'] = 'OSWA{blind_sqli_data_extraction}';
                error_log("OSWA Lab: User earned blind SQL injection flag");
            }
        }
        
    } catch (PDOException $e) {
        if (ENABLE_DEBUG) {
            echo "<div class='alert alert-danger'>Database Error: " . $e->getMessage() . "</div>";
            echo "<p>Query: " . htmlspecialchars($sql) . "</p>";
        }
        $search_results = [];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureBank - User Search</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .bg-gradient-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-custom { box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15); border: 0; }
        .vulnerability-hint { background: #f8f9fa; border-left: 4px solid #28a745; padding: 15px; margin: 15px 0; }
        .blind-sqli-hint { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; }
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
                <a class="nav-link" href="dashboard.php">Dashboard</a>
                <a class="nav-link active" href="search.php">Search</a>
                <?php if ($_SESSION['is_admin']): ?>
                    <a class="nav-link" href="admin.php">Admin Panel</a>
                <?php endif; ?>
                <a class="nav-link" href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card card-custom">
                    <div class="card-body">
                        <h2 class="card-title mb-4">
                            <i class="fas fa-users"></i> User Directory Search
                        </h2>
                        
                        <!-- Search Form -->
                        <form method="GET" class="mb-4">
                            <div class="input-group">
                                <input type="text" class="form-control" name="search" 
                                       placeholder="Search for users..." 
                                       value="<?php echo htmlspecialchars($search_query); ?>">
                                <button class="btn btn-primary" type="submit">
                                    <i class="fas fa-search"></i> Search
                                </button>
                            </div>
                        </form>
                        
                        <!-- Blind SQL Injection Hint -->
                        <div class="blind-sqli-hint">
                            <i class="fas fa-lightbulb"></i> <strong>Blind SQL Injection Challenge:</strong><br>
                            Try extracting database information using boolean-based techniques.<br>
                            Examples: 
                            <ul>
                                <li><code>admin' AND 1=1 --</code> (True condition)</li>
                                <li><code>admin' AND 1=2 --</code> (False condition)</li>
                                <li><code>admin' AND LENGTH(password)=5 --</code> (Test password length)</li>
                                <li><code>' UNION SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=database()--</code></li>
                            </ul>
                            <small>Hint: Look for differences in response when conditions are true vs false.</small>
                        </div>
                        
                        <?php if (isset($_SESSION['blind_sqli_attempts']) && $_SESSION['blind_sqli_attempts'] > 0): ?>
                            <div class="alert alert-info">
                                <i class="fas fa-chart-line"></i> 
                                <strong>SQL Injection Attempts Detected:</strong> <?php echo $_SESSION['blind_sqli_attempts']; ?><br>
                                Keep trying different payloads to extract information!
                            </div>
                        <?php endif; ?>
                        
                        <?php if (isset($_SESSION['blind_flag_earned'])): ?>
                            <div class="alert alert-success">
                                <i class="fas fa-flag"></i> 
                                <strong>Flag Earned!</strong> <?php echo $_SESSION['blind_flag_earned']; ?><br>
                                Great work on the blind SQL injection!
                            </div>
                        <?php endif; ?>
                        
                        <!-- Search Results -->
                        <?php if ($search_performed): ?>
                            <h4>Search Results for "<?php echo htmlspecialchars($search_query); ?>"</h4>
                            
                            <?php if (count($search_results) > 0): ?>
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Username</th>
                                                <th>Email</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($search_results as $user): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                                                    <td>
                                                        <button class="btn btn-sm btn-outline-primary">
                                                            <i class="fas fa-envelope"></i> Contact
                                                        </button>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else: ?>
                                <div class="alert alert-info">
                                    <i class="fas fa-info-circle"></i> No users found matching your search.
                                    <?php if (strpos($search_query, "'") !== false): ?>
                                        <br><strong>SQL Injection detected in your query!</strong> 
                                        This might affect the results.
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                            
                            <!-- Debug information for educational purposes -->
                            <?php if (ENABLE_DEBUG && (strpos($search_query, "'") !== false || strpos($search_query, "UNION") !== false)): ?>
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-bug"></i> Debug Information:</h6>
                                    <p><strong>Your input:</strong> <?php echo htmlspecialchars($search_query); ?></p>
                                    <p><strong>Generated query:</strong> <code><?php echo htmlspecialchars($sql ?? ''); ?></code></p>
                                    <p><strong>Results returned:</strong> <?php echo count($search_results); ?> rows</p>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                        
                        <!-- Information about the database structure -->
                        <div class="card mt-4 bg-light">
                            <div class="card-body">
                                <h6><i class="fas fa-database"></i> Database Schema Hints</h6>
                                <p>The user table has these columns: id, username, email, password, is_admin</p>
                                <p>Try to extract information about other tables in the database!</p>
                                <p><strong>Common payloads to try:</strong></p>
                                <ul>
                                    <li>Test for database name</li>
                                    <li>Enumerate table names</li>
                                    <li>Extract column information</li>
                                    <li>Retrieve admin passwords</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';

session_start();

$db = Database::getInstance();
$security = new Security();

// Redirect if already logged in
if ($security->validateSession()) {
    if ($_SESSION['role'] === 'admin') {
        header('Location: index.php');
    } else {
        header('Location: user_dashboard.php');
    }
    exit;
}

// Handle login
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    $user = $security->authenticate($username, $password);
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['last_activity'] = time();
        
        $security->logSecurityEvent($user['id'], 'login_success', 'User logged in successfully');
        
        // Redirect based on role
        if ($user['role'] === 'admin') {
            header('Location: index.php');
        } else {
            header('Location: user_dashboard.php');
        }
        exit;
    } else {
        $error = "Invalid credentials or account locked";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Security Management System</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-container">
            <h2>🛡️ Security Management System</h2>
            
            <?php if (isset($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if (isset($session_timeout)): ?>
                <div class="error">Session expired. Please login again.</div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            
            <div class="info-box">
                <strong>Default Admin Account:</strong><br>
                Username: admin<br>
                Password: admin123!
            </div>

            <div class="security-info">
                <h3>🔒 Security Features</h3>
                <ul>
                    <li>Account lockout after <?php echo MAX_LOGIN_ATTEMPTS; ?> failed attempts</li>
                    <li>Session timeout after <?php echo SESSION_TIMEOUT/60; ?> minutes of inactivity</li>
                    <li>Secure password hashing</li>
                    <li>Role-based access control</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html> 
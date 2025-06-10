<?php
require_once 'config/config.php';
require_once 'includes/auth.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';

// Ensure user is logged in
if (!isLoggedIn()) {
    header('Location: login.php');
    exit();
}

$db = Database::getInstance();
$security = new Security();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    
    // Verify current password
    $user = $db->query(
        "SELECT * FROM users WHERE id = ?",
        [$_SESSION['user_id']]
    )->fetch(PDO::FETCH_ASSOC);
    
    if (!password_verify($currentPassword, $user['password'])) {
        $error = "Current password is incorrect";
        $security->logSecurityEvent(
            $_SESSION['user_id'],
            'password_change_failed',
            'Invalid current password provided',
            $_SERVER['REMOTE_ADDR'] ?? '::1'
        );
    }
    // Check if new passwords match
    elseif ($newPassword !== $confirmPassword) {
        $error = "New passwords do not match";
        $security->logSecurityEvent(
            $_SESSION['user_id'],
            'password_change_failed',
            'New passwords did not match',
            $_SERVER['REMOTE_ADDR'] ?? '::1'
        );
    }
    // Validate password complexity
    else {
        $passwordValidation = $security->validatePasswordComplexity($newPassword);
        if ($passwordValidation !== true) {
            $error = implode("<br>", $passwordValidation);
            $security->logSecurityEvent(
                $_SESSION['user_id'],
                'password_change_failed',
                'Password does not meet complexity requirements',
                $_SERVER['REMOTE_ADDR'] ?? '::1'
            );
        } 
        // Check password history
        elseif (!$security->checkPasswordHistory($_SESSION['user_id'], $newPassword)) {
            $error = "New password cannot be the same as any of your last 5 passwords";
            $security->logSecurityEvent(
                $_SESSION['user_id'],
                'password_change_failed',
                'Password found in history',
                $_SERVER['REMOTE_ADDR'] ?? '::1'
            );
        }
        else {
            // Update password
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            
            // Add to password history
            $security->addPasswordToHistory($_SESSION['user_id'], $hashedPassword);
            
            $db->query(
                "UPDATE users SET password = ? WHERE id = ?",
                [$hashedPassword, $_SESSION['user_id']]
            );
            
            // Log successful password change
            $security->logSecurityEvent(
                $_SESSION['user_id'],
                'password_changed',
                'Password successfully changed',
                $_SERVER['REMOTE_ADDR'] ?? '::1'
            );
            
            $success = "Password successfully changed";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h1>Change Password</h1>
        
        <?php if ($error): ?>
        <div class="alert alert-danger">
            <?php echo $error; ?>
        </div>
        <?php endif; ?>
        
        <?php if ($success): ?>
        <div class="alert alert-success">
            <?php echo $success; ?>
        </div>
        <?php endif; ?>
        
        <form method="POST" class="form">
            <div class="form-group">
                <label>Current Password:</label>
                <input type="password" name="current_password" required>
            </div>
            
            <div class="form-group">
                <label>New Password:</label>
                <input type="password" name="new_password" required>
            </div>
            
            <div class="form-group">
                <label>Confirm New Password:</label>
                <input type="password" name="confirm_password" required>
            </div>
            
            <div class="password-requirements">
                <h4>Password Requirements:</h4>
                <ul>
                    <li>At least <?php echo PASSWORD_MIN_LENGTH; ?> characters long</li>
                    <?php if (PASSWORD_REQUIRE_MIXED): ?>
                    <li>Must contain uppercase and lowercase letters</li>
                    <?php endif; ?>
                    <?php if (PASSWORD_REQUIRE_NUMBERS): ?>
                    <li>Must contain at least one number</li>
                    <?php endif; ?>
                    <?php if (PASSWORD_REQUIRE_SYMBOLS): ?>
                    <li>Must contain at least one special character</li>
                    <?php endif; ?>
                </ul>
            </div>
            
            <button type="submit" class="btn btn-primary">Change Password</button>
            <a href="index.php" class="btn">Back to Dashboard</a>
        </form>
    </div>
</body>
</html> 
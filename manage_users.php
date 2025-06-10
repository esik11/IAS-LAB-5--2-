<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';

session_start();

$db = Database::getInstance();
$security = new Security();

// Check if user is logged in and is admin
if (!$security->validateSession() || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

// Handle user actions
if (isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'add_user':
            $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
            $password = $_POST['password'];
            $role = filter_input(INPUT_POST, 'role', FILTER_SANITIZE_STRING);
            
            if ($security->enforcePolicy('password_strength')($password)) {
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                try {
                    $db->query(
                        "INSERT INTO users (username, password, role, is_locked) VALUES (?, ?, ?, 0)",
                        [$username, $hashedPassword, $role]
                    );
                    $security->logSecurityEvent($_SESSION['user_id'], 'user_created', "Created user: $username");
                    header('Location: manage_users.php?success=User created successfully');
                } catch (Exception $e) {
                    header('Location: manage_users.php?error=Username already exists');
                }
            } else {
                header('Location: manage_users.php?error=Password does not meet security requirements');
            }
            exit;

        case 'update_user':
            $user_id = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_NUMBER_INT);
            $role = filter_input(INPUT_POST, 'role', FILTER_SANITIZE_STRING);
            $is_locked = isset($_POST['is_locked']) ? 1 : 0;
            
            if (isset($_POST['password']) && !empty($_POST['password'])) {
                if ($security->enforcePolicy('password_strength')($_POST['password'])) {
                    $hashedPassword = password_hash($_POST['password'], PASSWORD_DEFAULT);
                    $db->query(
                        "UPDATE users SET password = ?, role = ?, is_locked = ? WHERE id = ?",
                        [$hashedPassword, $role, $is_locked, $user_id]
                    );
                } else {
                    header('Location: manage_users.php?error=New password does not meet security requirements');
                    exit;
                }
            } else {
                $db->query(
                    "UPDATE users SET role = ?, is_locked = ? WHERE id = ?",
                    [$role, $is_locked, $user_id]
                );
            }
            
            $security->logSecurityEvent($_SESSION['user_id'], 'user_updated', "Updated user ID: $user_id");
            header('Location: manage_users.php?success=User updated successfully');
            exit;

        case 'delete_user':
            $user_id = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_NUMBER_INT);
            // Don't allow deleting own account
            if ($user_id != $_SESSION['user_id']) {
                $db->query("DELETE FROM users WHERE id = ?", [$user_id]);
                $security->logSecurityEvent($_SESSION['user_id'], 'user_deleted', "Deleted user ID: $user_id");
                header('Location: manage_users.php?success=User deleted successfully');
            } else {
                header('Location: manage_users.php?error=Cannot delete your own account');
            }
            exit;
    }
}

// Get user for editing if ID is provided
$edit_user = null;
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $edit_user = $db->query(
        "SELECT id, username, role, is_locked FROM users WHERE id = ?",
        [$_GET['edit']]
    )->fetch(PDO::FETCH_ASSOC);
}

// Get all users with their last login and activity
$users = $db->query(
    "SELECT u.*, 
            MAX(CASE WHEN sl.action = 'login' THEN sl.created_at END) as last_login,
            COUNT(CASE WHEN sl.action = 'login_failed' AND sl.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as recent_failed_logins,
            COUNT(sl.id) as total_activities
     FROM users u
     LEFT JOIN security_logs sl ON u.id = sl.user_id
     GROUP BY u.id
     ORDER BY u.username"
)->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - Security System</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>User Management</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <span class="role-badge"><?php echo htmlspecialchars($_SESSION['role']); ?></span>
                <a href="index.php" class="btn">Dashboard</a>
                <a href="?action=logout" class="btn-logout">Logout</a>
            </div>
        </header>

        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($_GET['success']); ?>
            </div>
        <?php endif; ?>

        <?php if (isset($_GET['error'])): ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($_GET['error']); ?>
            </div>
        <?php endif; ?>

        <!-- User Form -->
        <div class="card">
            <h2><?php echo $edit_user ? 'Edit User' : 'Add New User'; ?></h2>
            <form method="POST" class="form">
                <input type="hidden" name="action" value="<?php echo $edit_user ? 'update_user' : 'add_user'; ?>">
                <?php if ($edit_user): ?>
                    <input type="hidden" name="user_id" value="<?php echo $edit_user['id']; ?>">
                <?php endif; ?>

                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" value="<?php echo $edit_user ? htmlspecialchars($edit_user['username']) : ''; ?>"
                           <?php echo $edit_user ? 'readonly' : 'required'; ?>>
                </div>

                <div class="form-group">
                    <label><?php echo $edit_user ? 'New Password (leave blank to keep current)' : 'Password'; ?></label>
                    <input type="password" name="password" <?php echo $edit_user ? '' : 'required'; ?>>
                    <small>Minimum 8 characters, must include uppercase, lowercase, number, and special character</small>
                </div>

                <div class="form-group">
                    <label>Role</label>
                    <select name="role" required>
                        <option value="user" <?php echo ($edit_user && $edit_user['role'] === 'user') ? 'selected' : ''; ?>>User</option>
                        <option value="admin" <?php echo ($edit_user && $edit_user['role'] === 'admin') ? 'selected' : ''; ?>>Admin</option>
                    </select>
                </div>

                <?php if ($edit_user): ?>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" name="is_locked" <?php echo $edit_user['is_locked'] ? 'checked' : ''; ?>>
                            Account Locked
                        </label>
                    </div>
                <?php endif; ?>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">
                        <?php echo $edit_user ? 'Update User' : 'Add User'; ?>
                    </button>
                    <?php if ($edit_user): ?>
                        <a href="manage_users.php" class="btn">Cancel</a>
                    <?php endif; ?>
                </div>
            </form>
        </div>

        <!-- Users List -->
        <div class="card">
            <h2>User Accounts</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Recent Failed Logins</th>
                        <th>Total Activities</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td>
                                <span class="role-badge role-<?php echo $user['role']; ?>">
                                    <?php echo ucfirst(htmlspecialchars($user['role'])); ?>
                                </span>
                            </td>
                            <td>
                                <span class="status-badge status-<?php echo $user['is_locked'] ? 'danger' : 'success'; ?>">
                                    <?php echo $user['is_locked'] ? 'Locked' : 'Active'; ?>
                                </span>
                            </td>
                            <td><?php echo $user['last_login'] ? date('Y-m-d H:i', strtotime($user['last_login'])) : 'Never'; ?></td>
                            <td>
                                <span class="status-badge status-<?php echo $user['recent_failed_logins'] > 0 ? 'warning' : 'success'; ?>">
                                    <?php echo $user['recent_failed_logins']; ?>
                                </span>
                            </td>
                            <td><?php echo $user['total_activities']; ?></td>
                            <td>
                                <div class="action-buttons">
                                    <a href="?edit=<?php echo $user['id']; ?>" class="btn btn-sm">Edit</a>
                                    <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this user?');">
                                            <input type="hidden" name="action" value="delete_user">
                                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                            <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html> 
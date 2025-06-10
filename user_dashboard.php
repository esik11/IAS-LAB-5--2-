<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';

session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance();
$security = new Security();

// Get user's personal information
$user_id = $_SESSION['user_id'];
$stmt = $db->query("SELECT * FROM users WHERE id = ?", [$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// Get user's security incidents
$incidents = $db->query(
    "SELECT * FROM security_incidents 
     WHERE reported_by = ? 
     ORDER BY created_at DESC 
     LIMIT 5",
    [$user_id]
)->fetchAll(PDO::FETCH_ASSOC);

// Get user's last login time
$last_login = $db->query(
    "SELECT created_at FROM security_logs 
     WHERE user_id = ? AND action = 'login_success' 
     ORDER BY created_at DESC 
     LIMIT 1, 1", // Skip current login, get previous
    [$user_id]
)->fetchColumn();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard - Security Management System</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <!-- Bootstrap JavaScript Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="dashboard">
            <header>
                <h1>👤 User Dashboard</h1>
                <div class="user-info">
                    <span>Welcome, <?php echo htmlspecialchars($user['username']); ?></span>
                    <span class="role-badge <?php echo $_SESSION['role']; ?>"><?php echo $_SESSION['role']; ?></span>
                    <a href="index.php" class="btn btn-primary">Main Dashboard</a>
                    <a href="?action=logout" class="btn btn-danger">Logout</a>
                </div>
            </header>

            <div class="row mt-4">
                <!-- User Profile Card -->
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Profile Information</h5>
                            <div class="profile-info">
                                <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                                <p><strong>Role:</strong> <?php echo htmlspecialchars($_SESSION['role']); ?></p>
                                <p><strong>Last Login:</strong> <?php echo $last_login ? date('Y-m-d H:i:s', strtotime($last_login)) : 'First Login'; ?></p>
                                <p><strong>Account Created:</strong> <?php echo date('Y-m-d H:i:s', strtotime($user['created_at'])); ?></p>
                            </div>
                        </div>
                    </div>

                    <!-- Quick Actions -->
                    <div class="card mt-4">
                        <div class="card-body">
                            <h5 class="card-title">Quick Actions</h5>
                            <div class="d-grid gap-2">
                                <a href="index.php#incidents" class="btn btn-primary">Report New Incident</a>
                                <button type="button" class="btn btn-secondary" data-bs-toggle="modal" data-bs-target="#changePasswordModal">
                                    Change Password
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Reported Incidents -->
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Your Reported Incidents</h5>
                            <?php if (empty($incidents)): ?>
                                <p class="text-muted">You haven't reported any security incidents yet.</p>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Date</th>
                                                <th>Title</th>
                                                <th>Description</th>
                                                <th>Severity</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($incidents as $incident): ?>
                                            <tr class="severity-<?php echo htmlspecialchars($incident['severity']); ?>">
                                                <td><?php echo date('Y-m-d H:i:s', strtotime($incident['created_at'])); ?></td>
                                                <td><?php echo htmlspecialchars($incident['title']); ?></td>
                                                <td><?php echo htmlspecialchars($incident['description']); ?></td>
                                                <td>
                                                    <span class="badge bg-<?php echo $incident['severity'] === 'high' ? 'danger' : ($incident['severity'] === 'medium' ? 'warning' : 'info'); ?>">
                                                        <?php echo ucfirst(htmlspecialchars($incident['severity'])); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo ucfirst(htmlspecialchars($incident['status'])); ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Change Password Modal -->
    <div class="modal fade" id="changePasswordModal" tabindex="-1" aria-labelledby="changePasswordModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="changePasswordModalLabel">Change Password</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form action="change_password.php" method="POST">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="currentPassword" class="form-label">Current Password</label>
                            <input type="password" class="form-control" id="currentPassword" name="current_password" required>
                        </div>
                        <div class="mb-3">
                            <label for="newPassword" class="form-label">New Password</label>
                            <input type="password" class="form-control" id="newPassword" name="new_password" required>
                            <div class="form-text">Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.</div>
                        </div>
                        <div class="mb-3">
                            <label for="confirmPassword" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirmPassword" name="confirm_password" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Change Password</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html> 
<?php
require_once '../config/config.php';
require_once '../includes/auth.php';
require_once '../includes/Database.php';

// Ensure user is logged in and is admin
if (!isLoggedIn() || !isAdmin()) {
    header('Location: ../login.php');
    exit();
}

$db = Database::getInstance();

// Get filter parameters
$action = $_GET['action'] ?? '';
$startDate = $_GET['start_date'] ?? '';
$endDate = $_GET['end_date'] ?? '';
$user = $_GET['user'] ?? '';

// Build query
$query = "SELECT sl.*, u.username 
          FROM security_logs sl 
          LEFT JOIN users u ON sl.user_id = u.id 
          WHERE 1=1";
$params = [];

if ($action) {
    $query .= " AND sl.action = ?";
    $params[] = $action;
}

if ($startDate) {
    $query .= " AND DATE(sl.timestamp) >= ?";
    $params[] = $startDate;
}

if ($endDate) {
    $query .= " AND DATE(sl.timestamp) <= ?";
    $params[] = $endDate;
}

if ($user) {
    $query .= " AND (u.username LIKE ? OR sl.role LIKE ?)";
    $params[] = "%$user%";
    $params[] = "%$user%";
}

$query .= " ORDER BY sl.timestamp DESC LIMIT 1000";

$logs = $db->query($query, $params)->fetchAll(PDO::FETCH_ASSOC);

// Get unique actions for filter
$actions = $db->query("SELECT DISTINCT action FROM security_logs ORDER BY action")->fetchAll(PDO::FETCH_COLUMN);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Logs - Admin Panel</title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>
    <div class="container">
        <h1>Security Logs</h1>
        
        <div class="filters">
            <form method="GET" class="form-inline">
                <div class="form-group">
                    <label>Action:</label>
                    <select name="action">
                        <option value="">All</option>
                        <?php foreach ($actions as $act): ?>
                        <option value="<?php echo htmlspecialchars($act); ?>" 
                                <?php echo $act === $action ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($act); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Start Date:</label>
                    <input type="date" name="start_date" value="<?php echo htmlspecialchars($startDate); ?>">
                </div>
                
                <div class="form-group">
                    <label>End Date:</label>
                    <input type="date" name="end_date" value="<?php echo htmlspecialchars($endDate); ?>">
                </div>
                
                <div class="form-group">
                    <label>User/Role:</label>
                    <input type="text" name="user" value="<?php echo htmlspecialchars($user); ?>" 
                           placeholder="Search username or role">
                </div>
                
                <button type="submit" class="btn btn-primary">Filter</button>
                <a href="security_logs.php" class="btn">Clear Filters</a>
            </form>
        </div>
        
        <div class="table-responsive">
            <table class="table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Details</th>
                        <th>IP Address</th>
                        <th>Role</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log): ?>
                    <tr class="<?php echo strpos($log['action'], 'failed') !== false ? 'alert-danger' : ''; ?>">
                        <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                        <td><?php echo htmlspecialchars($log['username'] ?? 'System'); ?></td>
                        <td><?php echo htmlspecialchars($log['action']); ?></td>
                        <td><?php echo htmlspecialchars($log['details']); ?></td>
                        <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                        <td><?php echo htmlspecialchars($log['role']); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <div class="actions">
            <a href="index.php" class="btn">Back to Dashboard</a>
        </div>
    </div>
</body>
</html> 
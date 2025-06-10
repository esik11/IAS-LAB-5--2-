<?php
require_once '../config/config.php';
require_once '../includes/auth.php';
require_once '../includes/Database.php';

// Ensure user is logged in and has appropriate permissions
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403);
    exit('Access denied');
}

$db = Database::getInstance();

// Get recent security events
$events = $db->query("
    SELECT 
        timestamp,
        event_type,
        details,
        status
    FROM security_logs
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    ORDER BY timestamp DESC
    LIMIT 10
")->fetchAll(PDO::FETCH_ASSOC);

// Generate HTML for the events
foreach ($events as $event) {
    $statusClass = '';
    switch (strtolower($event['status'])) {
        case 'success':
            $statusClass = 'text-success';
            break;
        case 'warning':
            $statusClass = 'text-warning';
            break;
        case 'error':
            $statusClass = 'text-danger';
            break;
        default:
            $statusClass = 'text-info';
    }
    
    echo "<tr>";
    echo "<td>" . date('H:i:s', strtotime($event['timestamp'])) . "</td>";
    echo "<td>" . htmlspecialchars($event['event_type']) . "</td>";
    echo "<td>" . htmlspecialchars($event['details']) . "</td>";
    echo "<td class='{$statusClass}'>" . htmlspecialchars($event['status']) . "</td>";
    echo "</tr>";
}
?> 
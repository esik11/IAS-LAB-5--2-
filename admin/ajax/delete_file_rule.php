<?php
require_once('../../includes/auth_check.php');
require_once('../../includes/db_connect.php');

// Check if user is admin
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['id'])) {
    $stmt = $db->query(
        "DELETE FROM file_security_rules WHERE id = ?",
        [$_POST['id']]
    );
    
    echo json_encode(['success' => true]);
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request']);
}
?> 
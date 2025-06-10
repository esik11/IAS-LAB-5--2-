<?php
require_once('../../includes/auth_check.php');
require_once('../../includes/db_connect.php');

// Check if user is admin
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['id']) && isset($_POST['field']) && isset($_POST['value'])) {
    // Validate field name to prevent SQL injection
    $allowed_fields = ['is_allowed', 'scan_for_malware', 'require_encryption', 'max_size'];
    if (!in_array($_POST['field'], $allowed_fields)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid field name']);
        exit();
    }

    $sql = "UPDATE file_security_rules SET " . $_POST['field'] . " = ? WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $_POST['value'], $_POST['id']);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update file security rule']);
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request']);
}
?> 
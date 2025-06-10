<?php
require_once('../../includes/auth_check.php');
require_once('../../includes/db_connect.php');

// Check if user is admin
if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setting_name']) && isset($_POST['value'])) {
    // Validate setting name
    $allowed_settings = ['ssl_enabled', 'min_tls_version', 'preferred_ciphers', 'hsts_enabled', 'hsts_max_age'];
    if (!in_array($_POST['setting_name'], $allowed_settings)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid setting name']);
        exit();
    }

    $stmt = $conn->prepare("UPDATE ssl_configuration SET setting_value = ?, updated_by = ? WHERE setting_name = ?");
    $stmt->bind_param("sis", $_POST['value'], $_SESSION['user_id'], $_POST['setting_name']);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update SSL/TLS setting']);
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request']);
}
?> 
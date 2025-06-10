<?php
// Suppress warnings and notices that might break JSON output
error_reporting(0);
ini_set('display_errors', 0);

// Set proper JSON content type header
header('Content-Type: application/json');

// Start output buffering to catch any unwanted output
ob_start();

require_once '../../includes/db.php';
require_once '../../includes/auth.php';

// Ensure user is logged in and is admin
if (!isLoggedIn() || !isAdmin()) {
    ob_end_clean();
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit;
}

// Validate input
if (!isset($_POST['file_type']) || !isset($_POST['max_size'])) {
    ob_end_clean();
    echo json_encode(['success' => false, 'message' => 'Missing required fields']);
    exit;
}

try {
    $db = new Database();
    
    // Sanitize and validate inputs
    $file_type = trim(filter_var($_POST['file_type'], FILTER_SANITIZE_STRING));
    $max_size = filter_var($_POST['max_size'], FILTER_VALIDATE_FLOAT);
    $is_allowed = isset($_POST['is_allowed']) ? 1 : 0;
    $scan_for_malware = isset($_POST['scan_for_malware']) ? 1 : 0;
    $require_encryption = isset($_POST['require_encryption']) ? 1 : 0;

    if ($max_size === false) {
        ob_end_clean();
        echo json_encode(['success' => false, 'message' => 'Invalid max size value']);
        exit;
    }

    // Check if file type already exists
    $check_sql = "SELECT COUNT(*) as count FROM file_security_rules WHERE file_type = ?";
    $check_result = $db->query($check_sql, [$file_type]);
    $exists = $check_result->fetch(PDO::FETCH_ASSOC)['count'] > 0;

    if ($exists) {
        ob_end_clean();
        echo json_encode(['success' => false, 'message' => 'File type already exists']);
        exit;
    }

    $sql = "INSERT INTO file_security_rules 
            (file_type, max_size, is_allowed, scan_for_malware, require_encryption) 
            VALUES (?, ?, ?, ?, ?)";
    
    $params = [$file_type, $max_size, $is_allowed, $scan_for_malware, $require_encryption];
    $result = $db->query($sql, $params);
    
    if ($result) {
        // Get the inserted ID
        $new_id = $db->lastInsertId();
        
        // Log the change
        $log_sql = "INSERT INTO security_logs (action_type, description, user_id) 
                    VALUES ('file_rule_add', ?, ?)";
        $log_desc = "Added new file security rule for type: " . htmlspecialchars($file_type);
        $db->query($log_sql, [$log_desc, $_SESSION['user_id']]);
        
        ob_end_clean();
        echo json_encode([
            'success' => true,
            'message' => 'File rule added successfully',
            'data' => [
                'id' => $new_id,
                'file_type' => $file_type,
                'max_size' => $max_size,
                'is_allowed' => $is_allowed,
                'scan_for_malware' => $scan_for_malware,
                'require_encryption' => $require_encryption
            ]
        ]);
    } else {
        ob_end_clean();
        echo json_encode(['success' => false, 'message' => 'Failed to add file rule']);
    }
} catch (Exception $e) {
    error_log("Error adding file rule: " . $e->getMessage());
    ob_end_clean();
    echo json_encode(['success' => false, 'message' => 'Database error occurred: ' . $e->getMessage()]);
}
?> 
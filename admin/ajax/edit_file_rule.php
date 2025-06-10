<?php
// Prevent any output before headers
ob_start();

// Set error handling
error_reporting(E_ALL);
ini_set('display_errors', 0);

try {
    // Set JSON header
    header('Content-Type: application/json');

    // Include configuration and database class
    require_once '../../config/config.php';
    require_once '../../includes/Database.php';
    
    // Basic validation
    if (!isset($_POST['id']) || !isset($_POST['file_type']) || !isset($_POST['max_size'])) {
        throw new Exception('Missing required fields');
    }

    // Get and sanitize inputs
    $id = (int)$_POST['id'];
    $file_type = trim($_POST['file_type']);
    $max_size = (float)$_POST['max_size'];
    $is_allowed = isset($_POST['is_allowed']) ? 1 : 0;
    $scan_for_malware = isset($_POST['scan_for_malware']) ? 1 : 0;
    $require_encryption = isset($_POST['require_encryption']) ? 1 : 0;

    // Get database instance
    $db = Database::getInstance();

    // Update the rule
    $sql = "UPDATE file_security_rules 
            SET file_type = ?, 
                max_size = ?, 
                is_allowed = ?, 
                scan_for_malware = ?, 
                require_encryption = ? 
            WHERE id = ?";

    $result = $db->query($sql, [
        $file_type,
        $max_size,
        $is_allowed,
        $scan_for_malware,
        $require_encryption,
        $id
    ]);

    if ($result) {
        // Clear any output and send success response
        ob_clean();
        echo json_encode([
            'success' => true,
            'message' => 'File rule updated successfully'
        ]);
    } else {
        throw new Exception('Failed to update file rule');
    }

} catch (Exception $e) {
    // Log the error
    error_log("Error in edit_file_rule.php: " . $e->getMessage());
    
    // Clear any output and send error response
    ob_clean();
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}

// End output buffer
ob_end_flush();
?> 
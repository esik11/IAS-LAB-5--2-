<?php
// Disable error display in output
error_reporting(0);
ini_set('display_errors', 0);

// Set JSON content type first
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    require_once 'database/db_connect.php';

    // Get policy ID from request
    $policyId = isset($_GET['id']) ? intval($_GET['id']) : 0;

    if ($policyId <= 0) {
        throw new Exception('Invalid policy ID');
    }

    $conn = connectDB();
    
    // Fetch policy details
    $stmt = $conn->prepare("
        SELECT 
            id,
            policy_name,
            description,
            category,
            status,
            requirements,
            implementation_details,
            created_at
        FROM security_policies
        WHERE id = ?
    ");
    
    $stmt->execute([$policyId]);
    $policy = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$policy) {
        throw new Exception('Policy not found');
    }
    
    // Convert requirements string to array
    $requirements = array_map('trim', explode("\n", $policy['requirements']));
    // Remove the bullet points from requirements
    $requirements = array_map(function($req) {
        return trim($req, "- \t\n\r\0\x0B");
    }, $requirements);
    
    // Filter out empty requirements
    $requirements = array_filter($requirements);
    
    $policy['requirements'] = $requirements;
    
    echo json_encode([
        'success' => true,
        'data' => $policy
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
} 
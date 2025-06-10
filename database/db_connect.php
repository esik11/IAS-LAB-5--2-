<?php
function connectDB() {
    try {
        $host = 'localhost';
        $dbname = 'security_system';  // Changed to match your database name
        $username = 'root';
        $password = '';
        
        $conn = new PDO(
            "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
            $username,
            $password,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        
        return $conn;
    } catch (PDOException $e) {
        // Log the error but don't expose details
        error_log("Database Connection Error: " . $e->getMessage());
        
        // Return a JSON error response
        header('Content-Type: application/json');
        http_response_code(500);
        echo json_encode(['error' => 'Database connection failed']);
        exit;
    }
} 
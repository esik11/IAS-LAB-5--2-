<?php
class Database {
    private $pdo;
    private $encryption;
    private static $instance = null;

    private function __construct() {
        try {
            // Use config constants instead of hardcoded values
            $this->pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8",
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
            
            // Only initialize encryption if needed
            if (defined('USE_ENCRYPTION') && USE_ENCRYPTION) {
                require_once 'Encryption.php';
                $this->encryption = new Encryption();
            }
        } catch(PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw $e;
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->pdo;
    }

    public function query($sql, $params = []) {
        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch(PDOException $e) {
            $this->logError('Database query error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function createTables() {
        // Users table
        $this->query("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'user') NOT NULL,
            login_attempts INT DEFAULT 0,
            last_login_attempt DATETIME,
            is_locked BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");

        // Security logs table
        $this->query("CREATE TABLE IF NOT EXISTS security_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(100) NOT NULL,
            ip_address VARCHAR(45),
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )");

        // Security policies table
        $this->query("CREATE TABLE IF NOT EXISTS security_policies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            policy_name VARCHAR(100) NOT NULL,
            description TEXT,
            category ENUM('password', 'access', 'data', 'network', 'incident', 'compliance') NOT NULL,
            status ENUM('active', 'inactive', 'draft') DEFAULT 'draft',
            requirements TEXT,
            implementation_details TEXT,
            review_date DATE,
            last_audit_date DATETIME,
            last_audit_result ENUM('pass', 'fail', 'partial') DEFAULT NULL,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            created_by INT,
            updated_by INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )");

        // Security incidents table
        $this->query("CREATE TABLE IF NOT EXISTS security_incidents (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
            status ENUM('open', 'in_progress', 'resolved', 'closed') DEFAULT 'open',
            reported_by INT,
            assigned_to INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (reported_by) REFERENCES users(id),
            FOREIGN KEY (assigned_to) REFERENCES users(id)
        )");
    }

    public function createDefaultAdmin() {
        $adminExists = $this->query(
            "SELECT COUNT(*) FROM users WHERE username = ?", 
            [DEFAULT_ADMIN_USERNAME]
        )->fetchColumn();

        if (!$adminExists) {
            $hashedPassword = password_hash(DEFAULT_ADMIN_PASSWORD, PASSWORD_DEFAULT);
            $this->query(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
                [DEFAULT_ADMIN_USERNAME, $hashedPassword]
            );
        }
    }

    // Optimized method to handle sensitive data
    public function insertWithEncryption($table, $data, $sensitiveFields = []) {
        if (empty($sensitiveFields) || !isset($this->encryption)) {
            return $this->insert($table, $data);
        }

        foreach ($sensitiveFields as $field) {
            if (isset($data[$field])) {
                $data[$field] = 'enc:' . $this->encryption->encrypt($data[$field]);
            }
        }
        
        return $this->insert($table, $data);
    }

    // Basic insert method
    public function insert($table, $data) {
        $fields = array_keys($data);
        $placeholders = str_repeat('?,', count($fields) - 1) . '?';
        
        $sql = "INSERT INTO {$table} (" . implode(',', $fields) . ") VALUES ({$placeholders})";
        
        return $this->query($sql, array_values($data));
    }

    // Optimized method to retrieve encrypted data
    public function selectWithDecryption($sql, $params = [], $sensitiveFields = []) {
        if (empty($sensitiveFields) || !isset($this->encryption)) {
            return $this->query($sql, $params)->fetchAll();
        }

        $stmt = $this->query($sql, $params);
        $results = [];
        
        // Process one row at a time to save memory
        while ($row = $stmt->fetch()) {
            foreach ($sensitiveFields as $field) {
                if (isset($row[$field]) && strpos($row[$field], 'enc:') === 0) {
                    $row[$field] = $this->encryption->decrypt(substr($row[$field], 4));
                }
            }
            $results[] = $row;
        }
        
        return $results;
    }

    // Optimized logging method
    public function logSecurityEvent($userId, $action, $details, $ipAddress = null) {
        try {
            if ($ipAddress === null) {
                $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '::1';
            }
            
            // Get user role if user_id is provided
            $role = 'system';
            if ($userId) {
                $stmt = $this->query("SELECT role FROM users WHERE id = ?", [$userId]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($user) {
                    $role = $user['role'];
                }
            }
            
            $this->query(
                "INSERT INTO security_logs (user_id, action, details, ip_address, role) 
                 VALUES (?, ?, ?, ?, ?)",
                [$userId, $action, $details, $ipAddress, $role]
            );
            
            return true;
        } catch (Exception $e) {
            error_log("Error logging security event: " . $e->getMessage());
            return false;
        }
    }

    private function logError($message) {
        try {
            $this->query(
                "INSERT INTO error_logs (message, created_at) VALUES (?, NOW())",
                [substr($message, 0, 255)]
            );
        } catch(Exception $e) {
            error_log($message);
        }
    }
} 
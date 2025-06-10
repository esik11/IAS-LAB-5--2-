<?php

class Database {
    private $pdo;
    
    public function __construct() {
        try {
            // Update to connect to MySQL/MariaDB
            // Replace 'localhost', 'your_database', 'your_username', 'your_password' with your actual XAMPP MySQL details
            $host = 'localhost';
            $db_name = 'security_system_db'; // Choose a name for your new database in phpMyAdmin
            $username = 'root'; // Default XAMPP MySQL username
            $password = ''; // Default XAMPP MySQL password (often empty)

            $this->pdo = new PDO("mysql:host=$host;dbname=$db_name;charset=utf8", $username, $password);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->initializeDatabase();
        } catch(PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }
    
    private function initializeDatabase() {
        // Note: AUTOINCREMENT is generally just AUTO_INCREMENT in MySQL.
        // SQLite specific: id INTEGER PRIMARY KEY AUTOINCREMENT,
        // MySQL equivalent: id INT PRIMARY KEY AUTO_INCREMENT,

        // Users table
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            last_login DATETIME,
            failed_attempts INT DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        
        // Security policies table
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS security_policies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            policy_name VARCHAR(100) NOT NULL UNIQUE,
            policy_type VARCHAR(50) NOT NULL,
            description TEXT,
            compliance_status VARCHAR(20) DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        
        // Security logs table
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS security_logs (
            id INT PRIMARY KEY AUTO_INCREMENT,
            user_id INT,
            action VARCHAR(100) NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            status VARCHAR(20),
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Security incidents table
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS security_incidents (
            id INT PRIMARY KEY AUTO_INCREMENT,
            incident_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            description TEXT,
            status VARCHAR(20) DEFAULT 'open',
            assigned_to INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME
        )");
        
        // Compliance audits table
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS compliance_audits (
            id INT PRIMARY KEY AUTO_INCREMENT,
            audit_type VARCHAR(50) NOT NULL,
            policy_id INT,
            compliance_score INT,
            findings TEXT,
            recommendations TEXT,
            auditor VARCHAR(100),
            audit_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Create default admin user if not exists
        $this->createDefaultAdmin();
        $this->insertDefaultPolicies();
    }
    
    private function createDefaultAdmin() {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
        $stmt->execute();
        
        if ($stmt->fetchColumn() == 0) {
            $password_hash = password_hash('admin123!', PASSWORD_DEFAULT);
            $stmt = $this->pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
            $stmt->execute(['admin', $password_hash, 'admin']);
        }
    }
    
    private function insertDefaultPolicies() {
        $policies = [
            ['Password Management', 'authentication', 'Minimum 8 characters, mixed case, numbers, special characters'],
            ['Network Access Control', 'network', 'Implement firewall rules and ACLs for network segmentation'],
            ['Data Protection', 'data', 'Encrypt data at rest and in transit using AES-256'],
            ['GDPR Compliance', 'regulatory', 'Ensure data protection according to GDPR requirements'],
            ['Role-Based Access Control', 'access', 'Implement least privilege access using RBAC'],
            ['Security Monitoring', 'monitoring', 'Continuous monitoring of security events and logs']
        ];
        
        foreach ($policies as $policy) {
            $stmt = $this->pdo->prepare("INSERT IGNORE INTO security_policies (policy_name, policy_type, description) VALUES (?, ?, ?)");
            $stmt->execute($policy);
        }
    }
    
    public function getConnection() {
        return $this->pdo;
    }
} 
<?php
require_once 'Database.php';

class Security {
    private $db;
    private $encryption_key;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->encryption_key = ENCRYPTION_KEY;
    }
    
    public function logLoginAttempt($username, $success, $reason = null) {
        $userId = null;
        $role = 'system';
        
        // Get user info if exists
        $user = $this->db->query(
            "SELECT id, role FROM users WHERE username = ?",
            [$username]
        )->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            $userId = $user['id'];
            $role = $user['role'];
        }
        
        $action = $success ? 'login_success' : 'login_failed';
        $details = $success ? 'User logged in successfully' : "Login failed - Reason: $reason";
        
        $this->logSecurityEvent(
            $userId,
            $action,
            $details,
            $_SERVER['REMOTE_ADDR'] ?? '::1',
            $role
        );
    }
    
    public function logPasswordChange($userId, $success, $reason = null) {
        $user = $this->db->query(
            "SELECT role FROM users WHERE id = ?",
            [$userId]
        )->fetch(PDO::FETCH_ASSOC);
        
        $action = $success ? 'password_changed' : 'password_change_failed';
        $details = $success ? 'Password changed successfully' : "Password change failed - Reason: $reason";
        
        $this->logSecurityEvent(
            $userId,
            $action,
            $details,
            $_SERVER['REMOTE_ADDR'] ?? '::1',
            $user['role'] ?? 'system'
        );
    }
    
    public function logSecurityEvent($userId, $action, $details, $ipAddress = null, $role = 'system') {
        try {
            if ($ipAddress === null) {
                $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '::1';
            }
            
            $this->db->query(
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
    
    public function authenticate($username, $password) {
        try {
            // Get user details
            $stmt = $this->db->query(
                "SELECT * FROM users WHERE username = ?",
                [$username]
            );
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Check if user exists
            if (!$user) {
                $this->logLoginAttempt($username, false, 'User not found');
                return false;
            }
            
            // Check if account is locked
            if ($user['is_locked']) {
                if (strtotime($user['last_login_attempt']) + LOCKOUT_TIME > time()) {
                    $this->logLoginAttempt($username, false, 'Account locked');
                    return false;
                }
                // Reset lock if lockout period has passed
                $this->db->query(
                    "UPDATE users SET is_locked = 0, login_attempts = 0 WHERE id = ?",
                    [$user['id']]
                );
            }
            
            // Verify password
            if (!password_verify($password, $user['password'])) {
                // Increment login attempts
                $attempts = $user['login_attempts'] + 1;
                $is_locked = $attempts >= MAX_LOGIN_ATTEMPTS ? 1 : 0;
                
                $this->db->query(
                    "UPDATE users SET login_attempts = ?, is_locked = ?, last_login_attempt = NOW() WHERE id = ?",
                    [$attempts, $is_locked, $user['id']]
                );
                
                $this->logLoginAttempt($username, false, "Invalid password (Attempt $attempts of " . MAX_LOGIN_ATTEMPTS . ")");
                return false;
            }
            
            // Reset login attempts on successful login
            $this->db->query(
                "UPDATE users SET login_attempts = 0, last_login_attempt = NOW() WHERE id = ?",
                [$user['id']]
            );
            
            $this->logLoginAttempt($username, true);
            return $user;
            
        } catch (Exception $e) {
            error_log("Authentication error: " . $e->getMessage());
            return false;
        }
    }
    
    public function validatePasswordComplexity($password) {
        $errors = [];
        
        // Check minimum length
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters long";
        }
        
        // Check for mixed case
        if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain both uppercase and lowercase letters";
        }
        
        // Check for numbers
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number";
        }
        
        // Check for special characters
        if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }
        
        return empty($errors) ? true : $errors;
    }
    
    public function validateSession() {
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['last_activity'])) {
            return false;
        }
        
        if (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
            session_destroy();
            return false;
        }
        
        $_SESSION['last_activity'] = time();
        return true;
    }

    public function enforcePolicy($policy) {
        switch ($policy) {
            case 'password_strength':
                return function($password) {
                    $length = strlen($password) >= PASSWORD_MIN_LENGTH;
                    $mixed = PASSWORD_REQUIRE_MIXED ? preg_match('/[a-z]/', $password) && preg_match('/[A-Z]/', $password) : true;
                    $numbers = PASSWORD_REQUIRE_NUMBERS ? preg_match('/[0-9]/', $password) : true;
                    $symbols = PASSWORD_REQUIRE_SYMBOLS ? preg_match('/[^a-zA-Z0-9]/', $password) : true;
                    return $length && $mixed && $numbers && $symbols;
                };
            
            case 'access_control':
                return function($required_role) {
                    return isset($_SESSION['role']) && $_SESSION['role'] === $required_role;
                };
        }
    }

    public function generateAuditReport() {
        $report = [];
        
        // Check password policy compliance
        $users_with_weak_passwords = $this->db->query(
            "SELECT COUNT(*) FROM users WHERE LENGTH(password) < ?",
            [PASSWORD_MIN_LENGTH]
        )->fetchColumn();
        
        $report['password_policy'] = [
            'compliant' => $users_with_weak_passwords === 0,
            'details' => "$users_with_weak_passwords users have weak passwords"
        ];

        // Check recent security incidents
        $recent_incidents = $this->db->query(
            "SELECT COUNT(*) FROM security_incidents WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
        )->fetchColumn();
        
        $report['security_incidents'] = [
            'status' => $recent_incidents > 10 ? 'warning' : 'good',
            'details' => "$recent_incidents security incidents in last 30 days"
        ];

        // Check login failures
        $login_failures = $this->db->query(
            "SELECT COUNT(*) FROM security_logs WHERE action = 'login_failed' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        )->fetchColumn();
        
        $report['login_attempts'] = [
            'status' => $login_failures > 50 ? 'critical' : ($login_failures > 20 ? 'warning' : 'good'),
            'details' => "$login_failures failed login attempts in last 24 hours"
        ];

        return $report;
    }

    // Add password history check
    public function checkPasswordHistory($userId, $newPassword) {
        // Get last 5 passwords
        $stmt = $this->db->query(
            "SELECT old_password_hash FROM password_history 
             WHERE user_id = ? 
             ORDER BY changed_at DESC LIMIT 5",
            [$userId]
        );
        $oldPasswords = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Check if new password matches any of the last 5
        foreach ($oldPasswords as $oldHash) {
            if (password_verify($newPassword, $oldHash)) {
                return false;
            }
        }
        return true;
    }
    
    // Add password to history
    public function addPasswordToHistory($userId, $passwordHash) {
        $this->db->query(
            "INSERT INTO password_history (user_id, old_password_hash) VALUES (?, ?)",
            [$userId, $passwordHash]
        );
    }
    
    // Data encryption function
    public function encryptData($data) {
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->encryption_key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    // Data decryption function
    public function decryptData($encryptedData) {
        $data = base64_decode($encryptedData);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $this->encryption_key, 0, $iv);
    }
} 
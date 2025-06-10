<?php
require_once 'Database.php';

class UserManager {
    private $db;
    private $encryption;
    
    public function __construct() {
        $this->db = Database::getInstance();
        require_once 'Encryption.php';
        $this->encryption = new Encryption();
    }
    
    public function updatePassword($userId, $newPassword) {
        // Hash the new password
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        // Store old password hash for audit
        $oldHash = $this->db->query(
            "SELECT password FROM users WHERE id = ?", 
            [$userId]
        )->fetchColumn();
        
        // Update password
        $this->db->query(
            "UPDATE users SET password = ? WHERE id = ?",
            [$hashedPassword, $userId]
        );
        
        // Log password change
        $this->db->logSecurityEvent(
            $userId,
            'password_changed',
            'User password was changed',
            $_SERVER['REMOTE_ADDR'] ?? '::1'
        );
        
        // Store password history (encrypted)
        $this->db->insertWithEncryption(
            'password_history',
            [
                'user_id' => $userId,
                'old_password_hash' => $oldHash,
                'changed_at' => date('Y-m-d H:i:s')
            ],
            ['old_password_hash']
        );
    }
    
    public function getUserDetails($userId) {
        return $this->db->selectWithDecryption(
            "SELECT * FROM users WHERE id = ?",
            [$userId],
            ['email', 'phone'] // Sensitive fields to decrypt
        );
    }
    
    public function createUser($username, $password, $role, $email = null) {
        // Check least privilege principle
        if ($role === 'admin' && !$this->isCurrentUserAdmin()) {
            throw new Exception('Insufficient privileges to create admin user');
        }
        
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Insert user with encrypted sensitive data
        $this->db->insertWithEncryption(
            'users',
            [
                'username' => $username,
                'password' => $hashedPassword,
                'role' => $role,
                'email' => $email,
                'created_at' => date('Y-m-d H:i:s')
            ],
            ['email'] // Fields to encrypt
        );
        
        $userId = $this->db->getConnection()->lastInsertId();
        
        // Log user creation
        $this->db->logSecurityEvent(
            $_SESSION['user_id'] ?? null,
            'user_created',
            "Created new user: $username with role: $role",
            $_SERVER['REMOTE_ADDR'] ?? '::1'
        );
        
        return $userId;
    }
    
    private function isCurrentUserAdmin() {
        return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
    }
    
    public function updateUserRole($userId, $newRole) {
        // Enforce least privilege principle
        if (!$this->isCurrentUserAdmin()) {
            throw new Exception('Only administrators can change user roles');
        }
        
        // Prevent removing the last admin
        if ($newRole !== 'admin') {
            $adminCount = $this->db->query(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?",
                [$userId]
            )->fetchColumn();
            
            if ($adminCount === 0) {
                throw new Exception('Cannot remove the last administrator');
            }
        }
        
        $this->db->query(
            "UPDATE users SET role = ? WHERE id = ?",
            [$newRole, $userId]
        );
        
        // Log role change
        $this->db->logSecurityEvent(
            $_SESSION['user_id'] ?? null,
            'role_changed',
            "Changed user ID: $userId role to: $newRole",
            $_SERVER['REMOTE_ADDR'] ?? '::1'
        );
    }
} 
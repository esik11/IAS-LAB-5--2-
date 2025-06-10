<?php
require_once 'Database.php';

class Encryption {
    private $db;
    
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    public function isDatabaseEncrypted() {
        // Check if database encryption is enabled in settings
        $encryption_settings = $this->db->query(
            "SELECT value FROM security_settings WHERE setting_name = 'database_encryption'"
        )->fetchColumn();
        
        return $encryption_settings === 'enabled';
    }
    
    public function encrypt($data, $key = null) {
        if ($key === null) {
            $key = $this->getEncryptionKey();
        }
        
        $cipher = "AES-256-CBC";
        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($ivlen);
        
        $encrypted = openssl_encrypt(
            $data,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        return base64_encode($iv . $encrypted);
    }
    
    public function decrypt($data, $key = null) {
        if ($key === null) {
            $key = $this->getEncryptionKey();
        }
        
        $data = base64_decode($data);
        $cipher = "AES-256-CBC";
        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = substr($data, 0, $ivlen);
        $encrypted = substr($data, $ivlen);
        
        return openssl_decrypt(
            $encrypted,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
    
    private function getEncryptionKey() {
        // In a real application, this would be stored securely
        // For demo purposes, we're using a constant
        return defined('ENCRYPTION_KEY') ? ENCRYPTION_KEY : 'your-secure-encryption-key';
    }
    
    public function encryptFile($filePath) {
        if (!file_exists($filePath)) {
            throw new Exception('File not found');
        }
        
        $content = file_get_contents($filePath);
        $encrypted = $this->encrypt($content);
        file_put_contents($filePath . '.enc', $encrypted);
        unlink($filePath); // Remove original file
        
        // Log encryption event
        $this->db->query(
            "INSERT INTO security_logs (action, description, ip_address) VALUES (?, ?, ?)",
            ['file_encrypted', "File encrypted: $filePath", $_SERVER['REMOTE_ADDR']]
        );
        
        return $filePath . '.enc';
    }
    
    public function decryptFile($encryptedPath) {
        if (!file_exists($encryptedPath)) {
            throw new Exception('Encrypted file not found');
        }
        
        $encrypted = file_get_contents($encryptedPath);
        $decrypted = $this->decrypt($encrypted);
        $originalPath = substr($encryptedPath, 0, -4); // Remove .enc
        file_put_contents($originalPath, $decrypted);
        unlink($encryptedPath); // Remove encrypted file
        
        // Log decryption event
        $this->db->query(
            "INSERT INTO security_logs (action, description, ip_address) VALUES (?, ?, ?)",
            ['file_decrypted', "File decrypted: $originalPath", $_SERVER['REMOTE_ADDR']]
        );
        
        return $originalPath;
    }
    
    public function encryptDatabase() {
        // Get all sensitive tables
        $tables = ['users', 'security_policies', 'security_incidents'];
        
        foreach ($tables as $table) {
            $rows = $this->db->query("SELECT * FROM $table")->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($rows as $row) {
                $updates = [];
                $params = [];
                
                // Encrypt sensitive columns
                foreach ($row as $column => $value) {
                    if ($this->isSensitiveColumn($column)) {
                        $updates[] = "$column = ?";
                        $params[] = $this->encrypt($value);
                    }
                }
                
                if (!empty($updates)) {
                    $sql = "UPDATE $table SET " . implode(', ', $updates) . " WHERE id = ?";
                    $params[] = $row['id'];
                    $this->db->query($sql, $params);
                }
            }
        }
    }
    
    private function isSensitiveColumn($column) {
        $sensitiveColumns = [
            'password', 'email', 'phone', 'address',
            'credit_card', 'ssn', 'description'
        ];
        return in_array(strtolower($column), $sensitiveColumns);
    }
}

// Create encryption configuration directory if it doesn't exist
if (!file_exists(__DIR__ . '/../config')) {
    mkdir(__DIR__ . '/../config', 0700, true);
} 
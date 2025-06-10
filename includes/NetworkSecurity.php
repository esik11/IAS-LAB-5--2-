<?php
class NetworkSecurity {
    private $db;
    private $allowed_ips = [];
    private $blocked_ips = [];
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->loadNetworkRules();
        $this->enforceHTTPS();
    }
    
    private function enforceHTTPS() {
        if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
            if (!headers_sent()) {
                header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
                exit();
            }
        }
    }
    
    private function loadNetworkRules() {
        // By default, allow all IPs
        $this->allowed_ips = ['*'];
        
        // Load whitelisted IPs
        $whitelisted = $this->db->query(
            "SELECT ip_address FROM ip_whitelist"
        )->fetchAll(PDO::FETCH_COLUMN);
        
        if (!empty($whitelisted)) {
            $this->allowed_ips = array_merge($this->allowed_ips, $whitelisted);
        }
        
        // Load manually blocked IPs
        $blocked = $this->db->query(
            "SELECT ip_address FROM ip_blacklist"
        )->fetchAll(PDO::FETCH_COLUMN);
        
        $this->blocked_ips = $blocked;
    }
    
    public function validateAccess($ip) {
        // Always allow localhost and local network IPs
        if ($ip === '127.0.0.1' || $ip === '::1' || substr($ip, 0, 7) === '192.168') {
            return true;
        }
        
        // Check if IP is blocked
        if (in_array($ip, $this->blocked_ips)) {
            return false;
        }
        
        // Allow all IPs by default
        if (in_array('*', $this->allowed_ips)) {
            return true;
        }
        
        // Check if IP is in allowed range
        foreach ($this->allowed_ips as $allowed) {
            if (strpos($allowed, '/') !== false) {
                // Handle CIDR notation
                if ($this->ipInRange($ip, $allowed)) {
                    return true;
                }
            } else {
                if ($ip === $allowed) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private function ipInRange($ip, $range) {
        list($range, $netmask) = explode('/', $range, 2);
        $range_decimal = ip2long($range);
        $ip_decimal = ip2long($ip);
        $wildcard_decimal = pow(2, (32 - $netmask)) - 1;
        $netmask_decimal = ~ $wildcard_decimal;
        return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
    }
    
    public function addFirewallRule($rule) {
        // Simulate adding firewall rules
        // In a real implementation, this would interface with the system firewall
        $this->db->query(
            "INSERT INTO firewall_rules (rule_type, rule_value, created_by) VALUES (?, ?, ?)",
            [$rule['type'], $rule['value'], $rule['created_by']]
        );
    }
    
    public function monitorTraffic() {
        // Simulate traffic monitoring
        // In a real implementation, this would analyze server logs or use network monitoring tools
        $traffic = $this->db->query(
            "SELECT ip_address, COUNT(*) as requests, 
                    MAX(created_at) as last_access
             FROM security_logs 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
             GROUP BY ip_address"
        )->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($traffic as $entry) {
            if ($entry['requests'] > 100) { // Threshold for suspicious activity
                $this->db->query(
                    "INSERT INTO security_incidents (
                        title, description, severity, status, reported_by
                    ) VALUES (
                        ?, ?, 'high', 'open', 1
                    )",
                    [
                        'Suspicious Traffic Detected',
                        "High traffic volume from IP {$entry['ip_address']}: {$entry['requests']} requests in the last hour"
                    ]
                );
            }
        }
        
        return $traffic;
    }
    
    public function checkRateLimit($ip, $action = 'default', $limit = 60, $period = 60) {
        // Clean old entries
        $this->db->query(
            "DELETE FROM rate_limits WHERE timestamp < DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$period]
        );
        
        // Count recent requests
        $count = $this->db->query(
            "SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND action = ? AND timestamp > DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$ip, $action, $period]
        )->fetchColumn();
        
        if ($count >= $limit) {
            // Log rate limit exceeded
            $this->db->logSecurityEvent(
                null,
                'rate_limit_exceeded',
                "Rate limit exceeded for IP: $ip, Action: $action",
                $ip
            );
            return false;
        }
        
        // Log the request
        $this->db->query(
            "INSERT INTO rate_limits (ip_address, action) VALUES (?, ?)",
            [$ip, $action]
        );
        
        return true;
    }
}

// Create tables for network security if they don't exist
$db = Database::getInstance();
$db->query("
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        rule_type ENUM('allow', 'deny') NOT NULL,
        rule_value VARCHAR(255) NOT NULL,
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )
"); 
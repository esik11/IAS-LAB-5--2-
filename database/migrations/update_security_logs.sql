-- Backup existing data
CREATE TABLE IF NOT EXISTS security_logs_backup AS SELECT * FROM security_logs;

-- Drop existing table
DROP TABLE IF EXISTS security_logs;

-- Create new table with updated structure
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(50) NOT NULL,
    details TEXT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'system',
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migrate existing data
INSERT INTO security_logs (user_id, action, details, ip_address, role, timestamp)
SELECT 
    user_id,
    action,
    COALESCE(details, 'No details provided'),
    COALESCE(ip_address, '::1'),
    COALESCE(role, 'system'),
    created_at
FROM security_logs_backup;

-- Keep backup table for safety
-- You can drop it later with: DROP TABLE security_logs_backup; 
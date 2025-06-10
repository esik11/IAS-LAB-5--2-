-- Create database if not exists
CREATE DATABASE IF NOT EXISTS security_system;
USE security_system;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL,
    login_attempts INT DEFAULT 0,
    last_login_attempt DATETIME,
    is_locked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security logs table
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    details TEXT,
    role VARCHAR(50) DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Security policies table
CREATE TABLE IF NOT EXISTS security_policies (
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
);

-- Security policy revisions table
CREATE TABLE IF NOT EXISTS policy_revisions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT NOT NULL,
    revision_number INT NOT NULL,
    changes_made TEXT,
    previous_content TEXT,
    revised_by INT,
    revision_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id),
    FOREIGN KEY (revised_by) REFERENCES users(id)
);

-- Security policy compliance table
CREATE TABLE IF NOT EXISTS policy_compliance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT NOT NULL,
    compliance_status ENUM('compliant', 'non_compliant', 'partially_compliant') NOT NULL,
    assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    next_review_date DATE,
    notes TEXT,
    assessed_by INT,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id),
    FOREIGN KEY (assessed_by) REFERENCES users(id)
);

-- Security incidents table
CREATE TABLE IF NOT EXISTS security_incidents (
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
);

-- Network security table
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    rule_type ENUM('allow', 'deny') NOT NULL,
    protocol ENUM('tcp', 'udp', 'icmp', 'all') NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    port_range VARCHAR(50),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    priority INT NOT NULL,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Compliance frameworks table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Compliance audits table
CREATE TABLE IF NOT EXISTS compliance_audits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    compliance_score DECIMAL(5,2) NOT NULL,
    audit_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_by INT,
    report_data TEXT,
    FOREIGN KEY (completed_by) REFERENCES users(id)
);

-- Compliance violations table
CREATE TABLE IF NOT EXISTS compliance_violations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'remediation', 'resolved', 'closed') DEFAULT 'open',
    framework_id INT,
    detected_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
);

-- Network Access Control Tables
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    description TEXT,
    added_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ip_blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason TEXT,
    added_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by) REFERENCES users(id)
);

-- File Security Table
CREATE TABLE IF NOT EXISTS file_security_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_type VARCHAR(50) NOT NULL,
    max_size INT NOT NULL, -- in bytes
    is_allowed BOOLEAN DEFAULT TRUE,
    scan_for_malware BOOLEAN DEFAULT TRUE,
    require_encryption BOOLEAN DEFAULT FALSE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- SSL/TLS Configuration Table
CREATE TABLE IF NOT EXISTS ssl_configuration (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_name VARCHAR(100) NOT NULL,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_by INT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Compliance Checks Table
CREATE TABLE IF NOT EXISTS compliance_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT,
    compliance_score DECIMAL(5,2),
    status ENUM('compliant', 'non_compliant', 'partially_compliant') NOT NULL,
    findings TEXT,
    recommendations TEXT,
    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    next_review_date DATE,
    reviewed_by INT,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id),
    FOREIGN KEY (reviewed_by) REFERENCES users(id)
);

-- Policy Requirements Table
CREATE TABLE IF NOT EXISTS policy_requirements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT,
    requirement_type ENUM('password_policy', 'file_security', 'network_security', 'access_control', 'data_protection') NOT NULL,
    description TEXT NOT NULL,
    weight DECIMAL(3,2) DEFAULT 1.00,
    is_mandatory BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id)
);

-- Audit Schedules Table
CREATE TABLE IF NOT EXISTS audit_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT,
    frequency ENUM('daily', 'weekly', 'monthly', 'quarterly', 'annually') NOT NULL,
    last_audit_date TIMESTAMP NULL,
    next_audit_date TIMESTAMP NOT NULL,
    status ENUM('scheduled', 'in_progress', 'completed', 'overdue') DEFAULT 'scheduled',
    assigned_to INT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

-- System Settings Table
CREATE TABLE IF NOT EXISTS system_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_name VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_by INT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Insert default system settings
INSERT INTO system_settings (setting_name, setting_value, description) VALUES
('min_password_length', '8', 'Minimum required password length'),
('password_requires_special', '1', 'Require special characters in passwords'),
('password_requires_numbers', '1', 'Require numbers in passwords'),
('password_requires_mixed_case', '1', 'Require mixed case in passwords'),
('data_encryption_enabled', '1', 'Enable data encryption for sensitive information'),
('database_encryption', 'enabled', 'Database encryption status');

-- Insert sample security policies
INSERT INTO security_policies (policy_name, description, category, status, requirements, implementation_details) VALUES
(
    'Password Policy',
    'Defines requirements for user passwords to ensure system security',
    'password',
    'active',
    '- Minimum 8 characters\n- Must include uppercase and lowercase letters\n- Must include numbers\n- Must include special characters\n- Maximum age of 90 days',
    'Implemented through password validation in the authentication system'
),
(
    'Access Control Policy',
    'Defines who can access what resources and under what conditions',
    'access',
    'active',
    '- Role-based access control\n- Principle of least privilege\n- Regular access reviews\n- Immediate revocation upon termination',
    'Implemented through role-based permission system'
),
(
    'Data Protection Policy',
    'Guidelines for protecting sensitive data and ensuring GDPR compliance',
    'data',
    'active',
    '- Data classification\n- Encryption requirements\n- Data retention periods\n- Data backup procedures',
    'Implemented through encryption and data handling procedures'
),
(
    'Incident Response Policy',
    'Procedures for handling and reporting security incidents',
    'incident',
    'active',
    '- Incident classification\n- Response procedures\n- Reporting requirements\n- Post-incident analysis',
    'Implemented through incident management system'
);

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (name, description) VALUES
('GDPR', 'General Data Protection Regulation compliance requirements'),
('HIPAA', 'Health Insurance Portability and Accountability Act requirements'),
('ISO 27001', 'Information Security Management System standard'),
('PCI DSS', 'Payment Card Industry Data Security Standard')
ON DUPLICATE KEY UPDATE id=id;

-- Insert default SSL/TLS settings
INSERT INTO ssl_configuration (setting_name, setting_value, description) VALUES
('ssl_enabled', 'true', 'Enable/Disable SSL/TLS'),
('min_tls_version', '1.2', 'Minimum TLS version allowed'),
('preferred_ciphers', 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256', 'Preferred cipher suites'),
('hsts_enabled', 'true', 'HTTP Strict Transport Security'),
('hsts_max_age', '31536000', 'HSTS max age in seconds');

-- Insert default file security rules
INSERT INTO file_security_rules (file_type, max_size, is_allowed, scan_for_malware, require_encryption) VALUES
('image/jpeg', 5242880, true, true, false),  -- 5MB for JPEG
('image/png', 5242880, true, true, false),   -- 5MB for PNG
('application/pdf', 10485760, true, true, true), -- 10MB for PDF
('application/msword', 15728640, true, true, true), -- 15MB for DOC
('application/zip', 20971520, false, true, true);  -- 20MB for ZIP, blocked by default

-- Sample firewall rules
INSERT INTO firewall_rules (rule_name, rule_type, protocol, port_range, description, priority) VALUES
('HTTP Access', 'allow', 'tcp', '80', 'Allow HTTP traffic', 100),
('HTTPS Access', 'allow', 'tcp', '443', 'Allow HTTPS traffic', 90),
('Block Telnet', 'deny', 'tcp', '23', 'Block Telnet access', 50),
('MySQL Access', 'allow', 'tcp', '3306', 'Allow MySQL connections', 80);

-- Insert sample policy requirements
INSERT INTO policy_requirements (policy_id, requirement_type, description, weight) VALUES
(1, 'password_policy', 'Minimum password length of 8 characters', 1.00),
(1, 'password_policy', 'Must include uppercase and lowercase letters', 0.75),
(1, 'password_policy', 'Must include numbers', 0.75),
(1, 'password_policy', 'Must include special characters', 0.50),
(2, 'access_control', 'Role-based access control implementation', 1.00),
(2, 'access_control', 'Regular access reviews', 0.75),
(2, 'access_control', 'Immediate access revocation process', 0.75),
(3, 'data_protection', 'Data encryption at rest', 1.00),
(3, 'data_protection', 'Secure backup procedures', 0.75),
(3, 'data_protection', 'Data retention policies', 0.75);

-- Insert sample audit schedules
INSERT INTO audit_schedules (policy_id, frequency, next_audit_date, status, assigned_to) 
SELECT 
    p.id,
    'monthly',
    DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 30 DAY),
    'scheduled',
    (SELECT id FROM users WHERE role = 'admin' LIMIT 1)
FROM security_policies p
WHERE p.status = 'active';

-- Create stored procedures for policy management

DELIMITER //

-- Procedure to add a new policy
CREATE PROCEDURE add_security_policy(
    IN p_name VARCHAR(100),
    IN p_description TEXT,
    IN p_category VARCHAR(20),
    IN p_requirements TEXT,
    IN p_implementation TEXT,
    IN p_created_by INT
)
BEGIN
    INSERT INTO security_policies (
        policy_name, 
        description, 
        category, 
        requirements, 
        implementation_details, 
        created_by
    ) VALUES (
        p_name,
        p_description,
        p_category,
        p_requirements,
        p_implementation,
        p_created_by
    );
END //

-- Procedure to update an existing policy
CREATE PROCEDURE update_security_policy(
    IN p_id INT,
    IN p_name VARCHAR(100),
    IN p_description TEXT,
    IN p_category VARCHAR(20),
    IN p_status VARCHAR(10),
    IN p_requirements TEXT,
    IN p_implementation TEXT,
    IN p_updated_by INT
)
BEGIN
    -- First, create a revision record
    INSERT INTO policy_revisions (
        policy_id,
        revision_number,
        changes_made,
        previous_content,
        revised_by
    )
    SELECT 
        id,
        (SELECT COUNT(*) FROM policy_revisions WHERE policy_id = p_id) + 1,
        CONCAT('Updated by user ', p_updated_by),
        CONCAT(
            'Name: ', policy_name, '\n',
            'Description: ', description, '\n',
            'Category: ', category, '\n',
            'Status: ', status, '\n',
            'Requirements: ', requirements, '\n',
            'Implementation: ', implementation_details
        ),
        p_updated_by
    FROM security_policies
    WHERE id = p_id;

    -- Then update the policy
    UPDATE security_policies SET
        policy_name = p_name,
        description = p_description,
        category = p_category,
        status = p_status,
        requirements = p_requirements,
        implementation_details = p_implementation,
        updated_by = p_updated_by
    WHERE id = p_id;
END //

-- Procedure to delete a policy
CREATE PROCEDURE delete_security_policy(
    IN p_id INT,
    IN p_user_id INT
)
BEGIN
    -- Archive the policy in revisions before deletion
    INSERT INTO policy_revisions (
        policy_id,
        revision_number,
        changes_made,
        previous_content,
        revised_by
    )
    SELECT 
        id,
        -1, -- Use -1 to indicate deletion
        CONCAT('Deleted by user ', p_user_id),
        CONCAT(
            'Name: ', policy_name, '\n',
            'Description: ', description, '\n',
            'Category: ', category, '\n',
            'Status: ', status, '\n',
            'Requirements: ', requirements, '\n',
            'Implementation: ', implementation_details
        ),
        p_user_id
    FROM security_policies
    WHERE id = p_id;

    -- Delete the policy
    DELETE FROM security_policies WHERE id = p_id;
END //

DELIMITER ;

-- Password History Table
CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    old_password_hash TEXT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Error Logs Table
CREATE TABLE IF NOT EXISTS error_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'default',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_action (ip_address, action)
); 
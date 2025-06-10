-- Add description column to security_policies if it doesn't exist
ALTER TABLE security_policies
ADD COLUMN IF NOT EXISTS description TEXT;

-- First, let's create the policy_requirements table if it doesn't exist
CREATE TABLE IF NOT EXISTS policy_requirements (
    id INT PRIMARY KEY AUTO_INCREMENT,
    policy_id INT NOT NULL,
    requirement TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id)
);

-- Update Password Policy details
UPDATE security_policies 
SET description = 'Establishes strong password requirements to enhance system security and prevent unauthorized access. This policy ensures that all user passwords meet minimum security standards.'
WHERE policy_name = 'Password Policy';

-- Add Password Policy requirements
INSERT INTO policy_requirements (policy_id, requirement) 
SELECT id, requirement FROM (
    SELECT id,
    'Minimum 8 characters length' as requirement FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Must include at least one uppercase letter' FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Must include at least one lowercase letter' FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Must include at least one number' FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Must include at least one special character' FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Password must be changed every 90 days' FROM security_policies WHERE policy_name = 'Password Policy'
    UNION ALL
    SELECT id, 'Cannot reuse the last 5 passwords' FROM security_policies WHERE policy_name = 'Password Policy'
) AS temp;

-- Update Access Control Policy details
UPDATE security_policies 
SET description = 'Defines access control mechanisms and permissions to protect system resources and ensure appropriate user access levels.'
WHERE policy_name = 'Access Control Policy';

-- Add Access Control Policy requirements
INSERT INTO policy_requirements (policy_id, requirement)
SELECT id, requirement FROM (
    SELECT id, 'Implementation of Role-Based Access Control (RBAC)' FROM security_policies WHERE policy_name = 'Access Control Policy'
    UNION ALL
    SELECT id, 'Regular access rights review every 90 days' FROM security_policies WHERE policy_name = 'Access Control Policy'
    UNION ALL
    SELECT id, 'Immediate revocation of access rights upon employee termination' FROM security_policies WHERE policy_name = 'Access Control Policy'
    UNION ALL
    SELECT id, 'Two-factor authentication for sensitive operations' FROM security_policies WHERE policy_name = 'Access Control Policy'
    UNION ALL
    SELECT id, 'Logging of all access attempts (successful and failed)' FROM security_policies WHERE policy_name = 'Access Control Policy'
) AS temp;

-- Update Data Protection Policy details
UPDATE security_policies 
SET description = 'Ensures the confidentiality, integrity, and availability of sensitive data through proper handling, storage, and transmission procedures.'
WHERE policy_name = 'Data Protection Policy';

-- Add Data Protection Policy requirements
INSERT INTO policy_requirements (policy_id, requirement)
SELECT id, requirement FROM (
    SELECT id, 'All sensitive data must be encrypted at rest' FROM security_policies WHERE policy_name = 'Data Protection Policy'
    UNION ALL
    SELECT id, 'Use of secure protocols (HTTPS, SFTP, etc.) for data transmission' FROM security_policies WHERE policy_name = 'Data Protection Policy'
    UNION ALL
    SELECT id, 'Regular backup of critical data' FROM security_policies WHERE policy_name = 'Data Protection Policy'
    UNION ALL
    SELECT id, 'Data classification and handling procedures' FROM security_policies WHERE policy_name = 'Data Protection Policy'
    UNION ALL
    SELECT id, 'Secure data disposal procedures' FROM security_policies WHERE policy_name = 'Data Protection Policy'
) AS temp;

-- Update Incident Response Policy details
UPDATE security_policies 
SET description = 'Provides a structured approach to handling and responding to security incidents, ensuring quick and effective resolution while minimizing impact.'
WHERE policy_name = 'Incident Response Policy';

-- Add Incident Response Policy requirements
INSERT INTO policy_requirements (policy_id, requirement)
SELECT id, requirement FROM (
    SELECT id, 'Immediate reporting of security incidents' FROM security_policies WHERE policy_name = 'Incident Response Policy'
    UNION ALL
    SELECT id, 'Establishment of incident response team' FROM security_policies WHERE policy_name = 'Incident Response Policy'
    UNION ALL
    SELECT id, 'Regular incident response training' FROM security_policies WHERE policy_name = 'Incident Response Policy'
    UNION ALL
    SELECT id, 'Documentation of all security incidents' FROM security_policies WHERE policy_name = 'Incident Response Policy'
    UNION ALL
    SELECT id, 'Post-incident analysis and lessons learned' FROM security_policies WHERE policy_name = 'Incident Response Policy'
) AS temp; 
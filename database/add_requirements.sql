-- Add requirements for Incident Response Policy
INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'access_control', 'Incident response team access controls', 2.0
FROM security_policies WHERE policy_name = 'Incident Response Policy';

INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'network_security', 'Incident monitoring and detection systems', 3.0
FROM security_policies WHERE policy_name = 'Incident Response Policy';

INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'data_protection', 'Incident documentation and reporting', 2.0
FROM security_policies WHERE policy_name = 'Incident Response Policy';

-- Add missing requirements for Data Protection Policy
INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'data_protection', 'Data encryption at rest', 3.0
FROM security_policies WHERE policy_name = 'Data Protection Policy';

INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'network_security', 'Secure data transmission protocols', 2.0
FROM security_policies WHERE policy_name = 'Data Protection Policy';

-- Add missing requirements for Access Control Policy
INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'access_control', 'Role-based access control implementation', 3.0
FROM security_policies WHERE policy_name = 'Access Control Policy';

INSERT INTO policy_requirements (policy_id, requirement_type, description, weight)
SELECT id, 'access_control', 'Regular access reviews', 2.0
FROM security_policies WHERE policy_name = 'Access Control Policy'; 
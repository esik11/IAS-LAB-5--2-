<?php
require_once 'Database.php';
require_once 'Security.php';
require_once 'NetworkSecurity.php';
require_once 'Encryption.php';

class SecurityAudit {
    private $db;
    private $security;
    private $networkSecurity;
    private $encryption;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->security = new Security();
        $this->networkSecurity = new NetworkSecurity();
        $this->encryption = new Encryption();
    }
    
    public function runVulnerabilityScan() {
        $vulnerabilities = [];
        
        // Check file permissions
        $this->scanFilePermissions($vulnerabilities);
        
        // Check database security
        $this->scanDatabaseSecurity($vulnerabilities);
        
        // Check network security
        $this->scanNetworkSecurity($vulnerabilities);
        
        // Check password policies
        $this->scanPasswordPolicies($vulnerabilities);
        
        // Log vulnerabilities
        foreach ($vulnerabilities as $vuln) {
            $this->db->query(
                "INSERT INTO security_incidents (
                    title, description, severity, status, reported_by
                ) VALUES (?, ?, ?, 'open', 1)",
                [
                    $vuln['title'],
                    $vuln['description'],
                    $vuln['severity']
                ]
            );
        }
        
        return $vulnerabilities;
    }
    
    private function scanFilePermissions(&$vulnerabilities) {
        $criticalFiles = [
            'config/config.php',
            'config/encryption.key',
            'includes/Database.php',
            'includes/Security.php'
        ];
        
        foreach ($criticalFiles as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file);
                if (($perms & 0x0004) || ($perms & 0x0002)) { // World readable or writable
                    $vulnerabilities[] = [
                        'title' => 'Insecure File Permissions',
                        'description' => "File $file has insecure permissions: " . substr(sprintf('%o', $perms), -4),
                        'severity' => 'high'
                    ];
                }
            }
        }
    }
    
    private function scanDatabaseSecurity(&$vulnerabilities) {
        // Check for unencrypted sensitive data
        $tables = ['users', 'security_policies', 'security_incidents'];
        
        foreach ($tables as $table) {
            $columns = $this->db->query("SHOW COLUMNS FROM $table")->fetchAll(PDO::FETCH_COLUMN);
            
            foreach ($columns as $column) {
                if ($this->isSensitiveColumn($column)) {
                    $unencrypted = $this->db->query(
                        "SELECT COUNT(*) FROM $table 
                         WHERE $column IS NOT NULL 
                         AND $column NOT LIKE 'enc:%'"
                    )->fetchColumn();
                    
                    if ($unencrypted > 0) {
                        $vulnerabilities[] = [
                            'title' => 'Unencrypted Sensitive Data',
                            'description' => "Found $unencrypted unencrypted values in $table.$column",
                            'severity' => 'high'
                        ];
                    }
                }
            }
        }
    }
    
    private function scanNetworkSecurity(&$vulnerabilities) {
        // Check firewall rules
        $rules = $this->db->query("SELECT * FROM firewall_rules")->fetchAll(PDO::FETCH_ASSOC);
        if (count($rules) < 2) { // At minimum, we should have allow localhost and deny all
            $vulnerabilities[] = [
                'title' => 'Insufficient Firewall Rules',
                'description' => 'The system has too few firewall rules configured',
                'severity' => 'medium'
            ];
        }
        
        // Check for suspicious traffic patterns
        $traffic = $this->networkSecurity->monitorTraffic();
        foreach ($traffic as $entry) {
            if ($entry['requests'] > 1000) { // Potential DoS
                $vulnerabilities[] = [
                    'title' => 'Potential DoS Attack',
                    'description' => "High traffic volume from {$entry['ip_address']}: {$entry['requests']} requests/hour",
                    'severity' => 'critical'
                ];
            }
        }
    }
    
    private function scanPasswordPolicies(&$vulnerabilities) {
        // Check for weak passwords
        $weakPasswords = $this->db->query(
            "SELECT username FROM users 
             WHERE LENGTH(password) < 12 
             OR password NOT REGEXP '[0-9]' 
             OR password NOT REGEXP '[A-Z]' 
             OR password NOT REGEXP '[a-z]' 
             OR password NOT REGEXP '[^A-Za-z0-9]'"
        )->fetchAll(PDO::FETCH_COLUMN);
        
        if (!empty($weakPasswords)) {
            $vulnerabilities[] = [
                'title' => 'Weak Passwords Detected',
                'description' => 'The following users have weak passwords: ' . implode(', ', $weakPasswords),
                'severity' => 'high'
            ];
        }
    }
    
    private function isSensitiveColumn($column) {
        $sensitiveColumns = [
            'password', 'email', 'phone', 'address',
            'credit_card', 'ssn', 'description'
        ];
        return in_array(strtolower($column), $sensitiveColumns);
    }
    
    public function generateSecurityMetrics() {
        $metrics = [
            'total_incidents' => $this->db->query(
                "SELECT COUNT(*) FROM security_incidents"
            )->fetchColumn(),
            
            'open_incidents' => $this->db->query(
                "SELECT COUNT(*) FROM security_incidents WHERE status = 'open'"
            )->fetchColumn(),
            
            'critical_incidents' => $this->db->query(
                "SELECT COUNT(*) FROM security_incidents WHERE severity = 'critical'"
            )->fetchColumn(),
            
            'policy_compliance' => $this->calculatePolicyCompliance(),
            
            'failed_logins' => $this->db->query(
                "SELECT COUNT(*) FROM security_logs 
                 WHERE action = 'login_failed' 
                 AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
            )->fetchColumn(),
            
            'encryption_coverage' => $this->calculateEncryptionCoverage()
        ];
        
        return $metrics;
    }
    
    private function calculatePolicyCompliance() {
        $totalPolicies = $this->db->query(
            "SELECT COUNT(*) FROM security_policies"
        )->fetchColumn();
        
        $compliantPolicies = $this->db->query(
            "SELECT COUNT(*) FROM security_policies 
             WHERE last_audit_date IS NOT NULL 
             AND last_audit_result = 'pass'"
        )->fetchColumn();
        
        return $totalPolicies > 0 ? ($compliantPolicies / $totalPolicies) * 100 : 0;
    }
    
    private function calculateEncryptionCoverage() {
        $tables = ['users', 'security_policies', 'security_incidents'];
        $totalSensitive = 0;
        $encrypted = 0;
        
        foreach ($tables as $table) {
            $columns = $this->db->query("SHOW COLUMNS FROM $table")->fetchAll(PDO::FETCH_COLUMN);
            
            foreach ($columns as $column) {
                if ($this->isSensitiveColumn($column)) {
                    $result = $this->db->query(
                        "SELECT 
                            COUNT(*) as total,
                            SUM(CASE WHEN $column LIKE 'enc:%' THEN 1 ELSE 0 END) as encrypted
                         FROM $table 
                         WHERE $column IS NOT NULL"
                    )->fetch(PDO::FETCH_ASSOC);
                    
                    $totalSensitive += $result['total'];
                    $encrypted += $result['encrypted'];
                }
            }
        }
        
        return $totalSensitive > 0 ? ($encrypted / $totalSensitive) * 100 : 0;
    }

    public function runComplianceAssessment() {
        $violations = [];
        
        // Check database encryption
        if (!$this->encryption->isDatabaseEncrypted()) {
            $violations[] = [
                'title' => 'Encryption not enforced on database',
                'description' => 'Database encryption is not properly configured or enforced',
                'severity' => 'high',
                'framework_id' => $this->getFrameworkId('GDPR')
            ];
        }

        // Check access logs retention
        if (!$this->checkAccessLogsRetention()) {
            $violations[] = [
                'title' => 'Access logs retention period non-compliant',
                'description' => 'Access logs are not being retained for the required period',
                'severity' => 'medium',
                'framework_id' => $this->getFrameworkId('HIPAA')
            ];
        }

        // Check MFA implementation
        if (!$this->security->isMFAEnabled()) {
            $violations[] = [
                'title' => 'Multi-factor authentication not implemented',
                'description' => 'System lacks multi-factor authentication for user access',
                'severity' => 'high',
                'framework_id' => $this->getFrameworkId('ISO 27001')
            ];
        }

        // Store violations
        foreach ($violations as $violation) {
            $this->db->query(
                "INSERT INTO compliance_violations (title, description, severity, framework_id) 
                 VALUES (?, ?, ?, ?)",
                [$violation['title'], $violation['description'], $violation['severity'], $violation['framework_id']]
            );
        }

        // Calculate and store compliance score
        $score = $this->calculateComplianceScore($violations);
        $this->db->query(
            "INSERT INTO compliance_audits (title, compliance_score, completed_by) 
             VALUES (?, ?, ?)",
            ['Automated Compliance Check - ' . date('Y-m-d H:i:s'), $score, $_SESSION['user_id'] ?? null]
        );

        return [
            'score' => $score,
            'violations' => $violations
        ];
    }

    public function calculateOverallComplianceScore() {
        $total_checks = 3; // Total number of compliance checks
        $failed_checks = $this->db->query(
            "SELECT COUNT(*) FROM compliance_violations WHERE status = 'open'"
        )->fetchColumn();

        return round(100 * (($total_checks - $failed_checks) / $total_checks));
    }

    private function calculateComplianceScore($violations) {
        $total_checks = 3; // Total number of compliance checks
        $failed_checks = count($violations);
        return round(100 * (($total_checks - $failed_checks) / $total_checks), 2);
    }

    private function getFrameworkId($framework_name) {
        return $this->db->query(
            "SELECT id FROM compliance_frameworks WHERE name = ?",
            [$framework_name]
        )->fetchColumn();
    }

    private function checkAccessLogsRetention() {
        // Check if access logs are being retained for required period (e.g., 6 years for HIPAA)
        $oldest_log = $this->db->query(
            "SELECT MIN(created_at) FROM security_logs"
        )->fetchColumn();

        if (!$oldest_log) {
            return false;
        }

        $retention_period = strtotime('-6 years');
        return strtotime($oldest_log) <= $retention_period;
    }

    public function checkWeakPasswords() {
        // Check for users with weak passwords based on policy requirements
        $minLength = defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8;
        $requireMixed = defined('PASSWORD_REQUIRE_MIXED') ? PASSWORD_REQUIRE_MIXED : true;
        $requireNumbers = defined('PASSWORD_REQUIRE_NUMBERS') ? PASSWORD_REQUIRE_NUMBERS : true;
        $requireSymbols = defined('PASSWORD_REQUIRE_SYMBOLS') ? PASSWORD_REQUIRE_SYMBOLS : true;

        $weakPasswords = $this->db->query(
            "SELECT COUNT(*) FROM users WHERE 
            LENGTH(password) < ? OR
            (? = true AND password NOT REGEXP '[A-Z].*[a-z]|[a-z].*[A-Z]') OR
            (? = true AND password NOT REGEXP '[0-9]') OR
            (? = true AND password NOT REGEXP '[!@#$%^&*(),.?\":{}|<>]')",
            [$minLength, $requireMixed, $requireNumbers, $requireSymbols]
        )->fetchColumn();

        return $weakPasswords;
    }

    public function getRecentIncidents($days) {
        // Get count of security incidents in the last X days
        return $this->db->query(
            "SELECT COUNT(*) FROM security_incidents 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$days]
        )->fetchColumn();
    }

    public function getFailedLoginAttempts($hours) {
        // Get count of failed login attempts in the last X hours
        return $this->db->query(
            "SELECT COUNT(*) FROM security_logs 
             WHERE action = 'login_failed' 
             AND created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)",
            [$hours]
        )->fetchColumn();
    }

    public function generatePDFReport() {
        // Get all audit data
        $data = [
            'weak_passwords' => $this->checkWeakPasswords(),
            'recent_incidents' => $this->getRecentIncidents(30),
            'failed_logins' => $this->getFailedLoginAttempts(24),
            'overall_score' => $this->calculateOverallComplianceScore(),
            'generated_date' => date('Y-m-d H:i:s'),
            'generated_by' => $_SESSION['username'] ?? 'System'
        ];

        // Get detailed policy compliance
        $policies = $this->db->query(
            "SELECT p.*, 
                    COALESCE(pc.compliance_status, 'non_compliant') as status,
                    pc.notes,
                    pc.assessment_date
             FROM security_policies p
             LEFT JOIN policy_compliance pc ON p.id = pc.policy_id
             ORDER BY p.category, p.policy_name"
        )->fetchAll(PDO::FETCH_ASSOC);

        // Get recent security incidents
        $incidents = $this->db->query(
            "SELECT * FROM security_incidents 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
             ORDER BY severity DESC, created_at DESC"
        )->fetchAll(PDO::FETCH_ASSOC);

        // Include Composer's autoloader
        require_once __DIR__ . '/../vendor/autoload.php';

        // Create new PDF document
        $pdf = new \TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

        // Set document information
        $pdf->SetCreator('Security System');
        $pdf->SetAuthor($data['generated_by']);
        $pdf->SetTitle('Security Audit Report - ' . date('Y-m-d'));

        // Remove default header/footer
        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);

        // Set margins
        $pdf->SetMargins(15, 15, 15);

        // Set auto page breaks
        $pdf->SetAutoPageBreak(TRUE, 25);

        // Add a page
        $pdf->AddPage();

        // Set font
        $pdf->SetFont('helvetica', 'B', 20);

        // Title
        $pdf->Cell(0, 10, 'Security Audit Report', 0, 1, 'C');
        $pdf->Ln(10);

        // Executive Summary
        $pdf->SetFont('helvetica', 'B', 16);
        $pdf->Cell(0, 10, 'Executive Summary', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        $pdf->MultiCell(0, 10, 'This report provides a comprehensive overview of the system\'s security status and compliance with established policies. Overall compliance score: ' . $data['overall_score'] . '%', 0, 'L');
        $pdf->Ln(5);

        // Key Findings
        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->Cell(0, 10, 'Key Findings', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);

        // Password Policy
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(0, 10, 'Password Policy:', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        $pdf->MultiCell(0, 10, $data['weak_passwords'] . ' users have weak passwords', 0, 'L');

        // Security Incidents
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(0, 10, 'Security Incidents:', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        $pdf->MultiCell(0, 10, $data['recent_incidents'] . ' security incidents in last 30 days', 0, 'L');

        // Login Attempts
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(0, 10, 'Login Attempts:', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        $pdf->MultiCell(0, 10, $data['failed_logins'] . ' failed login attempts in last 24 hours', 0, 'L');
        $pdf->Ln(5);

        // Detailed Policy Compliance
        $pdf->AddPage();
        $pdf->SetFont('helvetica', 'B', 16);
        $pdf->Cell(0, 10, 'Detailed Policy Compliance', 0, 1, 'L');
        $pdf->Ln(5);

        foreach ($policies as $policy) {
            $pdf->SetFont('helvetica', 'B', 12);
            $pdf->Cell(0, 10, $policy['policy_name'], 0, 1, 'L');
            $pdf->SetFont('helvetica', '', 11);
            $pdf->MultiCell(0, 10, 'Category: ' . $policy['category'] . "\nStatus: " . $policy['status'] . "\nLast Assessment: " . $policy['assessment_date'], 0, 'L');
            $pdf->Ln(5);
        }

        // Security Incidents Details
        if (count($incidents) > 0) {
            $pdf->AddPage();
            $pdf->SetFont('helvetica', 'B', 16);
            $pdf->Cell(0, 10, 'Recent Security Incidents', 0, 1, 'L');
            $pdf->Ln(5);

            foreach ($incidents as $incident) {
                $pdf->SetFont('helvetica', 'B', 12);
                $pdf->Cell(0, 10, $incident['title'], 0, 1, 'L');
                $pdf->SetFont('helvetica', '', 11);
                $pdf->MultiCell(0, 10, 'Severity: ' . $incident['severity'] . "\nStatus: " . $incident['status'] . "\nDate: " . $incident['created_at'] . "\nDescription: " . $incident['description'], 0, 'L');
                $pdf->Ln(5);
            }
        }

        // Recommendations
        $pdf->AddPage();
        $pdf->SetFont('helvetica', 'B', 16);
        $pdf->Cell(0, 10, 'Recommendations', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);

        if ($data['weak_passwords'] > 0) {
            $pdf->MultiCell(0, 10, '• Enforce password policy and require users with weak passwords to update them', 0, 'L');
        }
        if ($data['recent_incidents'] > 0) {
            $pdf->MultiCell(0, 10, '• Review and address all security incidents', 0, 'L');
        }
        if ($data['failed_logins'] > 0) {
            $pdf->MultiCell(0, 10, '• Investigate failed login attempts and consider implementing additional access controls', 0, 'L');
        }

        return $pdf->Output('Security_Audit_Report.pdf', 'S');
    }

    public function generateSecurityIncidentsPDF() {
        // Get security incidents from the last 30 days
        $incidents = $this->db->query(
            "SELECT * FROM security_incidents 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
             ORDER BY severity DESC, created_at DESC"
        )->fetchAll(PDO::FETCH_ASSOC);

        // Include Composer's autoloader
        require_once __DIR__ . '/../vendor/autoload.php';

        // Create new PDF document
        $pdf = new \TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

        // Set document information
        $pdf->SetCreator('Security System');
        $pdf->SetAuthor($_SESSION['username'] ?? 'System');
        $pdf->SetTitle('Security Incidents Report - ' . date('Y-m-d'));

        // Remove default header/footer
        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);

        // Set margins
        $pdf->SetMargins(15, 15, 15);

        // Set auto page breaks
        $pdf->SetAutoPageBreak(TRUE, 25);

        // Add a page
        $pdf->AddPage();

        // Set font
        $pdf->SetFont('helvetica', 'B', 20);

        // Title
        $pdf->Cell(0, 10, 'Security Incidents Report', 0, 1, 'C');
        $pdf->Ln(10);

        // Summary
        $pdf->SetFont('helvetica', 'B', 16);
        $pdf->Cell(0, 10, 'Summary', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        $pdf->MultiCell(0, 10, 'Total Incidents in Last 30 Days: ' . count($incidents), 0, 'L');
        $pdf->Ln(5);

        // Incidents by Severity
        $severityCounts = array_count_values(array_column($incidents, 'severity'));
        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->Cell(0, 10, 'Incidents by Severity:', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 11);
        foreach ($severityCounts as $severity => $count) {
            $pdf->MultiCell(0, 10, ucfirst($severity) . ': ' . $count, 0, 'L');
        }
        $pdf->Ln(5);

        // Detailed Incidents List
        $pdf->SetFont('helvetica', 'B', 16);
        $pdf->Cell(0, 10, 'Detailed Incidents List', 0, 1, 'L');
        $pdf->Ln(5);

        foreach ($incidents as $incident) {
            $pdf->SetFont('helvetica', 'B', 12);
            $pdf->Cell(0, 10, $incident['title'], 0, 1, 'L');
            $pdf->SetFont('helvetica', '', 11);
            
            // Format the incident details
            $details = sprintf(
                "Severity: %s\nStatus: %s\nDate: %s\nDescription: %s\nResolution: %s",
                $incident['severity'],
                $incident['status'],
                $incident['created_at'],
                $incident['description'],
                $incident['resolution'] ?? 'Pending'
            );
            
            $pdf->MultiCell(0, 10, $details, 0, 'L');
            $pdf->Ln(5);
        }

        // Recommendations
        if (count($incidents) > 0) {
            $pdf->AddPage();
            $pdf->SetFont('helvetica', 'B', 16);
            $pdf->Cell(0, 10, 'Recommendations', 0, 1, 'L');
            $pdf->SetFont('helvetica', '', 11);
            
            $highSeverity = isset($severityCounts['high']) && $severityCounts['high'] > 0;
            $mediumSeverity = isset($severityCounts['medium']) && $severityCounts['medium'] > 0;
            
            if ($highSeverity) {
                $pdf->MultiCell(0, 10, '• Immediate attention required for high severity incidents', 0, 'L');
            }
            if ($mediumSeverity) {
                $pdf->MultiCell(0, 10, '• Schedule resolution for medium severity incidents within next 48 hours', 0, 'L');
            }
            $pdf->MultiCell(0, 10, '• Review security measures and update incident response procedures if needed', 0, 'L');
            $pdf->MultiCell(0, 10, '• Consider additional staff training if similar incidents are recurring', 0, 'L');
        }

        return $pdf->Output('Security_Incidents_Report.pdf', 'S');
    }

    public function generateSingleIncidentPDF($incident_id) {
        // Get the specific incident
        $incident = $this->db->query(
            "SELECT i.*, u.username 
             FROM security_incidents i 
             LEFT JOIN users u ON i.reported_by = u.id 
             WHERE i.id = ?",
            [$incident_id]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$incident) {
            return false;
        }

        // Include Composer's autoloader
        require_once __DIR__ . '/../vendor/autoload.php';

        // Create new PDF document
        $pdf = new \TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

        // Set document information
        $pdf->SetCreator('Security System');
        $pdf->SetAuthor($_SESSION['username'] ?? 'System');
        $pdf->SetTitle('Security Incident Report - ' . $incident['title']);

        // Remove default header/footer
        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);

        // Set margins
        $pdf->SetMargins(15, 15, 15);

        // Set auto page breaks
        $pdf->SetAutoPageBreak(TRUE, 25);

        // Add a page
        $pdf->AddPage();

        // Set font
        $pdf->SetFont('helvetica', 'B', 20);

        // Title
        $pdf->Cell(0, 10, 'Security Incident Report', 0, 1, 'C');
        $pdf->Ln(10);

        // Incident Details
        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->Cell(0, 10, 'Incident Details', 0, 1, 'L');
        $pdf->Ln(5);

        // Format incident information
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(40, 10, 'Title:', 0);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->Cell(0, 10, $incident['title'], 0, 1);

        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(40, 10, 'Severity:', 0);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->Cell(0, 10, ucfirst($incident['severity']), 0, 1);

        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(40, 10, 'Status:', 0);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->Cell(0, 10, ucfirst($incident['status']), 0, 1);

        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(40, 10, 'Reported By:', 0);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->Cell(0, 10, $incident['username'], 0, 1);

        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(40, 10, 'Date:', 0);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->Cell(0, 10, $incident['created_at'], 0, 1);

        $pdf->Ln(5);

        // Description
        $pdf->SetFont('helvetica', 'B', 12);
        $pdf->Cell(0, 10, 'Description:', 0, 1);
        $pdf->SetFont('helvetica', '', 12);
        $pdf->MultiCell(0, 10, $incident['description'], 0, 'L');

        // If there's a resolution
        if (!empty($incident['resolution'])) {
            $pdf->Ln(5);
            $pdf->SetFont('helvetica', 'B', 12);
            $pdf->Cell(0, 10, 'Resolution:', 0, 1);
            $pdf->SetFont('helvetica', '', 12);
            $pdf->MultiCell(0, 10, $incident['resolution'], 0, 'L');
        }

        // Recommendations based on severity
        $pdf->AddPage();
        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->Cell(0, 10, 'Recommendations', 0, 1, 'L');
        $pdf->SetFont('helvetica', '', 12);

        switch ($incident['severity']) {
            case 'critical':
                $pdf->MultiCell(0, 10, "• Immediate action required\n• Escalate to senior management\n• Consider system shutdown if necessary\n• Implement emergency response procedures", 0, 'L');
                break;
            case 'high':
                $pdf->MultiCell(0, 10, "• Address within 24 hours\n• Notify relevant stakeholders\n• Implement temporary security measures\n• Schedule immediate review", 0, 'L');
                break;
            case 'medium':
                $pdf->MultiCell(0, 10, "• Address within 72 hours\n• Monitor for escalation\n• Review security controls\n• Update security procedures", 0, 'L');
                break;
            case 'low':
                $pdf->MultiCell(0, 10, "• Address within 1 week\n• Document findings\n• Update security awareness training\n• Review similar incidents", 0, 'L');
                break;
        }

        return $pdf->Output('Security_Incident_Report_' . $incident_id . '.pdf', 'S');
    }

    public function runDetailedComplianceAudit() {
        $results = [
            'password_policy' => $this->auditPasswordPolicy(),
            'access_control' => $this->auditAccessControl(),
            'data_protection' => $this->auditDataProtection(),
            'incident_response' => $this->auditIncidentResponse(),
            'logging_monitoring' => $this->auditLoggingMonitoring()
        ];

        // Calculate overall score
        $totalScore = 0;
        $categories = 0;
        foreach ($results as $category) {
            $totalScore += $category['score'];
            $categories++;
        }

        $overallScore = $categories > 0 ? round($totalScore / $categories, 2) : 0;

        // Store audit results
        $audit_id = $this->db->query(
            "INSERT INTO compliance_audits (title, compliance_score, completed_by, report_data) 
             VALUES (?, ?, ?, ?)",
            [
                'Detailed Compliance Audit - ' . date('Y-m-d'),
                $overallScore,
                $_SESSION['user_id'],
                json_encode($results)
            ]
        );

        return [
            'overall_score' => $overallScore,
            'categories' => $results,
            'audit_id' => $audit_id
        ];
    }

    private function auditPasswordPolicy() {
        $issues = [];
        $score = 100;

        // Check weak passwords
        $weak_passwords = $this->db->query(
            "SELECT COUNT(*) FROM users WHERE LENGTH(password) < ?",
            [PASSWORD_MIN_LENGTH]
        )->fetchColumn();
        
        if ($weak_passwords > 0) {
            $issues[] = "Found $weak_passwords users with weak passwords";
            $score -= ($weak_passwords * 10);
        }

        // Check password age
        $old_passwords = $this->db->query(
            "SELECT COUNT(*) FROM users WHERE updated_at < DATE_SUB(NOW(), INTERVAL 90 DAY)"
        )->fetchColumn();
        
        if ($old_passwords > 0) {
            $issues[] = "$old_passwords users have passwords older than 90 days";
            $score -= ($old_passwords * 5);
        }

        return [
            'category' => 'Password Policy',
            'score' => max(0, $score),
            'issues' => $issues,
            'recommendations' => $this->getPasswordPolicyRecommendations($issues)
        ];
    }

    private function auditAccessControl() {
        $issues = [];
        $score = 100;

        // Check admin accounts
        $admin_count = $this->db->query(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        )->fetchColumn();
        
        if ($admin_count > 3) {
            $issues[] = "High number of admin accounts ($admin_count)";
            $score -= (($admin_count - 3) * 15);
        }

        // Check inactive but enabled accounts
        $inactive_accounts = $this->db->query(
            "SELECT COUNT(*) FROM users 
             WHERE last_login < DATE_SUB(NOW(), INTERVAL 30 DAY) 
             AND is_locked = 0"
        )->fetchColumn();
        
        if ($inactive_accounts > 0) {
            $issues[] = "$inactive_accounts inactive accounts still enabled";
            $score -= ($inactive_accounts * 5);
        }

        return [
            'category' => 'Access Control',
            'score' => max(0, $score),
            'issues' => $issues,
            'recommendations' => $this->getAccessControlRecommendations($issues)
        ];
    }

    private function auditDataProtection() {
        $issues = [];
        $score = 100;

        // Check encryption implementation
        if (!$this->encryption->isEncryptionEnabled()) {
            $issues[] = "Data encryption is not enabled";
            $score -= 40;
        }

        // Check sensitive data handling
        $unencrypted_data = $this->db->query(
            "SELECT COUNT(*) FROM security_incidents 
             WHERE description NOT LIKE 'enc:%'"
        )->fetchColumn();
        
        if ($unencrypted_data > 0) {
            $issues[] = "$unencrypted_data incidents contain unencrypted sensitive data";
            $score -= min(40, $unencrypted_data * 2);
        }

        return [
            'category' => 'Data Protection',
            'score' => max(0, $score),
            'issues' => $issues,
            'recommendations' => $this->getDataProtectionRecommendations($issues)
        ];
    }

    private function auditIncidentResponse() {
        $issues = [];
        $score = 100;

        // Check unresolved critical incidents
        $critical_unresolved = $this->db->query(
            "SELECT COUNT(*) FROM security_incidents 
             WHERE severity = 'critical' 
             AND status != 'resolved'"
        )->fetchColumn();
        
        if ($critical_unresolved > 0) {
            $issues[] = "$critical_unresolved unresolved critical incidents";
            $score -= ($critical_unresolved * 20);
        }

        // Check incident response time
        $slow_response = $this->db->query(
            "SELECT COUNT(*) FROM security_incidents 
             WHERE severity IN ('high', 'critical') 
             AND created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
             AND status = 'open'"
        )->fetchColumn();
        
        if ($slow_response > 0) {
            $issues[] = "$slow_response high/critical incidents without response for >24h";
            $score -= ($slow_response * 15);
        }

        return [
            'category' => 'Incident Response',
            'score' => max(0, $score),
            'issues' => $issues,
            'recommendations' => $this->getIncidentResponseRecommendations($issues)
        ];
    }

    private function auditLoggingMonitoring() {
        $issues = [];
        $score = 100;

        // Check logging coverage
        $users_without_logs = $this->db->query(
            "SELECT COUNT(*) FROM users u 
             LEFT JOIN security_logs sl ON u.id = sl.user_id 
             WHERE sl.id IS NULL"
        )->fetchColumn();
        
        if ($users_without_logs > 0) {
            $issues[] = "$users_without_logs users have no activity logs";
            $score -= ($users_without_logs * 10);
        }

        // Check failed login monitoring
        $high_failed_logins = $this->db->query(
            "SELECT COUNT(DISTINCT user_id) FROM security_logs 
             WHERE action = 'login_failed' 
             AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY user_id 
             HAVING COUNT(*) > 10"
        )->fetchColumn();
        
        if ($high_failed_logins > 0) {
            $issues[] = "$high_failed_logins users with high failed login attempts";
            $score -= ($high_failed_logins * 15);
        }

        return [
            'category' => 'Logging & Monitoring',
            'score' => max(0, $score),
            'issues' => $issues,
            'recommendations' => $this->getLoggingMonitoringRecommendations($issues)
        ];
    }

    private function getPasswordPolicyRecommendations($issues) {
        $recommendations = [];
        if (strpos(implode(' ', $issues), 'weak passwords') !== false) {
            $recommendations[] = "Enforce immediate password change for users with weak passwords";
            $recommendations[] = "Implement password strength meter on password change form";
        }
        if (strpos(implode(' ', $issues), '90 days') !== false) {
            $recommendations[] = "Set up automated password expiration notifications";
            $recommendations[] = "Implement forced password change mechanism";
        }
        return $recommendations;
    }

    private function getAccessControlRecommendations($issues) {
        $recommendations = [];
        if (strpos(implode(' ', $issues), 'admin accounts') !== false) {
            $recommendations[] = "Review and reduce number of admin accounts";
            $recommendations[] = "Implement admin action logging and review process";
        }
        if (strpos(implode(' ', $issues), 'inactive accounts') !== false) {
            $recommendations[] = "Set up automated account deactivation for inactive users";
            $recommendations[] = "Implement regular account activity reviews";
        }
        return $recommendations;
    }

    private function getDataProtectionRecommendations($issues) {
        $recommendations = [];
        if (strpos(implode(' ', $issues), 'encryption') !== false) {
            $recommendations[] = "Enable system-wide encryption for sensitive data";
            $recommendations[] = "Implement encryption key rotation policy";
        }
        if (strpos(implode(' ', $issues), 'unencrypted') !== false) {
            $recommendations[] = "Scan and encrypt all historical incident data";
            $recommendations[] = "Implement automated encryption for new incidents";
        }
        return $recommendations;
    }

    private function getIncidentResponseRecommendations($issues) {
        $recommendations = [];
        if (strpos(implode(' ', $issues), 'critical incidents') !== false) {
            $recommendations[] = "Implement escalation procedures for critical incidents";
            $recommendations[] = "Set up automated alerting for critical incident response";
        }
        if (strpos(implode(' ', $issues), 'without response') !== false) {
            $recommendations[] = "Establish incident response SLAs";
            $recommendations[] = "Implement incident response tracking system";
        }
        return $recommendations;
    }

    private function getLoggingMonitoringRecommendations($issues) {
        $recommendations = [];
        if (strpos(implode(' ', $issues), 'no activity logs') !== false) {
            $recommendations[] = "Implement comprehensive activity logging";
            $recommendations[] = "Set up log retention policies";
        }
        if (strpos(implplace(' ', $issues), 'failed login attempts') !== false) {
            $recommendations[] = "Implement automated account lockout after failed attempts";
            $recommendations[] = "Set up real-time alerts for suspicious login patterns";
        }
        return $recommendations;
    }
}

// Create tables for security auditing if they don't exist
$db = Database::getInstance();
$db->query("
    CREATE TABLE IF NOT EXISTS vulnerability_scans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        vulnerabilities_found INT,
        scan_summary TEXT,
        created_by INT,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )
"); 
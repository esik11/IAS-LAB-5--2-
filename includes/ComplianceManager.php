<?php
require_once 'Database.php';

class ComplianceManager {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    /**
     * Calculate compliance score for a specific policy
     */
    public function calculatePolicyScore($policyId) {
        // Get policy requirements and their weights
        $sql = "SELECT id, requirement_type, weight FROM policy_requirements WHERE policy_id = ?";
        $requirements = $this->db->query($sql, [$policyId])->fetchAll(PDO::FETCH_ASSOC);
        
        $totalWeight = 0;
        $weightedScore = 0;
        
        foreach ($requirements as $req) {
            $score = $this->checkRequirementCompliance($req);
            $weightedScore += $score * $req['weight'];
            $totalWeight += $req['weight'];
        }
        
        return $totalWeight > 0 ? round(($weightedScore / $totalWeight) * 100, 2) : 0;
    }
    
    /**
     * Check compliance for a specific requirement
     */
    private function checkRequirementCompliance($requirement) {
        switch ($requirement['requirement_type']) {
            case 'password_policy':
                return $this->checkPasswordPolicy($requirement);
            case 'file_security':
                return $this->checkFileSecurityCompliance($requirement);
            case 'network_security':
                return $this->checkNetworkSecurityCompliance($requirement);
            case 'access_control':
                return $this->checkAccessControlCompliance($requirement);
            case 'data_protection':
                return $this->checkDataProtectionCompliance($requirement);
            default:
                return 0;
        }
    }
    
    /**
     * Generate compliance report for a policy
     */
    public function generateComplianceReport($policyId) {
        // Get policy requirements
        $requirements = $this->db->query(
            "SELECT * FROM policy_requirements WHERE policy_id = ?",
            [$policyId]
        )->fetchAll(PDO::FETCH_ASSOC);

        $totalScore = 0;
        $totalWeight = 0;
        $findings = [];
        $recommendations = [];

        foreach ($requirements as $req) {
            $score = $this->checkRequirementCompliance($req);
            $totalScore += $score * $req['weight'];
            $totalWeight += $req['weight'];

            if ($score < 1) {
                $findings[] = "Non-compliant: " . $req['description'];
                $recommendations[] = $this->getRecommendation($req['requirement_type']);
            }
        }

        // Calculate final score
        $finalScore = $totalWeight > 0 ? ($totalScore / $totalWeight) * 100 : 0;
        $status = $this->getComplianceStatus($finalScore);

        // Record the compliance check
        $this->recordComplianceCheck($policyId, $finalScore, $status, $findings, $recommendations);

        return [
            'score' => round($finalScore, 2),
            'status' => $status,
            'findings' => implode("\n", $findings),
            'recommendations' => implode("\n", $recommendations)
        ];
    }
    
    /**
     * Save compliance check results to database
     */
    private function saveComplianceCheck($policyId, $score, $status, $findings, $recommendations) {
        $sql = "INSERT INTO compliance_checks (
                    policy_id, 
                    compliance_score, 
                    status, 
                    findings, 
                    recommendations, 
                    check_date,
                    next_review_date
                ) VALUES (?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY))";
        
        $this->db->query($sql, [
            $policyId,
            $score,
            $status,
            json_encode($findings),
            json_encode($recommendations)
        ]);
    }
    
    /**
     * Record a policy violation
     */
    public function recordViolation($policyId, $description, $severity = 'medium') {
        $sql = "INSERT INTO policy_violations (
                    policy_id,
                    description,
                    severity,
                    violation_date,
                    resolution_status
                ) VALUES (?, ?, ?, NOW(), 'open')";
        
        $this->db->query($sql, [$policyId, $description, $severity]);
    }
    
    /**
     * Schedule an audit
     */
    public function scheduleAudit($policyId, $frequency = 'monthly') {
        $nextAuditDate = $this->calculateNextAuditDate($frequency);
        
        $sql = "INSERT INTO audit_schedules (
                    policy_id,
                    frequency,
                    next_audit_date,
                    status
                ) VALUES (?, ?, ?, 'scheduled')
                ON DUPLICATE KEY UPDATE
                    frequency = VALUES(frequency),
                    next_audit_date = VALUES(next_audit_date),
                    status = 'scheduled'";
        
        $this->db->query($sql, [$policyId, $frequency, $nextAuditDate]);
    }
    
    /**
     * Calculate next audit date based on frequency
     */
    private function calculateNextAuditDate($frequency) {
        $intervals = [
            'daily' => 'P1D',
            'weekly' => 'P1W',
            'monthly' => 'P1M',
            'quarterly' => 'P3M',
            'annually' => 'P1Y'
        ];
        
        $interval = $intervals[$frequency] ?? 'P1M';
        $date = new DateTime();
        $date->add(new DateInterval($interval));
        return $date->format('Y-m-d H:i:s');
    }
    
    /**
     * Generate finding description based on requirement
     */
    private function generateFinding($requirement) {
        $templates = [
            'password_policy' => 'Password policy requirement "{requirement}" is not met.',
            'file_security' => 'File security requirement "{requirement}" is not compliant.',
            'network_security' => 'Network security requirement "{requirement}" needs attention.'
        ];
        
        $template = $templates[$requirement['requirement_type']] ?? 'Requirement "{requirement}" is not met.';
        return str_replace('{requirement}', $requirement['description'], $template);
    }
    
    /**
     * Generate recommendation based on requirement
     */
    private function generateRecommendation($requirement) {
        $templates = [
            'password_policy' => 'Update password policies to enforce {requirement}.',
            'file_security' => 'Implement file security controls for {requirement}.',
            'network_security' => 'Configure network security settings to ensure {requirement}.'
        ];
        
        $template = $templates[$requirement['requirement_type']] ?? 'Implement controls to ensure {requirement}.';
        return str_replace('{requirement}', strtolower($requirement['description']), $template);
    }
    
    /**
     * Check password policy compliance
     */
    private function checkPasswordPolicy($requirement) {
        // Check password requirements in the system
        $score = 1.0;
        
        // Check minimum length
        if (strpos(strtolower($requirement['description']), 'minimum') !== false) {
            $minLength = $this->db->query(
                "SELECT setting_value FROM system_settings WHERE setting_name = 'min_password_length'"
            )->fetchColumn();
            $score = ($minLength >= 8) ? 1.0 : 0.5;
        }
        
        // Check complexity requirements
        if (strpos(strtolower($requirement['description']), 'special') !== false) {
            $requiresSpecial = $this->db->query(
                "SELECT setting_value FROM system_settings WHERE setting_name = 'password_requires_special'"
            )->fetchColumn();
            $score = ($requiresSpecial == 1) ? 1.0 : 0.5;
        }
        
        return $score;
    }
    
    /**
     * Check file security compliance
     */
    private function checkFileSecurityCompliance($requirement) {
        // Check file security settings
        $score = 1.0;
        
        if (strpos(strtolower($requirement['description']), 'encrypt') !== false) {
            $encryptionEnabled = $this->db->query(
                "SELECT COUNT(*) FROM file_security_rules WHERE require_encryption = 1"
            )->fetchColumn();
            $score = ($encryptionEnabled > 0) ? 1.0 : 0.0;
        }
        
        return $score;
    }
    
    /**
     * Check network security compliance
     */
    private function checkNetworkSecurityCompliance($requirement) {
        // Check network security settings
        $score = 1.0;
        
        if (strpos(strtolower($requirement['description']), 'firewall') !== false) {
            $firewallRules = $this->db->query(
                "SELECT COUNT(*) FROM firewall_rules WHERE status = 'active'"
            )->fetchColumn();
            $score = ($firewallRules > 0) ? 1.0 : 0.0;
        }
        
        return $score;
    }

    private function checkAccessControlCompliance($requirement) {
        // Check access control settings
        $score = 1.0;
        
        if (strpos(strtolower($requirement['description']), 'role') !== false) {
            $hasRoles = $this->db->query(
                "SELECT COUNT(DISTINCT role) FROM users"
            )->fetchColumn();
            $score = ($hasRoles > 1) ? 1.0 : 0.5;
        }
        
        return $score;
    }

    private function checkDataProtectionCompliance($requirement) {
        // Check data protection settings
        $score = 1.0;
        
        if (strpos(strtolower($requirement['description']), 'encryption') !== false) {
            $encryptionEnabled = $this->db->query(
                "SELECT setting_value FROM system_settings WHERE setting_name = 'data_encryption_enabled'"
            )->fetchColumn();
            $score = ($encryptionEnabled == 1) ? 1.0 : 0.0;
        }
        
        return $score;
    }

    private function getRecommendation($requirementType) {
        $recommendations = [
            'password_policy' => 'Update password policy settings to meet security requirements',
            'file_security' => 'Enable file encryption and implement secure file handling',
            'network_security' => 'Configure firewall rules and network security controls',
            'access_control' => 'Implement role-based access control and regular access reviews',
            'data_protection' => 'Enable data encryption and implement data protection measures'
        ];
        
        return $recommendations[$requirementType] ?? 'Review and update security controls';
    }

    private function getComplianceStatus($score) {
        if ($score >= 90) return 'compliant';
        if ($score >= 70) return 'partially_compliant';
        return 'non_compliant';
    }

    private function recordComplianceCheck($policyId, $score, $status, $findings, $recommendations) {
        $this->db->query(
            "INSERT INTO compliance_checks (
                policy_id, 
                compliance_score, 
                status, 
                findings, 
                recommendations, 
                check_date
            ) VALUES (?, ?, ?, ?, ?, NOW())",
            [
                $policyId,
                $score,
                $status,
                implode("\n", $findings),
                implode("\n", $recommendations)
            ]
        );
    }
} 
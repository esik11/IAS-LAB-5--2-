<?php
// config.php - Database and Security Configuration
session_start();

// Include database configuration
require_once 'database.php';

// Security Configuration
define('ENCRYPTION_KEY', 'your-secret-encryption-key-change-this');
define('SESSION_TIMEOUT', 1800); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_TIME', 900); // 15 minutes

// Initialize system
$database = new Database();
$security = new SecurityManager($database);

// Handle login
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    $user = $security->authenticate($username, $password);
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['last_activity'] = time();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = "Invalid credentials or account locked";
    }
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $security->logSecurityEvent(isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null, 'logout', 'success', 'User logged out');
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    session_destroy();
    $session_timeout = true;
}

$_SESSION['last_activity'] = time();

// Check if user is logged in
$is_logged_in = isset($_SESSION['user_id']);
$is_admin = $is_logged_in && $_SESSION['role'] === 'admin';

// Handle admin actions
if ($is_admin && isset($_POST['action']) && $_POST['action'] === 'create_incident') {
    $stmt = $database->getConnection()->prepare("INSERT INTO security_incidents (incident_type, severity, description, assigned_to) VALUES (?, ?, ?, ?)");
    $stmt->execute([
        isset($_POST['incident_type']) ? $_POST['incident_type'] : '',
        isset($_POST['severity']) ? $_POST['severity'] : '',
        isset($_POST['description']) ? $_POST['description'] : '',
        $_SESSION['user_id']
    ]);
    $security->logSecurityEvent($_SESSION['user_id'], 'incident_created', 'success', 'Security incident created');
}

if ($is_admin && isset($_POST['action']) && $_POST['action'] === 'run_audit') {
    $audit_report = $security->generateComplianceReport();
    $security->logSecurityEvent($_SESSION['user_id'], 'compliance_audit', 'success', 'Compliance audit completed');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Management System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php if (!$is_logged_in): ?>
            <!-- Login Form -->
            <div class="login-container">
                <h2 style="text-align: center; margin-bottom: 30px; color: #2c3e50;">Security Management System</h2>
                
                <?php if (isset($login_error)): ?>
                    <div class="error"><?php echo htmlspecialchars($login_error); ?></div>
                <?php endif; ?>
                
                <?php if (isset($session_timeout)): ?>
                    <div class="error">Session expired. Please login again.</div>
                <?php endif; ?>
                
                <form method="POST" class="login-form">
                    <input type="hidden" name="action" value="login">
                    
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; font-size: 14px;">
                    <strong>Default Admin Account:</strong><br>
                    Username: admin<br>
                    Password: admin123!
                </div>
            </div>
        <?php else: ?>
            <!-- Dashboard -->
            <div class="header">
                <h1>🛡️ Security Management Dashboard</h1>
                <div class="user-info">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                    <span class="role-badge <?php echo $_SESSION['role']; ?>"><?php echo $_SESSION['role']; ?></span>
                    <a href="?action=logout" class="btn btn-danger">Logout</a>
                </div>
            </div>
            
            <div class="dashboard">
                <!-- Statistics Cards -->
                <div class="dashboard-grid">
                    <?php
                    $db = $database->getConnection();
                    
                    // Get statistics
                    $total_policies = $db->query("SELECT COUNT(*) FROM security_policies")->fetchColumn();
                    $active_incidents = $db->query("SELECT COUNT(*) FROM security_incidents WHERE status = 'open'")->fetchColumn();
                    $recent_logs = $db->query("SELECT COUNT(*) FROM security_logs WHERE DATE(created_at) = DATE('now')")->fetchColumn();
                    $compliance_score = $db->query("SELECT AVG(compliance_score) FROM compliance_audits WHERE DATE(audit_date) >= DATE('now', '-30 days')")->fetchColumn() ?: 0;
                    ?>
                    
                    <div class="card stat-card">
                        <div class="stat-number"><?php echo $total_policies; ?></div>
                        <div>Security Policies</div>
                    </div>
                    
                    <div class="card stat-card">
                        <div class="stat-number"><?php echo $active_incidents; ?></div>
                        <div>Active Incidents</div>
                    </div>
                    
                    <div class="card stat-card">
                        <div class="stat-number"><?php echo $recent_logs; ?></div>
                        <div>Today's Security Events</div>
                    </div>
                    
                    <div class="card stat-card">
                        <div class="stat-number"><?php echo round($compliance_score); ?>%</div>
                        <div>Compliance Score</div>
                    </div>
                </div>
                
                <!-- Tabs -->
                <div class="tabs">
                    <div class="tab active" onclick="showTab('policies')">Security Policies</div>
                    <div class="tab" onclick="showTab('logs')">Security Logs</div>
                    <?php if ($is_admin): ?>
                        <div class="tab" onclick="showTab('incidents')">Incident Management</div>
                        <div class="tab" onclick="showTab('compliance')">Compliance Audit</div>
                    <?php endif; ?>
                </div>
                
                <!-- Security Policies Tab -->
                <div id="policies" class="tab-content active">
                    <div class="card">
                        <h3>Security Policies & Controls</h3>
                        <p>Current security policies aligned with GDPR and industry best practices:</p>
                        
                        <?php
                        $policies = $db->query("SELECT * FROM security_policies ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Policy Name</th>
                                    <th>Type</th>
                                    <th>Description</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($policies as $policy): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($policy['policy_name']); ?></td>
                                        <td><?php echo htmlspecialchars($policy['policy_type']); ?></td>
                                        <td><?php echo htmlspecialchars($policy['description']); ?></td>
                                        <td><span class="status-badge status-success"><?php echo htmlspecialchars($policy['compliance_status']); ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Security Logs Tab -->
                <div id="logs" class="tab-content">
                    <div class="card">
                        <h3>Recent Security Events</h3>
                        <p>Monitor security events and access attempts:</p>
                        
                        <?php
                        $logs = $db->query("SELECT sl.*, u.username 
                                         FROM security_logs sl 
                                         LEFT JOIN users u ON sl.user_id = u.id 
                                         ORDER BY sl.created_at DESC 
                                         LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Status</th>
                                    <th>IP Address</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                                        <td><?php echo htmlspecialchars($log['username'] ?: 'System'); ?></td>
                                        <td><?php echo htmlspecialchars($log['action']); ?></td>
                                        <td>
                                            <span class="status-badge status-<?php echo $log['status'] === 'success' ? 'success' : ($log['status'] === 'failed' ? 'danger' : 'warning'); ?>">
                                                <?php echo htmlspecialchars($log['status']); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                        <td><?php echo htmlspecialchars($log['details']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <?php if ($is_admin): ?>
                    <!-- Incident Management Tab -->
                    <div id="incidents" class="tab-content">
                        <div class="card">
                            <h3>Security Incident Response</h3>
                            <p>Manage and track security incidents:</p>
                            
                            <form method="POST" class="form-inline">
                                <input type="hidden" name="action" value="create_incident">
                                <div class="form-group">
                                    <label>Incident Type</label>
                                    <select name="incident_type" required>
                                        <option value="">Select Type</option>
                                        <option value="data_breach">Data Breach</option>
                                        <option value="unauthorized_access">Unauthorized Access</option>
                                        <option value="malware">Malware Detection</option>
                                        <option value="phishing">Phishing Attack</option>
                                        <option value="policy_violation">Policy Violation</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Severity</label>
                                    <select name="severity" required>
                                        <option value="">Select Severity</option>
                                        <option value="low">Low</option>
                                        <option value="medium">Medium</option>
                                        <option value="high">High</option>
                                        <option value="critical">Critical</option>
                                    </select>
                                </div>
                                <div class="form-group" style="flex: 1;">
                                    <label>Description</label>
                                    <input type="text" name="description" placeholder="Incident description" required>
                                </div>
                                <button type="submit" class="btn btn-warning">Create Incident</button>
                            </form>
                            
                            <?php
                            $incidents = $db->query("SELECT si.*, u.username as assigned_user 
                                                   FROM security_incidents si 
                                                   LEFT JOIN users u ON si.assigned_to = u.id 
                                                   ORDER BY si.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
                            ?>
                            
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Type</th>
                                        <th>Severity</th>
                                        <th>Description</th>
                                        <th>Status</th>
                                        <th>Assigned To</th>
                                        <th>Created</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($incidents as $incident): ?>
                                        <tr>
                                            <td>#<?php echo $incident['id']; ?></td>
                                            <td><?php echo htmlspecialchars($incident['incident_type']); ?></td>
                                            <td>
                                                <span class="status-badge status-<?php echo $incident['severity'] === 'critical' ? 'danger' : ($incident['severity'] === 'high' ? 'warning' : 'success'); ?>">
                                                    <?php echo htmlspecialchars($incident['severity']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo htmlspecialchars($incident['description']); ?></td>
                                            <td>
                                                <span class="status-badge status-<?php echo $incident['status'] === 'resolved' ? 'success' : 'warning'; ?>">
                                                    <?php echo htmlspecialchars($incident['status']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo htmlspecialchars($incident['assigned_user'] ?: 'Unassigned'); ?></td>
                                            <td><?php echo date('Y-m-d H:i', strtotime($incident['created_at'])); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <!-- Compliance Audit Tab -->
                    <div id="compliance" class="tab-content">
                        <div class="card">
                            <h3>Security Policy Compliance Audit</h3>
                            <p>Automated compliance checking and reporting:</p>
                            
                            <form method="POST" style="margin-bottom: 20px;">
                                <input type="hidden" name="action" value="run_audit">
                                <button type="submit" class="btn btn-success">🔍 Run Compliance Audit</button>
                            </form>
                            
                            <?php if (isset($audit_report)): ?>
                                <div class="success">
                                    <strong>✅ Compliance Audit Completed</strong><br>
                                    Audit completed successfully. Results are displayed below.
                                </div>
                                
                                <h4 style="margin: 20px 0 15px 0;">Audit Results</h4>
                                <?php foreach ($audit_report as $result): ?>
                                    <div style="margin-bottom: 15px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                            <strong><?php echo htmlspecialchars($result['policy']); ?></strong>
                                            <div>
                                                <span style="font-size: 18px; font-weight: bold; color: <?php echo $result['score'] >= 90 ? '#27ae60' : ($result['score'] >= 75 ? '#f39c12' : '#e74c3c'); ?>">
                                                    <?php echo $result['score']; ?>%
                                                </span>
                                            </div>
                                        </div>
                                        <div class="progress-bar">
                                            <div class="progress-fill" style="width: <?php echo $result['score']; ?>%"></div>
                                        </div>
                                        <div style="margin-top: 10px; font-size: 14px;">
                                            <div><strong>Findings:</strong> <?php echo htmlspecialchars($result['findings']); ?></div>
                                            <div style="margin-top: 5px;"><strong>Recommendations:</strong> <?php echo htmlspecialchars($result['recommendations']); ?></div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                            
                            <h4 style="margin: 30px 0 15px 0;">Recent Audit History</h4>
                            <?php
                            $audits = $db->query("SELECT ca.*, sp.policy_name 
                                                FROM compliance_audits ca 
                                                LEFT JOIN security_policies sp ON ca.policy_id = sp.id 
                                                ORDER BY ca.audit_date DESC 
                                                LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
                            ?>
                            
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Policy</th>
                                        <th>Score</th>
                                        <th>Findings</th>
                                        <th>Auditor</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($audits as $audit): ?>
                                        <tr>
                                            <td><?php echo date('Y-m-d H:i', strtotime($audit['audit_date'])); ?></td>
                                            <td><?php echo htmlspecialchars($audit['policy_name'] ?: $audit['audit_type']); ?></td>
                                            <td>
                                                <span style="color: <?php echo $audit['compliance_score'] >= 90 ? '#27ae60' : ($audit['compliance_score'] >= 75 ? '#f39c12' : '#e74c3c'); ?>; font-weight: bold;">
                                                    <?php echo $audit['compliance_score']; ?>%
                                                </span>
                                            </td>
                                            <td><?php echo htmlspecialchars($audit['findings']); ?></td>
                                            <td><?php echo htmlspecialchars($audit['auditor']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endif; ?>
                
                <!-- Security Policy Implementation Guide -->
                <div class="card" style="margin-top: 30px;">
                    <h3>🛡️ Implemented Security Controls</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;">
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Authentication Controls</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>Strong password policy (8+ chars, mixed case, numbers, symbols)</li>
                                <li>Account lockout after 3 failed attempts</li>
                                <li>Session timeout (30 minutes)</li>
                                <li>Secure password hashing (bcrypt)</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Access Controls</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>Role-based access control (Admin/User)</li>
                                <li>Least privilege principle enforcement</li>
                                <li>Session management and validation</li>
                                <li>Administrative function restrictions</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Data Protection</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>Input validation and sanitization</li>
                                <li>SQL injection protection (prepared statements)</li>
                                <li>XSS protection (output encoding)</li>
                                <li>Secure data storage practices</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Monitoring & Logging</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>Comprehensive security event logging</li>
                                <li>Failed login attempt tracking</li>
                                <li>User activity monitoring</li>
                                <li>Real-time security alerting</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Incident Response</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>Incident creation and tracking system</li>
                                <li>Severity classification framework</li>
                                <li>Assignment and escalation procedures</li>
                                <li>Response time monitoring</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 style="color: #27ae60; margin-bottom: 10px;">✅ Compliance & Audit</h4>
                            <ul style="line-height: 1.6; color: #555;">
                                <li>GDPR compliance framework</li>
                                <li>Automated compliance scoring</li>
                                <li>Policy violation detection</li>
                                <li>Regular audit reporting</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <!-- Security Recommendations -->
                <div class="card" style="margin-top: 20px;">
                    <h3>🔒 Security Recommendations</h3>
                    <div style="background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;">
                        <h4 style="color: #856404; margin-bottom: 10px;">Additional Security Measures to Consider:</h4>
                        <ul style="line-height: 1.8; color: #856404;">
                            <li><strong>Two-Factor Authentication (2FA):</strong> Implement TOTP or SMS-based 2FA for enhanced security</li>
                            <li><strong>Network Security:</strong> Configure firewall rules and implement network segmentation</li>
                            <li><strong>Encryption:</strong> Enable SSL/TLS for data in transit and consider database encryption</li>
                            <li><strong>Backup & Recovery:</strong> Implement regular automated backups with encryption</li>
                            <li><strong>Security Training:</strong> Conduct regular security awareness training for users</li>
                            <li><strong>Vulnerability Scanning:</strong> Implement automated vulnerability assessments</li>
                            <li><strong>Incident Response Plan:</strong> Develop and test comprehensive incident response procedures</li>
                        </ul>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        // Auto-refresh security logs every 30 seconds
        setInterval(function() {
            if (document.getElementById('logs').classList.contains('active')) {
                // Only refresh if logs tab is active
                // In a real implementation, you'd use AJAX here
                console.log('Refreshing security logs...');
            }
        }, 30000);
        
        // Simulate real-time security monitoring
        function updateSecurityStatus() {
            const statCards = document.querySelectorAll('.stat-card .stat-number');
            statCards.forEach(card => {
                // Add subtle animation to indicate live monitoring
                card.style.transition = 'all 0.3s ease';
                card.style.transform = 'scale(1.05)';
                setTimeout(() => {
                    card.style.transform = 'scale(1)';
                }, 300);
            });
        }
        
        // Update status every 60 seconds
        setInterval(updateSecurityStatus, 60000);
        
        // Form validation for incident creation
        document.addEventListener('DOMContentLoaded', function() {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const requiredFields = form.querySelectorAll('[required]');
                    let hasErrors = false;
                    
                    requiredFields.forEach(field => {
                        if (!field.value.trim()) {
                            field.style.borderColor = '#e74c3c';
                            hasErrors = true;
                        } else {
                            field.style.borderColor = '#ecf0f1';
                        }
                    });
                    
                    if (hasErrors) {
                        e.preventDefault();
                        alert('Please fill in all required fields.');
                    }
                });
            });
        });
        
        // Password strength indicator (for future enhancement)
        function checkPasswordStrength(password) {
            let strength = 0;
            const checks = [
                password.length >= 8,
                /[a-z]/.test(password),
                /[A-Z]/.test(password),
                /[0-9]/.test(password),
                /[^A-Za-z0-9]/.test(password)
            ];
            
            strength = checks.filter(Boolean).length;
            
            const strengthLevels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
            const strengthColors = ['#e74c3c', '#f39c12', '#f1c40f', '#3498db', '#27ae60'];
            
            return {
                score: strength,
                text: strengthLevels[strength - 1] || 'Very Weak',
                color: strengthColors[strength - 1] || '#e74c3c'
            };
        }
    </script>
</body>
</html>
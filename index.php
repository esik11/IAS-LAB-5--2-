<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';
require_once 'includes/NetworkSecurity.php';
require_once 'includes/Encryption.php';
require_once 'includes/SecurityAudit.php';

session_start();

$db = Database::getInstance();
$security = new Security();
$networkSecurity = new NetworkSecurity();
$encryption = new Encryption();
$securityAudit = new SecurityAudit();

// Check if user is logged in
if (!$security->validateSession()) {
    header('Location: login.php');
    exit;
}

// Check if user has admin role
if ($_SESSION['role'] !== 'admin') {
    header('Location: user_dashboard.php');
    exit;
}

$is_admin = $_SESSION['role'] === 'admin';

// Validate network access
if (!$networkSecurity->validateAccess($_SERVER['REMOTE_ADDR'])) {
    die('Access denied from your IP address');
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $user_id = $_SESSION['user_id']; // Store user_id before session destroy
    $security->logSecurityEvent($user_id, 'logout', 'User logged out');
    session_destroy();
    header('Location: login.php');
    exit;
}

// Handle security incident creation
if (isset($_POST['action']) && $_POST['action'] === 'create_incident') {
    $title = filter_input(INPUT_POST, 'title', FILTER_SANITIZE_STRING);
    $description = filter_input(INPUT_POST, 'description', FILTER_SANITIZE_STRING);
    $severity = filter_input(INPUT_POST, 'severity', FILTER_SANITIZE_STRING);
    
    // Encrypt sensitive data
    $description = $encryption->encrypt($description);
    
    $db->query(
        "INSERT INTO security_incidents (title, description, severity, reported_by) VALUES (?, ?, ?, ?)",
        [$title, $description, $severity, $_SESSION['user_id']]
    );
    
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Generate audit report for admins
$audit_report = null;
if ($is_admin && isset($_POST['action']) && $_POST['action'] === 'generate_audit') {
    $audit_report = $security->generateAuditReport();
    $security->logSecurityEvent($_SESSION['user_id'], 'audit_generated', 'Security audit report generated');
}

// Get statistics
$stats = [
    'total_incidents' => $db->query("SELECT COUNT(*) FROM security_incidents")->fetchColumn(),
    'open_incidents' => $db->query("SELECT COUNT(*) FROM security_incidents WHERE status = 'open'")->fetchColumn(),
    'recent_logs' => $db->query("SELECT COUNT(*) FROM security_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")->fetchColumn(),
    'compliance_score' => $db->query("SELECT AVG(CASE WHEN compliance_status = 'compliant' THEN 100 WHEN compliance_status = 'partially_compliant' THEN 50 ELSE 0 END) FROM policy_compliance")->fetchColumn() ?: 0
];

// Get security metrics
$metrics = $securityAudit->generateSecurityMetrics();

// Get recent incidents
$incidents = $db->query(
    "SELECT i.*, u.username 
     FROM security_incidents i 
     LEFT JOIN users u ON i.reported_by = u.id 
     ORDER BY i.created_at DESC 
     LIMIT 10"
)->fetchAll(PDO::FETCH_ASSOC);

// Decrypt incident descriptions
foreach ($incidents as &$incident) {
    if (strpos($incident['description'], 'enc:') === 0) {
        try {
            $incident['description'] = $encryption->decrypt($incident['description']);
        } catch (Exception $e) {
            $incident['description'] = '[Encrypted]';
        }
    }
}

// Get security policies
$policies = $db->query(
    "SELECT * FROM security_policies 
     ORDER BY created_at DESC"
)->fetchAll(PDO::FETCH_ASSOC);

// Get recent security logs with user roles
$logs = $db->query(
    "SELECT l.*, u.username, u.role 
     FROM security_logs l
     LEFT JOIN users u ON l.user_id = u.id 
     ORDER BY l.created_at DESC 
     LIMIT 10"
)->fetchAll(PDO::FETCH_ASSOC);

// Run vulnerability scan if requested
$vulnerabilities = [];
if (isset($_GET['scan']) && $_SESSION['is_admin']) {
    $vulnerabilities = $securityAudit->runVulnerabilityScan();
}

// Add new network security related stats
$network_stats = [
    'firewall_rules' => $db->query("SELECT COUNT(*) FROM firewall_rules")->fetchColumn(),
    'blocked_ips' => $db->query("SELECT COUNT(*) FROM ip_blacklist")->fetchColumn(),
    'file_rules' => $db->query("SELECT COUNT(*) FROM file_security_rules")->fetchColumn()
];

// Get firewall rules
$firewall_rules = $db->query(
    "SELECT * FROM firewall_rules 
     ORDER BY priority DESC 
     LIMIT 10"
)->fetchAll(PDO::FETCH_ASSOC);

// Get IP blacklist/whitelist
$blacklisted_ips = $db->query(
    "SELECT * FROM ip_blacklist 
     ORDER BY created_at DESC 
     LIMIT 5"
)->fetchAll(PDO::FETCH_ASSOC);

$whitelisted_ips = $db->query(
    "SELECT * FROM ip_whitelist 
     ORDER BY created_at DESC 
     LIMIT 5"
)->fetchAll(PDO::FETCH_ASSOC);

// Get file security rules
$file_rules = $db->query(
    "SELECT * FROM file_security_rules"
)->fetchAll(PDO::FETCH_ASSOC);

// Get SSL configuration
$ssl_config = $db->query(
    "SELECT * FROM ssl_configuration"
)->fetchAll(PDO::FETCH_ASSOC);

// Handle network security form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $is_admin) {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'add_firewall_rule':
                $db->query(
                    "INSERT INTO firewall_rules (rule_name, rule_type, protocol, port_range, description, priority, created_by) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [
                        $_POST['rule_name'],
                        $_POST['rule_type'],
                        $_POST['protocol'],
                        $_POST['port_range'],
                        $_POST['description'],
                        $_POST['priority'],
                        $_SESSION['user_id']
                    ]
                );
                break;

            case 'add_ip_blacklist':
                $db->query(
                    "INSERT INTO ip_blacklist (ip_address, reason, added_by) 
                     VALUES (?, ?, ?)",
                    [
                        $_POST['ip_address'],
                        $_POST['reason'],
                        $_SESSION['user_id']
                    ]
                );
                break;

            case 'add_ip_whitelist':
                $db->query(
                    "INSERT INTO ip_whitelist (ip_address, description, added_by) 
                     VALUES (?, ?, ?)",
                    [
                        $_POST['ip_address'],
                        $_POST['description'],
                        $_SESSION['user_id']
                    ]
                );
                break;
        }
        
        // Redirect to prevent form resubmission
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Security Management System</title>
    <!-- jQuery must be loaded before Bootstrap -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <!-- Bootstrap JavaScript Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Initialize all tab functionality
        const TabManager = {
            init: function() {
                // Show default tab on page load
                document.addEventListener('DOMContentLoaded', () => {
                    this.showTab('incidents');
                    this.setupAutoRefresh();
                });
            },

            showTab: function(tabName) {
                // Hide all tab contents
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.style.display = 'none';
                    content.classList.remove('active');
                });
                
                // Remove active class from all tabs
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected tab content
                const selectedTab = document.getElementById(tabName);
                if (selectedTab) {
                    selectedTab.style.display = 'block';
                    selectedTab.classList.add('active');
                }
                
                // Add active class to clicked tab
                const clickedTab = document.querySelector(`.tab[onclick*="${tabName}"]`);
                if (clickedTab) {
                    clickedTab.classList.add('active');
                }
            },

            setupAutoRefresh: function() {
                // Auto-refresh security logs every 30 seconds
                setInterval(() => {
                    if (document.getElementById('logs').classList.contains('active')) {
                        // Only refresh if logs tab is active
                        location.reload();
                    }
                }, 30000);
            }
        };

        // Initialize the tab manager
        TabManager.init();

        // Make showTab available globally
        window.showTab = function(tabName) {
            TabManager.showTab(tabName);
        };
    </script>
</head>
<body>
    <div class="container">
        <div class="dashboard">
            <header>
                <h1>🛡️ Security Management Dashboard</h1>
                <div class="user-info">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                    <span class="role-badge <?php echo $_SESSION['role']; ?>"><?php echo $_SESSION['role']; ?></span>
                    <?php if ($is_admin): ?>
                        <a href="manage_users.php" class="btn">Manage Users</a>
                    <?php endif; ?>
                    <a href="?action=logout" class="btn-logout">Logout</a>
                </div>
            </header>

            <!-- Statistics Cards -->
            <div class="dashboard-grid">
                <div class="stat-card">
                    <div class="stat-icon">📊</div>
                    <h3>Total Incidents</h3>
                    <div class="stat-number"><?php echo $stats['total_incidents']; ?></div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">⚠️</div>
                    <h3>Open Incidents</h3>
                    <div class="stat-number"><?php echo $stats['open_incidents']; ?></div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">📝</div>
                    <h3>24h Security Events</h3>
                    <div class="stat-number"><?php echo $stats['recent_logs']; ?></div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">✓</div>
                    <h3>Compliance Score</h3>
                    <div class="stat-number"><?php echo round($stats['compliance_score']); ?>%</div>
                </div>

                <?php if ($is_admin): ?>
                <div class="stat-card">
                    <div class="stat-icon">🔒</div>
                    <h3>Firewall Rules</h3>
                    <div class="stat-number"><?php echo $network_stats['firewall_rules']; ?></div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">🚫</div>
                    <h3>Blocked IPs</h3>
                    <div class="stat-number"><?php echo $network_stats['blocked_ips']; ?></div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon">📁</div>
                    <h3>File Security Rules</h3>
                    <div class="stat-number"><?php echo $network_stats['file_rules']; ?></div>
                </div>
                <?php endif; ?>
            </div>

            <!-- Tabs Navigation -->
            <div class="tabs">
                <div class="tab active" onclick="showTab('incidents')">Security Incidents</div>
                <div class="tab" onclick="showTab('logs')">Security Logs</div>
                <?php if ($is_admin): ?>
                    <div class="tab" onclick="showTab('policies')">Security Policies</div>
                    <div class="tab" onclick="showTab('compliance')">Compliance Audit</div>
                    <div class="tab" onclick="showTab('network_security')">Network Security</div>
                <?php endif; ?>
            </div>

            <!-- Security Incidents Tab -->
            <div id="incidents" class="tab-content active">
                <div class="card">
                    <h2>Security Incidents</h2>
                    <form method="POST" class="incident-form">
                        <input type="hidden" name="action" value="create_incident">
                        <div class="form-group">
                            <label>Title</label>
                            <input type="text" name="title" required>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea name="description" required></textarea>
                        </div>
                        <div class="form-group">
                            <label>Severity</label>
                            <select name="severity" required>
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>
                        <button type="submit">Report Incident</button>
                    </form>

                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Description</th>
                                <th>Severity</th>
                                <th>Reported By</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($incidents as $incident): ?>
                            <tr class="severity-<?php echo htmlspecialchars($incident['severity']); ?>">
                                <td><?php echo htmlspecialchars($incident['title']); ?></td>
                                <td><?php echo htmlspecialchars($incident['description']); ?></td>
                                <td><?php echo htmlspecialchars($incident['severity']); ?></td>
                                <td><?php echo htmlspecialchars($incident['username']); ?></td>
                                <td>
                                    <?php echo htmlspecialchars($incident['created_at']); ?>
                                    <form method="post" action="security_incidents.php" style="display: inline;">
                                        <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                                        <button type="submit" name="download_incidents_pdf" class="btn btn-sm btn-primary">
                                            <i class="fas fa-file-pdf"></i> PDF
                                        </button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Security Logs Tab -->
            <div id="logs" class="tab-content">
                <div class="card">
                    <h2>Security Events Log</h2>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>User</th>
                                <th>Role</th>
                                <th>Action</th>
                                <th>IP Address</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                                <td><?php echo htmlspecialchars($log['username'] ?? 'System'); ?></td>
                                <td>
                                    <span class="role-badge <?php echo htmlspecialchars($log['role'] ?? 'system'); ?>">
                                        <?php echo ucfirst(htmlspecialchars($log['role'] ?? 'System')); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($log['action']); ?></td>
                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                <td><?php echo htmlspecialchars($log['details']); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <?php if ($is_admin): ?>
                <!-- Security Policies Tab -->
                <div id="policies" class="tab-content">
                    <div class="card">
                        <h2>Security Policies</h2>
                        <div class="admin-tools">
                            <a href="manage_policies.php" class="btn">Manage Security Policies</a>
                        </div>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Policy Name</th>
                                    <th>Category</th>
                                    <th>Status</th>
                                    <th>Last Updated</th>
                                    <th>Compliance</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($policies as $policy): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($policy['policy_name']); ?></td>
                                    <td><?php echo ucfirst(htmlspecialchars($policy['category'])); ?></td>
                                    <td>
                                        <span class="status-badge <?php echo $policy['status'] === 'active' ? 'status-success' : 'status-warning'; ?>">
                                            <?php echo ucfirst(htmlspecialchars($policy['status'])); ?>
                                        </span>
                                    </td>
                                    <td><?php echo date('Y-m-d H:i', strtotime($policy['created_at'])); ?></td>
                                    <td>
                                        <span class="status-badge <?php 
                                            echo $policy['last_audit_result'] === 'pass' ? 'status-success' : 
                                                ($policy['last_audit_result'] === 'partial' ? 'status-warning' : 'status-danger'); 
                                        ?>">
                                            <?php echo $policy['last_audit_result'] ? ucfirst($policy['last_audit_result']) : 'Not Assessed'; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <button type="button" class="btn btn-sm btn-primary" onclick="viewPolicy(<?php echo $policy['id']; ?>)">
                                            View Details
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Compliance Audit Tab -->
                <div id="compliance" class="tab-content">
                    <div class="card">
                        <h2>Security Compliance Audit</h2>
                        <div class="audit-actions">
                            <form method="post">
                                <input type="hidden" name="action" value="generate_audit">
                                <button type="submit" class="btn btn-primary">Run Compliance Audit</button>
                            </form>
                            <a href="audit_report.php" class="btn">View Audit History</a>
                        </div>

                        <?php if (isset($_POST['action']) && $_POST['action'] === 'generate_audit'): 
                            $audit_results = $securityAudit->runDetailedComplianceAudit();
                        ?>
                            <div class="audit-results">
                                <h3>Audit Results</h3>
                                <div class="overall-score">
                                    <h4>Overall Compliance Score</h4>
                                    <div class="score-circle <?php echo $audit_results['overall_score'] >= 90 ? 'excellent' : ($audit_results['overall_score'] >= 70 ? 'good' : 'poor'); ?>">
                                        <?php echo round($audit_results['overall_score']); ?>%
                                    </div>
                                </div>

                                <div class="category-scores">
                                    <?php foreach ($audit_results['categories'] as $category): ?>
                                        <div class="category-score">
                                            <h4><?php echo htmlspecialchars($category['category']); ?></h4>
                                            <div class="score-bar">
                                                <div class="score-fill" style="width: <?php echo $category['score']; ?>%"></div>
                                                <span><?php echo $category['score']; ?>%</span>
                                            </div>
                                            <?php if (!empty($category['issues'])): ?>
                                                <div class="issues">
                                                    <h5>Issues Found:</h5>
                                                    <ul>
                                                        <?php foreach ($category['issues'] as $issue): ?>
                                                            <li><?php echo htmlspecialchars($issue); ?></li>
                                                        <?php endforeach; ?>
                                                    </ul>
                                                </div>
                                            <?php endif; ?>
                                            <?php if (!empty($category['recommendations'])): ?>
                                                <div class="recommendations">
                                                    <h5>Recommendations:</h5>
                                                    <ul>
                                                        <?php foreach ($category['recommendations'] as $rec): ?>
                                                            <li><?php echo htmlspecialchars($rec); ?></li>
                                                        <?php endforeach; ?>
                                                    </ul>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Network Security Tab Content -->
            <?php if ($is_admin): ?>
            <div id="network_security" class="tab-content">
                <div class="card">
                    <h2>Network & Security Controls</h2>
                    
                    <!-- Firewall Rules Section -->
                    <section class="security-section">
                        <h3>Firewall Rules</h3>
                        <form method="POST" class="security-form">
                            <input type="hidden" name="action" value="add_firewall_rule">
                            <div class="form-group">
                                <label>Rule Name:</label>
                                <input type="text" name="rule_name" required class="form-control">
                            </div>
                            <div class="form-group">
                                <label>Type:</label>
                                <select name="rule_type" required class="form-control">
                                    <option value="allow">Allow</option>
                                    <option value="deny">Deny</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Protocol:</label>
                                <select name="protocol" required class="form-control">
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                    <option value="icmp">ICMP</option>
                                    <option value="all">All</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Port Range:</label>
                                <input type="text" name="port_range" placeholder="e.g., 80 or 80-443" class="form-control">
                            </div>
                            <div class="form-group">
                                <label>Priority:</label>
                                <input type="number" name="priority" required class="form-control">
                            </div>
                            <div class="form-group">
                                <label>Description:</label>
                                <textarea name="description" class="form-control"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Add Firewall Rule</button>
                        </form>

                        <table class="data-table mt-4">
                            <thead>
                                <tr>
                                    <th>Rule Name</th>
                                    <th>Type</th>
                                    <th>Protocol</th>
                                    <th>Port Range</th>
                                    <th>Priority</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($firewall_rules as $rule): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($rule['rule_name']); ?></td>
                                    <td><?php echo htmlspecialchars($rule['rule_type']); ?></td>
                                    <td><?php echo htmlspecialchars($rule['protocol']); ?></td>
                                    <td><?php echo htmlspecialchars($rule['port_range']); ?></td>
                                    <td><?php echo htmlspecialchars($rule['priority']); ?></td>
                                    <td>
                                        <button onclick="deleteFirewallRule(<?php echo $rule['id']; ?>)" class="btn btn-danger btn-sm">Delete</button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </section>

                    <!-- IP Access Control Section -->
                    <section class="security-section mt-4">
                        <h3>IP Access Control</h3>
                        <div class="row">
                            <div class="col-md-6">
                                <h4>IP Whitelist</h4>
                                <form method="POST" class="mb-3">
                                    <input type="hidden" name="action" value="add_ip_whitelist">
                                    <div class="form-group">
                                        <input type="text" name="ip_address" placeholder="IP Address" required class="form-control">
                                    </div>
                                    <div class="form-group">
                                        <input type="text" name="description" placeholder="Description" class="form-control">
                                    </div>
                                    <button type="submit" class="btn btn-primary">Add to Whitelist</button>
                                </form>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Description</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($whitelisted_ips as $ip): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($ip['ip_address']); ?></td>
                                            <td><?php echo htmlspecialchars($ip['description']); ?></td>
                                            <td>
                                                <button onclick="deleteWhitelistIP(<?php echo $ip['id']; ?>)" class="btn btn-danger btn-sm">Delete</button>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                            <div class="col-md-6">
                                <h4>IP Blacklist</h4>
                                <form method="POST" class="mb-3">
                                    <input type="hidden" name="action" value="add_ip_blacklist">
                                    <div class="form-group">
                                        <input type="text" name="ip_address" placeholder="IP Address" required class="form-control">
                                    </div>
                                    <div class="form-group">
                                        <input type="text" name="reason" placeholder="Reason" class="form-control">
                                    </div>
                                    <button type="submit" class="btn btn-primary">Add to Blacklist</button>
                                </form>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Reason</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($blacklisted_ips as $ip): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($ip['ip_address']); ?></td>
                                            <td><?php echo htmlspecialchars($ip['reason']); ?></td>
                                            <td>
                                                <button onclick="deleteBlacklistIP(<?php echo $ip['id']; ?>)" class="btn btn-danger btn-sm">Delete</button>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </section>

                    <!-- File Security Section -->
                    <section class="security-section mt-4">
                        <h3>File Upload Security</h3>
                        <button class="btn btn-primary mb-3" onclick="addNewFileRule()">Add New File Type</button>
                        <table id="fileRulesTable" class="data-table">
                            <thead>
                                <tr>
                                    <th>File Type</th>
                                    <th>Max Size (MB)</th>
                                    <th>Allowed</th>
                                    <th>Malware Scan</th>
                                    <th>Encryption</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($file_rules as $rule): ?>
                                <tr id="file-rule-<?php echo $rule['id']; ?>">
                                    <td><?php echo htmlspecialchars($rule['file_type']); ?></td>
                                    <td><?php echo htmlspecialchars($rule['max_size'] / 1048576); ?></td>
                                    <td>
                                        <input type="checkbox" 
                                               onchange="updateFileRule(<?php echo $rule['id']; ?>, 'is_allowed')" 
                                               <?php echo $rule['is_allowed'] ? 'checked' : ''; ?>>
                                    </td>
                                    <td>
                                        <input type="checkbox" 
                                               onchange="updateFileRule(<?php echo $rule['id']; ?>, 'scan_for_malware')" 
                                               <?php echo $rule['scan_for_malware'] ? 'checked' : ''; ?>>
                                    </td>
                                    <td>
                                        <input type="checkbox" 
                                               onchange="updateFileRule(<?php echo $rule['id']; ?>, 'require_encryption')" 
                                               <?php echo $rule['require_encryption'] ? 'checked' : ''; ?>>
                                    </td>
                                    <td>
                                        <button onclick="editFileRule(<?php echo $rule['id']; ?>)" class="btn btn-primary btn-sm">Edit</button>
                                        <button onclick="deleteFileRule(<?php echo $rule['id']; ?>)" class="btn btn-danger btn-sm">Delete</button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </section>

                    <!-- SSL/TLS Configuration -->
                    <section class="security-section mt-4">
                        <h3>SSL/TLS Configuration</h3>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Value</th>
                                    <th>Description</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($ssl_config as $setting): ?>
                                <tr data-setting="<?php echo htmlspecialchars($setting['setting_name']); ?>">
                                    <td><?php echo htmlspecialchars($setting['setting_name']); ?></td>
                                    <td>
                                        <?php if ($setting['setting_name'] === 'ssl_enabled' || $setting['setting_name'] === 'hsts_enabled'): ?>
                                            <select class="form-control" onchange="updateSSLSetting('<?php echo $setting['setting_name']; ?>', this.value)">
                                                <option value="true" <?php echo $setting['setting_value'] === 'true' ? 'selected' : ''; ?>>true</option>
                                                <option value="false" <?php echo $setting['setting_value'] === 'false' ? 'selected' : ''; ?>>false</option>
                                            </select>
                                        <?php elseif ($setting['setting_name'] === 'min_tls_version'): ?>
                                            <select class="form-control" onchange="updateSSLSetting('<?php echo $setting['setting_name']; ?>', this.value)">
                                                <option value="1.0" <?php echo $setting['setting_value'] === '1.0' ? 'selected' : ''; ?>>1.0</option>
                                                <option value="1.1" <?php echo $setting['setting_value'] === '1.1' ? 'selected' : ''; ?>>1.1</option>
                                                <option value="1.2" <?php echo $setting['setting_value'] === '1.2' ? 'selected' : ''; ?>>1.2</option>
                                                <option value="1.3" <?php echo $setting['setting_value'] === '1.3' ? 'selected' : ''; ?>>1.3</option>
                                            </select>
                                        <?php else: ?>
                                            <input type="text" class="form-control" 
                                                   value="<?php echo htmlspecialchars($setting['setting_value']); ?>"
                                                   onchange="updateSSLSetting('<?php echo $setting['setting_name']; ?>', this.value)">
                                        <?php endif; ?>
                                    </td>
                                    <td class="ssl-description"><?php echo htmlspecialchars($setting['description']); ?></td>
                                    <td>
                                        <button onclick="editSSLDescription('<?php echo $setting['setting_name']; ?>')" class="btn btn-primary btn-sm">Edit Description</button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </section>

                    <!-- Password Security Monitoring -->
                    <section class="security-section mt-4">
                        <h3>Password Security Status</h3>
                        <div class="row">
                            <div class="col-md-12">
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Minimum Length (12 chars)</span>
                                        <span class="badge bg-success">Compliant</span>
                                    </div>
                                </div>
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Password History (5)</span>
                                        <span class="badge bg-success">Compliant</span>
                                    </div>
                                    <div class="details mt-2">
                                        <?php
                                        $passwordStats = $db->query("
                                            SELECT 
                                                COUNT(*) as total_changes,
                                                COUNT(DISTINCT user_id) as unique_users
                                            FROM password_history
                                            WHERE changed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                                        ")->fetch(PDO::FETCH_ASSOC);
                                        echo "Last 30 days: {$passwordStats['total_changes']} changes by {$passwordStats['unique_users']} users";
                                        ?>
                                    </div>
                                </div>
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Special Characters</span>
                                        <span class="badge bg-success">Required</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Network Security Monitoring -->
                    <section class="security-section mt-4">
                        <h3>Network Security Status</h3>
                        <div class="row">
                            <div class="col-md-12">
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">HTTPS Enforcement</span>
                                        <span class="badge bg-primary">Active</span>
                                    </div>
                                </div>
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Rate Limiting</span>
                                        <span class="badge bg-warning">Configured</span>
                                    </div>
                                    <div class="details mt-2">
                                        <?php
                                        $networkStats = $db->query("
                                            SELECT 
                                                COUNT(*) as total_attempts,
                                                COUNT(DISTINCT ip_address) as unique_ips,
                                                SUM(CASE WHEN action = 'rate_limit_exceeded' THEN 1 ELSE 0 END) as rate_limits
                                            FROM security_logs
                                            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                                        ")->fetch(PDO::FETCH_ASSOC);
                                        echo "Rate limits exceeded: {$networkStats['rate_limits']} times in last 24h";
                                        ?>
                                    </div>
                                </div>
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">IP Restrictions</span>
                                        <span class="badge bg-info">Enforced</span>
                                    </div>
                                    <div class="details mt-2">
                                        <?php echo "Unique IPs: {$networkStats['unique_ips']} in last 24h"; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Data Protection Status -->
                    <section class="security-section mt-4">
                        <h3>Data Protection Status</h3>
                        <div class="row">
                            <div class="col-md-12">
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Encryption (AES-256)</span>
                                        <span class="badge bg-primary">Active</span>
                                    </div>
                                    <div class="details mt-2">Using AES-256-CBC encryption for sensitive data</div>
                                </div>
                                <div class="policy-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="label">Encrypted Records</span>
                                        <span class="badge bg-primary">Active</span>
                                    </div>
                                    <div class="details mt-2">
                                        <?php
                                        $encryptionStatus = $db->query("
                                            SELECT 
                                                COUNT(*) as total_records,
                                                SUM(CASE WHEN is_encrypted = 1 THEN 1 ELSE 0 END) as encrypted_records
                                            FROM sensitive_data
                                        ")->fetch(PDO::FETCH_ASSOC);
                                        $percentage = ($encryptionStatus['encrypted_records'] / $encryptionStatus['total_records']) * 100;
                                        echo round($percentage, 1) . "% of records encrypted";
                                        ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Real-time Security Events -->
                    <section class="security-section mt-4">
                        <h3>Real-time Security Events</h3>
                        <div class="row">
                            <div class="col-md-12">
                                <div class="table-responsive">
                                    <table class="table">
                                        <thead>
                                            <tr>
                                                <th>Time</th>
                                                <th>Event Type</th>
                                                <th>Details</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody id="security-events-body">
                                            <?php
                                            $events = $db->query("
                                                SELECT 
                                                    timestamp,
                                                    event_type,
                                                    details,
                                                    status
                                                FROM security_logs
                                                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                                                ORDER BY timestamp DESC
                                                LIMIT 10
                                            ")->fetchAll(PDO::FETCH_ASSOC);

                                            foreach ($events as $event) {
                                                $statusClass = '';
                                                switch (strtolower($event['status'])) {
                                                    case 'success':
                                                        $statusClass = 'text-success';
                                                        break;
                                                    case 'warning':
                                                        $statusClass = 'text-warning';
                                                        break;
                                                    case 'error':
                                                        $statusClass = 'text-danger';
                                                        break;
                                                    default:
                                                        $statusClass = 'text-info';
                                                }
                                                
                                                echo "<tr>";
                                                echo "<td>" . date('H:i:s', strtotime($event['timestamp'])) . "</td>";
                                                echo "<td>" . htmlspecialchars($event['event_type']) . "</td>";
                                                echo "<td>" . htmlspecialchars($event['details']) . "</td>";
                                                echo "<td class='{$statusClass}'>" . htmlspecialchars($event['status']) . "</td>";
                                                echo "</tr>";
                                            }
                                            ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </section>
                </div>
            </div>
            <?php endif; ?>

            <!-- Security Controls Implementation -->
            <div class="card">
                <h3>🛡️ Implemented Security Controls</h3>
                <div class="controls-grid">
                    <div class="control-item">
                        <h4>✅ Authentication Controls</h4>
                        <ul>
                            <li>Strong password policy (8+ chars, mixed case, numbers, symbols)</li>
                            <li>Account lockout after <?php echo MAX_LOGIN_ATTEMPTS; ?> failed attempts</li>
                            <li>Session timeout (<?php echo SESSION_TIMEOUT/60; ?> minutes)</li>
                            <li>Secure password hashing (bcrypt)</li>
                        </ul>
                    </div>
                    
                    <div class="control-item">
                        <h4>✅ Access Controls</h4>
                        <ul>
                            <li>Role-based access control (Admin/User)</li>
                            <li>Least privilege principle enforcement</li>
                            <li>Session management and validation</li>
                            <li>Administrative function restrictions</li>
                        </ul>
                    </div>
                    
                    <div class="control-item">
                        <h4>✅ Data Protection</h4>
                        <ul>
                            <li>Input validation and sanitization</li>
                            <li>SQL injection protection (prepared statements)</li>
                            <li>XSS protection (output encoding)</li>
                            <li>Secure data storage practices</li>
                        </ul>
                    </div>
                    
                    <div class="control-item">
                        <h4>✅ Monitoring & Logging</h4>
                        <ul>
                            <li>Comprehensive security event logging</li>
                            <li>Failed login attempt tracking</li>
                            <li>User activity monitoring</li>
                            <li>Real-time security alerting</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Policy Details Modal -->
    <div class="modal fade" id="policyDetailsModal" tabindex="-1" aria-labelledby="policyDetailsModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="policyDetailsModalLabel">Policy Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" id="policyDetailsContent">
                    <!-- Content will be loaded dynamically -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function viewPolicy(policyId) {
            // Fetch policy details using AJAX
            fetch(`get_policy_details.php?id=${policyId}`)
                .then(response => response.json())
                .then(response => {
                    if (response.error) {
                        throw new Error(response.message || response.error);
                    }
                    
                    const data = response.data;
                    const content = document.getElementById('policyDetailsContent');
                    content.innerHTML = `
                        <div class="policy-details">
                            <h4>${data.policy_name}</h4>
                            <div class="mb-3">
                                <strong>Category:</strong> ${data.category}
                            </div>
                            <div class="mb-3">
                                <strong>Status:</strong> 
                                <span class="status-badge ${data.status === 'active' ? 'status-success' : 'status-warning'}">
                                    ${data.status}
                                </span>
                            </div>
                            <div class="mb-3">
                                <strong>Last Updated:</strong> ${new Date(data.created_at).toLocaleString()}
                            </div>
                            <div class="mb-3">
                                <strong>Description:</strong>
                                <p>${data.description || 'No description available.'}</p>
                            </div>
                            <div class="mb-3">
                                <strong>Requirements:</strong>
                                <ul>
                                    ${data.requirements && data.requirements.length > 0 
                                        ? data.requirements.map(req => `<li>${req}</li>`).join('') 
                                        : '<li>No requirements specified.</li>'}
                                </ul>
                            </div>
                            <div class="mb-3">
                                <strong>Implementation Details:</strong>
                                <p>${data.implementation_details || 'No implementation details available.'}</p>
                            </div>
                        </div>
                    `;
                    
                    const modal = new bootstrap.Modal(document.getElementById('policyDetailsModal'));
                    modal.show();
                })
                .catch(error => {
                    console.error('Error fetching policy details:', error);
                    alert('Error loading policy details. Please try again.');
                });
        }

        function deleteFirewallRule(id) {
            if (confirm('Are you sure you want to delete this firewall rule?')) {
                $.post('ajax/delete_firewall_rule.php', { id: id }, function(response) {
                    location.reload();
                });
            }
        }

        function deleteWhitelistIP(id) {
            if (confirm('Are you sure you want to remove this IP from whitelist?')) {
                $.post('ajax/delete_ip_whitelist.php', { id: id }, function(response) {
                    location.reload();
                });
            }
        }

        function deleteBlacklistIP(id) {
            if (confirm('Are you sure you want to remove this IP from blacklist?')) {
                $.post('ajax/delete_ip_blacklist.php', { id: id }, function(response) {
                    location.reload();
                });
            }
        }

        function updateFileRule(id, field) {
            const value = event.target.checked ? 1 : 0;
            $.post('ajax/update_file_rule.php', {
                id: id,
                field: field,
                value: value
            }, function(response) {
                // Handle response if needed
            });
        }

        function editSSLDescription(setting_name) {
            const row = document.querySelector(`tr[data-setting="${setting_name}"]`);
            if (!row) {
                console.error('Row not found for setting:', setting_name);
                return;
            }
            const currentDescription = row.querySelector('.ssl-description').textContent;

            // Create modal content
            const content = `
                <form id="editSSLDescriptionForm">
                    <input type="hidden" name="setting_name" value="${setting_name}">
                    <div class="form-group">
                        <label>Description:</label>
                        <textarea name="description" class="form-control" required>${currentDescription}</textarea>
                    </div>
                </form>
            `;

            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('editModal'));
            document.getElementById('editModalLabel').textContent = 'Edit SSL Setting Description';
            document.getElementById('editModalBody').innerHTML = content;
            document.getElementById('editModalSave').onclick = () => saveSSLDescription(setting_name);
            modal.show();
        }

        function saveSSLDescription(setting_name) {
            const form = document.getElementById('editSSLDescriptionForm');
            const formData = new FormData(form);

            $.ajax({
                url: 'admin/ajax/update_ssl_description.php',
                method: 'POST',
                data: {
                    setting_name: setting_name,
                    description: formData.get('description')
                },
                success: function(response) {
                    const row = document.querySelector(`tr[data-setting="${setting_name}"]`);
                    if (row) {
                        row.querySelector('.ssl-description').textContent = formData.get('description');
                    }
                    const modal = bootstrap.Modal.getInstance(document.getElementById('editModal'));
                    modal.hide();
                },
                error: function(xhr, status, error) {
                    alert('Failed to update description: ' + error);
                }
            });
        }

        function editFileRule(id) {
            const row = document.getElementById('file-rule-' + id);
            const fileType = row.cells[0].textContent;
            const maxSize = row.cells[1].textContent;
            const isAllowed = row.cells[2].querySelector('input').checked;
            const scanMalware = row.cells[3].querySelector('input').checked;
            const requireEncryption = row.cells[4].querySelector('input').checked;

            // Create modal content
            const content = `
                <form id="editFileRuleForm">
                    <input type="hidden" name="id" value="${id}">
                    <div class="form-group">
                        <label>File Type:</label>
                        <input type="text" name="file_type" class="form-control" value="${fileType}" required>
                    </div>
                    <div class="form-group">
                        <label>Max Size (MB):</label>
                        <input type="number" name="max_size" class="form-control" value="${maxSize}" required>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="is_allowed" class="form-check-input" ${isAllowed ? 'checked' : ''}>
                        <label class="form-check-label">Allowed</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="scan_for_malware" class="form-check-input" ${scanMalware ? 'checked' : ''}>
                        <label class="form-check-label">Scan for Malware</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="require_encryption" class="form-check-input" ${requireEncryption ? 'checked' : ''}>
                        <label class="form-check-label">Require Encryption</label>
                    </div>
                </form>
            `;

            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('editModal'));
            document.getElementById('editModalLabel').textContent = 'Edit File Rule';
            document.getElementById('editModalBody').innerHTML = content;
            document.getElementById('editModalSave').onclick = () => saveFileRule(id);
            modal.show();
        }

        function addNewFileRule() {
            // Create modal content for new file rule
            const content = `
                <form id="editFileRuleForm">
                    <div class="form-group">
                        <label>File Type:</label>
                        <input type="text" name="file_type" class="form-control" placeholder="e.g., application/pdf" required>
                    </div>
                    <div class="form-group">
                        <label>Max Size (MB):</label>
                        <input type="number" name="max_size" class="form-control" value="5" required>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="is_allowed" class="form-check-input" checked>
                        <label class="form-check-label">Allowed</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="scan_for_malware" class="form-check-input" checked>
                        <label class="form-check-label">Scan for Malware</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" name="require_encryption" class="form-check-input">
                        <label class="form-check-label">Require Encryption</label>
                    </div>
                </form>
            `;

            // Show modal
            const modal = new bootstrap.Modal(document.getElementById('editModal'));
            document.getElementById('editModalLabel').textContent = 'Add New File Rule';
            document.getElementById('editModalBody').innerHTML = content;
            document.getElementById('editModalSave').onclick = saveNewFileRule;
            modal.show();
        }

        function saveFileRule(id) {
            const form = document.getElementById('editFileRuleForm');
            const formData = new FormData(form);

            $.ajax({
                url: 'admin/ajax/edit_file_rule.php',
                method: 'POST',
                data: {
                    id: id,
                    file_type: formData.get('file_type'),
                    max_size: formData.get('max_size'),
                    is_allowed: formData.get('is_allowed') ? 1 : 0,
                    scan_for_malware: formData.get('scan_for_malware') ? 1 : 0,
                    require_encryption: formData.get('require_encryption') ? 1 : 0
                },
                success: function(response) {
                    try {
                        const result = JSON.parse(response);
                        if (result.success) {
                            // Update the row in the table without reloading
                            const row = document.getElementById('file-rule-' + id);
                            row.cells[0].textContent = formData.get('file_type');
                            row.cells[1].textContent = formData.get('max_size');
                            row.cells[2].querySelector('input').checked = formData.get('is_allowed') ? true : false;
                            row.cells[3].querySelector('input').checked = formData.get('scan_for_malware') ? true : false;
                            row.cells[4].querySelector('input').checked = formData.get('require_encryption') ? true : false;
                            
                            // Close the modal
                            const modal = bootstrap.Modal.getInstance(document.getElementById('editModal'));
                            modal.hide();
                            
                            // Show success message
                            alert('File rule updated successfully!');
                        } else {
                            alert('Failed to update file rule: ' + (result.message || 'Unknown error'));
                        }
                    } catch (e) {
                        alert('Failed to parse server response');
                    }
                },
                error: function(xhr, status, error) {
                    alert('Failed to update file rule: ' + error);
                }
            });

            // Prevent form submission
            return false;
        }

        function saveNewFileRule() {
            const form = document.getElementById('editFileRuleForm');
            const formData = new FormData(form);

            $.ajax({
                url: 'admin/ajax/add_file_rule.php',
                method: 'POST',
                data: {
                    file_type: formData.get('file_type'),
                    max_size: formData.get('max_size'),
                    is_allowed: formData.get('is_allowed') ? 1 : 0,
                    scan_for_malware: formData.get('scan_for_malware') ? 1 : 0,
                    require_encryption: formData.get('require_encryption') ? 1 : 0
                },
                success: function(response) {
                    try {
                        const result = JSON.parse(response);
                        if (result.success) {
                            // Refresh only the table content
                            $('#fileRulesTable').load(window.location.href + ' #fileRulesTable > *');
                            
                            // Close the modal
                            const modal = bootstrap.Modal.getInstance(document.getElementById('editModal'));
                            modal.hide();
                            
                            // Show success message
                            alert('New file rule added successfully!');
                        } else {
                            alert('Failed to add file rule: ' + (result.message || 'Unknown error'));
                        }
                    } catch (e) {
                        alert('Failed to parse server response');
                    }
                },
                error: function(xhr, status, error) {
                    alert('Failed to add file rule: ' + error);
                }
            });

            // Prevent form submission
            return false;
        }

        // Add form submit handlers
        $(document).ready(function() {
            // Prevent default form submissions
            $(document).on('submit', '#editFileRuleForm', function(e) {
                e.preventDefault();
                return false;
            });

            // Update the onclick handler for the save button
            $('#editModalSave').click(function(e) {
                e.preventDefault();
                const form = document.getElementById('editFileRuleForm');
                const id = form.querySelector('input[name="id"]')?.value;
                if (id) {
                    saveFileRule(id);
                } else {
                    saveNewFileRule();
                }
            });
        });

        function updateSSLSetting(setting_name, value) {
            $.ajax({
                url: 'admin/ajax/update_ssl_setting.php',
                method: 'POST',
                data: {
                    setting_name: setting_name,
                    value: value
                },
                success: function(response) {
                    // Show success message
                    alert('SSL setting updated successfully');
                },
                error: function(xhr, status, error) {
                    alert('Failed to update SSL setting: ' + error);
                }
            });
        }

        function deleteFileRule(id) {
            if (confirm('Are you sure you want to delete this file rule?')) {
                $.ajax({
                    url: 'admin/ajax/delete_file_rule.php',
                    method: 'POST',
                    data: { id: id },
                    success: function(response) {
                        location.reload();
                    },
                    error: function(xhr, status, error) {
                        alert('Failed to delete file rule: ' + error);
                    }
                });
            }
        }
    </script>

    <!-- Add Modal for Editing -->
    <div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="editModalLabel">Edit</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body" id="editModalBody">
                    <!-- Content will be dynamically added -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" id="editModalSave">Save changes</button>
                </div>
            </div>
        </div>
    </div>
</body>
</html> 
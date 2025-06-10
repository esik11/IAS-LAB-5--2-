<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';
require_once 'includes/SecurityAudit.php';

session_start();

$db = Database::getInstance();
$security = new Security();
$securityAudit = new SecurityAudit();

// Check if user is logged in and is admin
if (!$security->validateSession() || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

// Handle compliance assessment request
if (isset($_POST['action']) && $_POST['action'] === 'run_assessment') {
    $assessment_result = $securityAudit->runComplianceAssessment();
    $security->logSecurityEvent($_SESSION['user_id'], 'compliance_assessment', 'Compliance assessment completed');
}

// Get compliance statistics
$stats = [
    'overall_score' => $securityAudit->calculateOverallComplianceScore(),
    'total_reports' => $db->query("SELECT COUNT(*) FROM compliance_audits WHERE DATE(audit_date) >= DATE_SUB(NOW(), INTERVAL 30 DAY)")->fetchColumn(),
    'active_violations' => $db->query("SELECT COUNT(*) FROM compliance_violations WHERE status = 'open'")->fetchColumn(),
    'pending_remediation' => $db->query("SELECT COUNT(*) FROM compliance_violations WHERE status = 'remediation'")->fetchColumn()
];

// Get recent compliance reports
$reports = $db->query(
    "SELECT * FROM compliance_audits 
     ORDER BY audit_date DESC 
     LIMIT 10"
)->fetchAll(PDO::FETCH_ASSOC);

// Get active violations
$violations = $db->query(
    "SELECT v.*, f.name as framework_name 
     FROM compliance_violations v
     LEFT JOIN compliance_frameworks f ON v.framework_id = f.id
     WHERE v.status = 'open'
     ORDER BY v.severity DESC"
)->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Management - Security System</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .score-card {
            color: #28a745;
        }
        .reports-card {
            color: #17a2b8;
        }
        .violations-card {
            color: #dc3545;
        }
        .pending-card {
            color: #ffc107;
        }
        .big-number {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .status-completed {
            background: #28a745;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .severity-high {
            background: #dc3545;
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .severity-medium {
            background: #ffc107;
            color: black;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .action-button {
            padding: 8px 16px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
        }
        .remediate-button {
            background: #007bff;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Compliance Management</h1>
            <div class="actions">
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="run_assessment">
                    <button type="submit" class="btn btn-primary">🔍 Run Assessment</button>
                </form>
                <button onclick="generateReport()" class="btn">📄 Generate Report</button>
            </div>
        </header>

        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card score-card">
                <h3>Overall Score</h3>
                <div class="big-number"><?php echo round($stats['overall_score']); ?>%</div>
                <div>Compliance rating</div>
            </div>
            
            <div class="stat-card reports-card">
                <h3>Total Reports</h3>
                <div class="big-number"><?php echo $stats['total_reports']; ?></div>
                <div>Generated reports</div>
            </div>
            
            <div class="stat-card violations-card">
                <h3>Active Violations</h3>
                <div class="big-number"><?php echo $stats['active_violations']; ?></div>
                <div>Need attention</div>
            </div>
            
            <div class="stat-card pending-card">
                <h3>Pending Remediation</h3>
                <div class="big-number"><?php echo $stats['pending_remediation']; ?></div>
                <div>In progress</div>
            </div>
        </div>

        <div class="content-grid">
            <!-- Recent Compliance Reports -->
            <div class="card">
                <div class="card-header">
                    <h2>Recent Compliance Reports</h2>
                    <button onclick="newReport()" class="btn btn-small">+ New Report</button>
                </div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Report Title</th>
                            <th>Status</th>
                            <th>Score</th>
                            <th>Generated</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($reports as $report): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($report['title']); ?></td>
                            <td><span class="status-completed">Completed</span></td>
                            <td><?php echo $report['compliance_score']; ?>%</td>
                            <td><?php echo date('M d, Y H:i', strtotime($report['audit_date'])); ?></td>
                            <td>
                                <button onclick="viewReport(<?php echo $report['id']; ?>)" class="action-button">👁️</button>
                                <button onclick="downloadReport(<?php echo $report['id']; ?>)" class="action-button">⬇️</button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Active Violations -->
            <div class="card">
                <h2>Active Violations</h2>
                <div class="violations-list">
                    <?php foreach ($violations as $violation): ?>
                    <div class="violation-item">
                        <div class="violation-header">
                            <h3><?php echo htmlspecialchars($violation['title']); ?></h3>
                            <span class="severity-<?php echo strtolower($violation['severity']); ?>">
                                <?php echo ucfirst($violation['severity']); ?>
                            </span>
                        </div>
                        <div class="violation-details">
                            <p>Framework: <?php echo htmlspecialchars($violation['framework_name']); ?></p>
                            <button class="action-button remediate-button">Remediate</button>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>

    <script>
    function newReport() {
        // Implement new report creation
    }

    function viewReport(id) {
        // Implement report viewing
    }

    function downloadReport(id) {
        // Implement report download
    }

    function generateReport() {
        // Implement report generation
    }
    </script>
</body>
</html> 
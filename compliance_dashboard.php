<?php
require_once 'config/config.php';
require_once 'includes/auth.php';
require_once 'includes/Database.php';
require_once 'includes/ComplianceManager.php';
require_once 'includes/SecurityAudit.php';

// Ensure user is logged in and is admin
if (!isLoggedIn() || !isAdmin()) {
    header('Location: login.php');
    exit();
}

$db = Database::getInstance();
$complianceManager = new ComplianceManager($db);
$securityAudit = new SecurityAudit();

// Handle compliance check request
if (isset($_POST['action']) && $_POST['action'] === 'run_check' && isset($_POST['policy_id'])) {
    $report = $complianceManager->generateComplianceReport($_POST['policy_id']);
    $message = "Compliance check completed. Score: {$report['score']}%";
}

// Get overall compliance score
$sql = "SELECT AVG(compliance_score) as avg_score FROM compliance_checks 
        WHERE check_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
$result = $db->query($sql);
$overall_score = round($result->fetch(PDO::FETCH_ASSOC)['avg_score'] ?? 0, 2);

// Get policy compliance status
$sql = "SELECT 
            p.id as policy_id,
            p.policy_name,
            c.compliance_score,
            c.status,
            c.check_date,
            c.findings,
            c.recommendations
        FROM security_policies p
        LEFT JOIN compliance_checks c ON p.id = c.policy_id
        WHERE c.check_date = (
            SELECT MAX(check_date) 
            FROM compliance_checks 
            WHERE policy_id = p.id
        )
        ORDER BY c.check_date DESC";
$policies = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);

// Get recent violations
$sql = "SELECT 
            p.policy_name,
            v.severity,
            v.description,
            v.detected_date as violation_date,
            v.status as resolution_status
        FROM compliance_violations v
        JOIN compliance_frameworks f ON v.framework_id = f.id
        JOIN security_policies p ON p.category = 'compliance'
        ORDER BY v.detected_date DESC
        LIMIT 5";
$violations = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);

// Get upcoming audits
$sql = "SELECT 
            p.policy_name,
            a.frequency,
            a.next_audit_date,
            a.status
        FROM audit_schedules a
        JOIN security_policies p ON a.policy_id = p.id
        WHERE a.next_audit_date >= CURDATE()
        ORDER BY a.next_audit_date ASC
        LIMIT 5";
$upcoming_audits = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container mt-4">
        <h1>Compliance Dashboard</h1>
        
        <?php if (isset($message)): ?>
        <div class="alert alert-success">
            <?php echo htmlspecialchars($message); ?>
        </div>
        <?php endif; ?>

        <!-- Overall Compliance Score -->
        <div class="row mt-4">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body text-center">
                        <h5 class="card-title">Overall Compliance Score</h5>
                        <div class="display-4 <?php echo $overall_score >= 80 ? 'text-success' : ($overall_score >= 60 ? 'text-warning' : 'text-danger'); ?>">
                            <?php echo $overall_score; ?>%
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Quick Stats -->
            <div class="col-md-8">
                <div class="row">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">Compliant Policies</h6>
                                <div class="h3"><?php echo count(array_filter($policies, function($p) { return $p['status'] === 'compliant'; })); ?></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">Open Violations</h6>
                                <div class="h3"><?php echo count(array_filter($violations, function($v) { return $v['resolution_status'] === 'open'; })); ?></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body">
                                <h6 class="card-title">Pending Audits</h6>
                                <div class="h3"><?php echo count($upcoming_audits); ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Policy Compliance Table -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">Policy Compliance Status</h5>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Policy</th>
                            <th>Score</th>
                            <th>Status</th>
                            <th>Last Check</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($policies as $policy): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($policy['policy_name']); ?></td>
                            <td>
                                <?php if (isset($policy['compliance_score'])): ?>
                                <div class="progress">
                                    <div class="progress-bar <?php echo $policy['compliance_score'] >= 80 ? 'bg-success' : ($policy['compliance_score'] >= 60 ? 'bg-warning' : 'bg-danger'); ?>" 
                                         role="progressbar" 
                                         style="width: <?php echo $policy['compliance_score']; ?>%">
                                        <?php echo $policy['compliance_score']; ?>%
                                    </div>
                                </div>
                                <?php else: ?>
                                Not checked
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (isset($policy['status'])): ?>
                                <span class="badge <?php echo $policy['status'] === 'compliant' ? 'bg-success' : ($policy['status'] === 'partially_compliant' ? 'bg-warning' : 'bg-danger'); ?>">
                                    <?php echo ucfirst(str_replace('_', ' ', $policy['status'])); ?>
                                </span>
                                <?php else: ?>
                                Not checked
                                <?php endif; ?>
                            </td>
                            <td><?php echo isset($policy['check_date']) ? date('Y-m-d H:i', strtotime($policy['check_date'])) : 'Never'; ?></td>
                            <td>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="action" value="run_check">
                                    <input type="hidden" name="policy_id" value="<?php echo $policy['policy_id']; ?>">
                                    <button type="submit" class="btn btn-primary btn-sm">Run Check</button>
                                </form>
                                <?php if (isset($policy['findings']) || isset($policy['recommendations'])): ?>
                                <button class="btn btn-info btn-sm" onclick="viewDetails(<?php echo htmlspecialchars(json_encode($policy)); ?>)">Details</button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Violations -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">Recent Policy Violations</h5>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Policy</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th>Date</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($violations as $violation): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($violation['policy_name']); ?></td>
                            <td>
                                <span class="badge <?php echo $violation['severity'] === 'critical' ? 'bg-danger' : ($violation['severity'] === 'high' ? 'bg-warning' : 'bg-info'); ?>">
                                    <?php echo ucfirst($violation['severity']); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($violation['description']); ?></td>
                            <td><?php echo date('Y-m-d H:i', strtotime($violation['violation_date'])); ?></td>
                            <td><?php echo ucfirst($violation['resolution_status']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Upcoming Audits -->
        <div class="card mt-4 mb-4">
            <div class="card-header">
                <h5 class="mb-0">Upcoming Audits</h5>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Policy</th>
                            <th>Frequency</th>
                            <th>Next Audit Date</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($upcoming_audits as $audit): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($audit['policy_name']); ?></td>
                            <td><?php echo ucfirst($audit['frequency']); ?></td>
                            <td><?php echo date('Y-m-d', strtotime($audit['next_audit_date'])); ?></td>
                            <td>
                                <span class="badge <?php echo $audit['status'] === 'scheduled' ? 'bg-info' : ($audit['status'] === 'in_progress' ? 'bg-warning' : 'bg-success'); ?>">
                                    <?php echo ucfirst($audit['status']); ?>
                                </span>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-primary" onclick="scheduleAudit(<?php echo htmlspecialchars(json_encode($audit)); ?>)">Schedule</button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Details Modal -->
    <div class="modal fade" id="detailsModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Compliance Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="findingsContainer"></div>
                    <div id="recommendationsContainer" class="mt-3"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function viewDetails(policy) {
            const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
            document.getElementById('findingsContainer').innerHTML = `
                <h6>Findings:</h6>
                <pre>${policy.findings}</pre>
            `;
            document.getElementById('recommendationsContainer').innerHTML = `
                <h6>Recommendations:</h6>
                <pre>${policy.recommendations}</pre>
            `;
            modal.show();
        }

        function scheduleAudit(audit) {
            // Implement audit scheduling functionality
            alert('Audit scheduling will be implemented here');
        }
    </script>
</body>
</html> 
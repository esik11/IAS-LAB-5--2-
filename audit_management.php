<?php
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/ComplianceManager.php';

// Ensure user is logged in and is admin
if (!isLoggedIn() || !isAdmin()) {
    header('Location: login.php');
    exit();
}

$db = new Database();
$complianceManager = new ComplianceManager($db);

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['schedule_audit'])) {
        $policyId = $_POST['policy_id'];
        $frequency = $_POST['frequency'];
        $complianceManager->scheduleAudit($policyId, $frequency);
        header('Location: audit_management.php?success=scheduled');
        exit();
    }
    
    if (isset($_POST['conduct_audit'])) {
        $policyId = $_POST['policy_id'];
        $report = $complianceManager->generateComplianceReport($policyId);
        
        // Update audit status
        $sql = "UPDATE audit_schedules SET 
                status = 'completed',
                last_audit_date = NOW()
                WHERE policy_id = ?";
        $db->query($sql, [$policyId]);
        
        header('Location: audit_management.php?success=completed');
        exit();
    }
}

// Get all policies
$sql = "SELECT id, policy_name FROM security_policies";
$policies = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);

// Get scheduled audits
$sql = "SELECT 
            a.*,
            p.policy_name,
            c.compliance_score as last_score,
            c.status as last_status
        FROM audit_schedules a
        JOIN security_policies p ON a.policy_id = p.id
        LEFT JOIN compliance_checks c ON p.id = c.policy_id
        WHERE c.check_date = (
            SELECT MAX(check_date)
            FROM compliance_checks
            WHERE policy_id = p.id
        )
        ORDER BY a.next_audit_date ASC";
$scheduled_audits = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container mt-4">
        <h1>Audit Management</h1>
        
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <?php echo $_GET['success'] === 'scheduled' ? 'Audit has been scheduled successfully.' : 'Audit has been completed successfully.'; ?>
            </div>
        <?php endif; ?>
        
        <!-- Schedule New Audit -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">Schedule New Audit</h5>
            </div>
            <div class="card-body">
                <form method="POST" class="row g-3">
                    <div class="col-md-4">
                        <label for="policy_id" class="form-label">Policy</label>
                        <select name="policy_id" id="policy_id" class="form-select" required>
                            <option value="">Select Policy</option>
                            <?php foreach ($policies as $policy): ?>
                                <option value="<?php echo $policy['id']; ?>">
                                    <?php echo htmlspecialchars($policy['policy_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label for="frequency" class="form-label">Frequency</label>
                        <select name="frequency" id="frequency" class="form-select" required>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly" selected>Monthly</option>
                            <option value="quarterly">Quarterly</option>
                            <option value="annually">Annually</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" name="schedule_audit" class="btn btn-primary d-block">Schedule Audit</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Scheduled Audits -->
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">Scheduled Audits</h5>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Policy</th>
                            <th>Frequency</th>
                            <th>Next Audit</th>
                            <th>Last Score</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($scheduled_audits as $audit): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($audit['policy_name']); ?></td>
                                <td><?php echo ucfirst($audit['frequency']); ?></td>
                                <td>
                                    <?php 
                                    $next_date = new DateTime($audit['next_audit_date']);
                                    $now = new DateTime();
                                    $interval = $next_date->diff($now);
                                    
                                    if ($next_date < $now) {
                                        echo '<span class="text-danger">Overdue by ' . $interval->days . ' days</span>';
                                    } else {
                                        echo 'In ' . $interval->days . ' days';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php if ($audit['last_score']): ?>
                                        <div class="progress">
                                            <div class="progress-bar <?php echo $audit['last_score'] >= 80 ? 'bg-success' : ($audit['last_score'] >= 60 ? 'bg-warning' : 'bg-danger'); ?>" 
                                                 role="progressbar" 
                                                 style="width: <?php echo $audit['last_score']; ?>%">
                                                <?php echo $audit['last_score']; ?>%
                                            </div>
                                        </div>
                                    <?php else: ?>
                                        <span class="text-muted">No previous audit</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge <?php echo $audit['status'] === 'scheduled' ? 'bg-info' : ($audit['status'] === 'in_progress' ? 'bg-warning' : 'bg-success'); ?>">
                                        <?php echo ucfirst($audit['status']); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($audit['status'] !== 'completed'): ?>
                                        <form method="POST" class="d-inline">
                                            <input type="hidden" name="policy_id" value="<?php echo $audit['policy_id']; ?>">
                                            <button type="submit" name="conduct_audit" class="btn btn-sm btn-primary">
                                                Conduct Audit
                                            </button>
                                        </form>
                                    <?php endif; ?>
                                    <button type="button" class="btn btn-sm btn-info" onclick="viewHistory(<?php echo $audit['policy_id']; ?>)">
                                        View History
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Audit History Modal -->
    <div class="modal fade" id="historyModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Audit History</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="auditHistory"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function viewHistory(policyId) {
            // Fetch audit history via AJAX
            $.get('ajax/get_audit_history.php', { policy_id: policyId }, function(data) {
                const modal = new bootstrap.Modal(document.getElementById('historyModal'));
                document.getElementById('auditHistory').innerHTML = data;
                modal.show();
            });
        }
    </script>
</body>
</html> 
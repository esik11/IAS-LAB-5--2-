<?php
require_once '../includes/auth.php';
require_once '../includes/db.php';

// Ensure user is logged in and is admin
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403);
    exit('Unauthorized');
}

if (!isset($_GET['policy_id'])) {
    http_response_code(400);
    exit('Missing policy ID');
}

$db = new Database();

// Get audit history
$sql = "SELECT 
            c.*,
            u.username as reviewer_name
        FROM compliance_checks c
        LEFT JOIN users u ON c.reviewed_by = u.id
        WHERE c.policy_id = ?
        ORDER BY c.check_date DESC";

$history = $db->query($sql, [$_GET['policy_id']])->fetchAll(PDO::FETCH_ASSOC);

if (empty($history)) {
    echo '<div class="alert alert-info">No audit history available for this policy.</div>';
    exit();
}
?>

<div class="table-responsive">
    <table class="table">
        <thead>
            <tr>
                <th>Date</th>
                <th>Score</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Recommendations</th>
                <th>Reviewed By</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($history as $check): ?>
                <tr>
                    <td><?php echo date('Y-m-d H:i', strtotime($check['check_date'])); ?></td>
                    <td>
                        <div class="progress">
                            <div class="progress-bar <?php echo $check['compliance_score'] >= 80 ? 'bg-success' : ($check['compliance_score'] >= 60 ? 'bg-warning' : 'bg-danger'); ?>" 
                                 role="progressbar" 
                                 style="width: <?php echo $check['compliance_score']; ?>%">
                                <?php echo $check['compliance_score']; ?>%
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="badge <?php echo $check['status'] === 'compliant' ? 'bg-success' : ($check['status'] === 'partially_compliant' ? 'bg-warning' : 'bg-danger'); ?>">
                            <?php echo ucfirst(str_replace('_', ' ', $check['status'])); ?>
                        </span>
                    </td>
                    <td>
                        <?php 
                        $findings = json_decode($check['findings'], true);
                        if (!empty($findings)):
                        ?>
                            <ul class="list-unstyled mb-0">
                                <?php foreach ($findings as $finding): ?>
                                    <li>• <?php echo htmlspecialchars($finding); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <span class="text-muted">No findings</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php 
                        $recommendations = json_decode($check['recommendations'], true);
                        if (!empty($recommendations)):
                        ?>
                            <ul class="list-unstyled mb-0">
                                <?php foreach ($recommendations as $recommendation): ?>
                                    <li>• <?php echo htmlspecialchars($recommendation); ?></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <span class="text-muted">No recommendations</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $check['reviewer_name'] ?? 'System'; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="mt-3">
    <h6>Compliance Score Trend</h6>
    <canvas id="scoreChart"></canvas>
</div>

<script>
// Create compliance score trend chart
const ctx = document.getElementById('scoreChart').getContext('2d');
const scores = <?php echo json_encode(array_map(function($check) {
    return [
        'date' => date('Y-m-d', strtotime($check['check_date'])),
        'score' => $check['compliance_score']
    ];
}, array_reverse($history))); ?>;

new Chart(ctx, {
    type: 'line',
    data: {
        labels: scores.map(s => s.date),
        datasets: [{
            label: 'Compliance Score',
            data: scores.map(s => s.score),
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});
</script> 
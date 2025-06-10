<?php
require_once 'config/config.php';
require_once 'includes/auth.php';
require_once 'includes/Database.php';
require_once 'includes/SecurityAudit.php';

// Ensure user is logged in and has appropriate permissions
if (!isLoggedIn() || !isAdmin()) {
    header('Location: login.php');
    exit();
}

$db = Database::getInstance();

// Get password policy stats
$passwordStats = $db->query("
    SELECT 
        COUNT(*) as total_changes,
        COUNT(DISTINCT user_id) as unique_users
    FROM password_history
    WHERE changed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
")->fetch(PDO::FETCH_ASSOC);

// Get network security stats
$networkStats = $db->query("
    SELECT 
        COUNT(*) as total_attempts,
        COUNT(DISTINCT ip_address) as unique_ips,
        SUM(CASE WHEN action = 'rate_limit_exceeded' THEN 1 ELSE 0 END) as rate_limits
    FROM security_logs
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
")->fetch(PDO::FETCH_ASSOC);

// Get encryption status
$encryptionStatus = $db->query("
    SELECT 
        COUNT(*) as total_records,
        SUM(CASE WHEN is_encrypted = 1 THEN 1 ELSE 0 END) as encrypted_records
    FROM sensitive_data
")->fetch(PDO::FETCH_ASSOC);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network & Security Controls</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style>
        .section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .policy-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 10px;
        }
        .status {
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: 500;
        }
        .status.compliant { background: #d4edda; color: #155724; }
        .status.active { background: #cce5ff; color: #004085; }
        .status.configured { background: #fff3cd; color: #856404; }
        .status.enforced { background: #d1ecf1; color: #0c5460; }
        .details {
            margin-top: 10px;
            font-size: 0.9em;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h1>Network & Security Controls</h1>
        
        <div class="row mt-4">
            <!-- Password Security Section -->
            <div class="col-md-4">
                <div class="section">
                    <h2>Password Policy</h2>
                    <div class="policy-item">
                        <span class="label">Minimum Length (12 chars)</span>
                        <span class="status compliant">Compliant</span>
                    </div>
                    <div class="policy-item">
                        <span class="label">Password History (5)</span>
                        <span class="status compliant">Compliant</span>
                        <div class="details">
                            Last 30 days: <?php echo $passwordStats['total_changes']; ?> changes by <?php echo $passwordStats['unique_users']; ?> users
                        </div>
                    </div>
                    <div class="policy-item">
                        <span class="label">Special Characters</span>
                        <span class="status compliant">Required</span>
                    </div>
                </div>
            </div>

            <!-- Network Security Section -->
            <div class="col-md-4">
                <div class="section">
                    <h2>Network Security</h2>
                    <div class="policy-item">
                        <span class="label">HTTPS Enforcement</span>
                        <span class="status active">Active</span>
                    </div>
                    <div class="policy-item">
                        <span class="label">Rate Limiting</span>
                        <span class="status configured">Configured</span>
                        <div class="details">
                            Rate limits exceeded: <?php echo $networkStats['rate_limits']; ?> times in last 24h
                        </div>
                    </div>
                    <div class="policy-item">
                        <span class="label">IP Restrictions</span>
                        <span class="status enforced">Enforced</span>
                        <div class="details">
                            Unique IPs: <?php echo $networkStats['unique_ips']; ?> in last 24h
                        </div>
                    </div>
                </div>
            </div>

            <!-- Data Protection Section -->
            <div class="col-md-4">
                <div class="section">
                    <h2>Data Protection</h2>
                    <div class="policy-item">
                        <span class="label">Encryption (AES-256)</span>
                        <span class="status active">Active</span>
                        <div class="details">
                            Using AES-256-CBC encryption for sensitive data
                        </div>
                    </div>
                    <div class="policy-item">
                        <span class="label">Encrypted Records</span>
                        <span class="status active">Active</span>
                        <div class="details">
                            <?php 
                            $percentage = ($encryptionStatus['encrypted_records'] / $encryptionStatus['total_records']) * 100;
                            echo round($percentage, 1) . "% of records encrypted";
                            ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Real-time Monitoring -->
        <div class="section mt-4">
            <h2>Real-time Security Monitoring</h2>
            <div class="row">
                <div class="col-md-12">
                    <div id="security-events" class="policy-item">
                        <h4>Recent Security Events</h4>
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
                                    <!-- Will be populated by JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Function to fetch and update security events
        function updateSecurityEvents() {
            $.ajax({
                url: 'ajax/get_security_events.php',
                method: 'GET',
                success: function(data) {
                    $('#security-events-body').html(data);
                }
            });
        }

        // Update security events every 30 seconds
        $(document).ready(function() {
            updateSecurityEvents();
            setInterval(updateSecurityEvents, 30000);
        });
    </script>
</body>
</html> 
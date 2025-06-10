<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';
require_once 'includes/SecurityAudit.php';

session_start();

$db = Database::getInstance();
$security = new Security();
$audit = new SecurityAudit();

// Check if user is logged in
if (!$security->validateSession()) {
    header('Location: login.php');
    exit;
}

// Handle Generate Audit Report action
if (isset($_POST['generate_audit'])) {
    $security->logSecurityEvent($_SESSION['user_id'], 'audit_generated', 'Security audit report generated');
    // Prevent form resubmission
    header('Location: audit_report.php?generated=1');
    exit;
}

// Handle Download PDF action
if (isset($_POST['download_pdf'])) {
    $pdfContent = $audit->generatePDFReport();
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="Security_Audit_Report_' . date('Y-m-d') . '.pdf"');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');
    echo $pdfContent;
    exit;
}

// Get audit statistics
$weak_passwords = $audit->checkWeakPasswords();
$recent_incidents = $audit->getRecentIncidents(30); // Last 30 days
$failed_logins = $audit->getFailedLoginAttempts(24); // Last 24 hours

// Show success message if report was generated
$report_generated = isset($_GET['generated']) && $_GET['generated'] == 1;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Audit - Security System</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .nav-tabs {
            border-bottom: 1px solid #dee2e6;
            margin-bottom: 20px;
        }
        .nav-tabs a {
            display: inline-block;
            padding: 10px 20px;
            text-decoration: none;
            color: #495057;
        }
        .nav-tabs a.active {
            color: #007bff;
            border-bottom: 2px solid #007bff;
        }
        .audit-section {
            margin: 20px 0;
        }
        .audit-result {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .audit-label {
            font-weight: bold;
            color: #333;
            margin-right: 10px;
        }
        .audit-value {
            color: #28a745;
        }
        .audit-value.warning {
            color: #dc3545;
        }
        .generate-btn {
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .generate-btn:hover {
            background: #218838;
        }
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: none;
        }
        .success-message.show {
            display: block;
        }
        .button-group {
            margin-bottom: 20px;
        }
        .download-btn {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 10px;
        }
        .download-btn:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <a href="index.php?page=incidents">Security Incidents</a>
            <a href="index.php?page=logs">Security Logs</a>
            <a href="index.php?page=policies">Security Policies</a>
            <a href="audit_report.php" class="active">Compliance Audit</a>
        </div>

        <h1>Security Compliance Audit</h1>

        <?php if ($report_generated): ?>
        <div class="success-message show">
            Audit report generated successfully!
        </div>
        <?php endif; ?>

        <!-- Generate Report and Download Buttons -->
        <div class="button-group">
            <form method="POST" style="display: inline-block;">
                <button type="submit" name="generate_audit" class="generate-btn">Generate Audit Report</button>
            </form>
            <form method="POST" style="display: inline-block;">
                <button type="submit" name="download_pdf" class="download-btn">Download as PDF</button>
            </form>
        </div>

        <!-- Audit Results -->
        <div class="audit-results">
            <h2>Audit Results</h2>

            <!-- Password Policy -->
            <div class="audit-section">
                <div class="audit-result">
                    <span class="audit-label">Password Policy:</span>
                    <span class="audit-value <?php echo $weak_passwords > 0 ? 'warning' : ''; ?>">
                        <?php echo $weak_passwords; ?> users have weak passwords
                    </span>
                </div>
            </div>

            <!-- Security Incidents -->
            <div class="audit-section">
                <div class="audit-result">
                    <span class="audit-label">Security Incidents:</span>
                    <span class="audit-value <?php echo $recent_incidents > 0 ? 'warning' : ''; ?>">
                        <?php echo $recent_incidents; ?> security incidents in last 30 days
                    </span>
                </div>
            </div>

            <!-- Login Attempts -->
            <div class="audit-section">
                <div class="audit-result">
                    <span class="audit-label">Login Attempts:</span>
                    <span class="audit-value <?php echo $failed_logins > 0 ? 'warning' : ''; ?>">
                        <?php echo $failed_logins; ?> failed login attempts in last 24 hours
                    </span>
                </div>
            </div>
        </div>
    </div>
</body>
</html> 
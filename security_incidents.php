<?php
// Include configuration and required files
require_once 'config/config.php';
require_once 'includes/Database.php';

// Initialize database connection
$db = Database::getInstance();

// Handle PDF Download
if (isset($_POST['download_incidents_pdf'])) {
    require_once 'includes/SecurityAudit.php';
    $audit = new SecurityAudit($db);
    $pdfContent = $audit->generateSecurityIncidentsPDF();
    
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="Security_Incidents_Report_' . date('Y-m-d') . '.pdf"');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');
    echo $pdfContent;
    exit;
}

// Handle single incident PDF download
if (isset($_POST['download_incidents_pdf']) && isset($_POST['incident_id'])) {
    require_once 'includes/SecurityAudit.php';
    $audit = new SecurityAudit($db);
    $pdfContent = $audit->generateSingleIncidentPDF($_POST['incident_id']);
    
    if ($pdfContent) {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="Security_Incident_Report_' . $_POST['incident_id'] . '_' . date('Y-m-d') . '.pdf"');
        header('Cache-Control: private, max-age=0, must-revalidate');
        header('Pragma: public');
        echo $pdfContent;
        exit;
    } else {
        // Handle error - incident not found
        header('Location: index.php?error=incident_not_found');
        exit;
    }
}

// ... existing code ...

// Add this where you want the download button to appear
echo '<form method="post" style="display: inline-block; margin: 10px;">
    <button type="submit" name="download_incidents_pdf" class="btn btn-primary">
        <i class="fas fa-file-pdf"></i> Download as PDF
    </button>
</form>'; 
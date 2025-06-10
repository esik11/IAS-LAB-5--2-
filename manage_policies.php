<?php
require_once 'config/config.php';
require_once 'includes/Database.php';
require_once 'includes/Security.php';

session_start();

$db = Database::getInstance();
$security = new Security();

// Check if user is logged in and is admin
if (!$security->validateSession() || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

// Handle policy actions
if (isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'add_policy':
            $db->query("CALL add_security_policy(?, ?, ?, ?, ?, ?)", [
                $_POST['policy_name'],
                $_POST['description'],
                $_POST['category'],
                $_POST['requirements'],
                $_POST['implementation'],
                $_SESSION['user_id']
            ]);
            $security->logSecurityEvent($_SESSION['user_id'], 'policy_created', "Created policy: {$_POST['policy_name']}");
            header('Location: manage_policies.php?success=Policy created successfully');
            exit;

        case 'update_policy':
            $db->query("CALL update_security_policy(?, ?, ?, ?, ?, ?, ?, ?)", [
                $_POST['policy_id'],
                $_POST['policy_name'],
                $_POST['description'],
                $_POST['category'],
                $_POST['status'],
                $_POST['requirements'],
                $_POST['implementation'],
                $_SESSION['user_id']
            ]);
            $security->logSecurityEvent($_SESSION['user_id'], 'policy_updated', "Updated policy ID: {$_POST['policy_id']}");
            header('Location: manage_policies.php?success=Policy updated successfully');
            exit;

        case 'delete_policy':
            $db->query("CALL delete_security_policy(?, ?)", [
                $_POST['policy_id'],
                $_SESSION['user_id']
            ]);
            $security->logSecurityEvent($_SESSION['user_id'], 'policy_deleted', "Deleted policy ID: {$_POST['policy_id']}");
            header('Location: manage_policies.php?success=Policy deleted successfully');
            exit;
    }
}

// Get policy for editing if ID is provided
$edit_policy = null;
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $edit_policy = $db->query(
        "SELECT * FROM security_policies WHERE id = ?",
        [$_GET['edit']]
    )->fetch(PDO::FETCH_ASSOC);
}

// Get all policies
$policies = $db->query(
    "SELECT sp.*, 
            u1.username as created_by_name,
            u2.username as updated_by_name,
            (SELECT COUNT(*) FROM policy_revisions WHERE policy_id = sp.id) as revision_count
     FROM security_policies sp
     LEFT JOIN users u1 ON sp.created_by = u1.id
     LEFT JOIN users u2 ON sp.updated_by = u2.id
     ORDER BY sp.created_at DESC"
)->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Security Policies</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Policy Management</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <span class="role-badge"><?php echo htmlspecialchars($_SESSION['role']); ?></span>
                <a href="index.php" class="btn">Dashboard</a>
                <a href="?action=logout" class="btn-logout">Logout</a>
            </div>
        </header>

        <?php if (isset($_GET['success'])): ?>
            <div class="success-message"><?php echo htmlspecialchars($_GET['success']); ?></div>
        <?php endif; ?>

        <!-- Policy Form -->
        <div class="card">
            <h2><?php echo $edit_policy ? 'Edit Policy' : 'Add New Policy'; ?></h2>
            <form method="POST" class="policy-form">
                <input type="hidden" name="action" value="<?php echo $edit_policy ? 'update_policy' : 'add_policy'; ?>">
                <?php if ($edit_policy): ?>
                    <input type="hidden" name="policy_id" value="<?php echo $edit_policy['id']; ?>">
                <?php endif; ?>

                <div class="form-group">
                    <label>Policy Name</label>
                    <input type="text" name="policy_name" required 
                           value="<?php echo $edit_policy ? htmlspecialchars($edit_policy['policy_name']) : ''; ?>">
                </div>

                <div class="form-group">
                    <label>Description</label>
                    <textarea name="description" required><?php echo $edit_policy ? htmlspecialchars($edit_policy['description']) : ''; ?></textarea>
                </div>

                <div class="form-group">
                    <label>Category</label>
                    <select name="category" required>
                        <?php
                        $categories = ['password', 'access', 'data', 'network', 'incident', 'compliance'];
                        foreach ($categories as $category):
                            $selected = $edit_policy && $edit_policy['category'] === $category ? 'selected' : '';
                        ?>
                            <option value="<?php echo $category; ?>" <?php echo $selected; ?>>
                                <?php echo ucfirst($category); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <?php if ($edit_policy): ?>
                    <div class="form-group">
                        <label>Status</label>
                        <select name="status" required>
                            <?php
                            $statuses = ['draft', 'active', 'inactive'];
                            foreach ($statuses as $status):
                                $selected = $edit_policy['status'] === $status ? 'selected' : '';
                            ?>
                                <option value="<?php echo $status; ?>" <?php echo $selected; ?>>
                                    <?php echo ucfirst($status); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                <?php endif; ?>

                <div class="form-group">
                    <label>Requirements</label>
                    <textarea name="requirements" required><?php echo $edit_policy ? htmlspecialchars($edit_policy['requirements']) : ''; ?></textarea>
                </div>

                <div class="form-group">
                    <label>Implementation Details</label>
                    <textarea name="implementation" required><?php echo $edit_policy ? htmlspecialchars($edit_policy['implementation_details']) : ''; ?></textarea>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">
                        <?php echo $edit_policy ? 'Update Policy' : 'Add Policy'; ?>
                    </button>
                    <?php if ($edit_policy): ?>
                        <a href="manage_policies.php" class="btn">Cancel</a>
                    <?php endif; ?>
                </div>
            </form>
        </div>

        <!-- Policies List -->
        <div class="card">
            <h2>Security Policies</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Created By</th>
                        <th>Last Updated</th>
                        <th>Revisions</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($policies as $policy): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($policy['policy_name']); ?></td>
                            <td><?php echo ucfirst(htmlspecialchars($policy['category'])); ?></td>
                            <td>
                                <span class="status-badge status-<?php echo $policy['status']; ?>">
                                    <?php echo ucfirst(htmlspecialchars($policy['status'])); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($policy['created_by_name']); ?></td>
                            <td><?php echo date('Y-m-d H:i', strtotime($policy['last_updated'])); ?></td>
                            <td><?php echo $policy['revision_count']; ?></td>
                            <td class="actions">
                                <a href="?edit=<?php echo $policy['id']; ?>" class="btn btn-small">Edit</a>
                                <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this policy?');">
                                    <input type="hidden" name="action" value="delete_policy">
                                    <input type="hidden" name="policy_id" value="<?php echo $policy['id']; ?>">
                                    <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html> 
<?php
session_start();

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Check if user is admin
 */
function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

/**
 * Validate session
 */
function validateSession() {
    if (!isLoggedIn()) {
        return false;
    }

    // Check session timeout
    if (isset($_SESSION['last_activity'])) {
        $timeout = 30 * 60; // 30 minutes
        if (time() - $_SESSION['last_activity'] > $timeout) {
            session_destroy();
            return false;
        }
    }

    // Update last activity time
    $_SESSION['last_activity'] = time();
    return true;
}

/**
 * Require authentication
 */
function requireAuth() {
    if (!validateSession()) {
        header('Location: /login.php');
        exit();
    }
}

/**
 * Require admin role
 */
function requireAdmin() {
    requireAuth();
    if (!isAdmin()) {
        header('Location: /index.php');
        exit();
    }
}

/**
 * Get current user ID
 */
function getCurrentUserId() {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Get current username
 */
function getCurrentUsername() {
    return $_SESSION['username'] ?? null;
}

/**
 * Get current user role
 */
function getCurrentUserRole() {
    return $_SESSION['role'] ?? null;
} 
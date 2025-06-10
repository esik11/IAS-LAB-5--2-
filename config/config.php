<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'security_system');
define('DB_USER', 'root');
define('DB_PASS', '');

// Security Configuration
define('ENCRYPTION_KEY', 'your-secret-key-change-this');
define('SESSION_TIMEOUT', 1800); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_TIME', 900); // 15 minutes

// Password Complexity Requirements
define('PASSWORD_MIN_LENGTH', 8);
define('PASSWORD_REQUIRE_MIXED', true);
define('PASSWORD_REQUIRE_NUMBERS', true);
define('PASSWORD_REQUIRE_SYMBOLS', true);

// Default Admin Credentials
define('DEFAULT_ADMIN_USERNAME', 'admin');
define('DEFAULT_ADMIN_PASSWORD', 'Admin@123');

// GDPR Compliance Settings
define('DATA_RETENTION_PERIOD', 365); // days
define('REQUIRE_CONSENT', true);
define('LOG_USER_ACTIONS', true);

// Initialize session with secure settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Strict'); 
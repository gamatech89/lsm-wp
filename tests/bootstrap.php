<?php
/**
 * PHPUnit bootstrap for the Landeseiten Maintenance plugin.
 *
 * Plain PHPUnit, no WordPress: the handful of WordPress functions the tested
 * classes call are replaced by in-memory fakes in stubs/wp-functions.php.
 */

// Fixed fake WordPress root. Tests that need real files create them under here
// or (for LSM_Hardening) under per-test temp dirs handed in through seams.
$lsm_test_root = rtrim(sys_get_temp_dir(), '/\\') . '/lsm-wp-tests/';
if (!is_dir($lsm_test_root . 'wp-content/uploads')) {
    mkdir($lsm_test_root . 'wp-content/uploads', 0777, true);
}

// update_all_plugins() require_once()s these admin files; empty stand-ins are enough.
if (!is_dir($lsm_test_root . 'wp-admin/includes')) {
    mkdir($lsm_test_root . 'wp-admin/includes', 0777, true);
}
foreach (['update', 'plugin', 'class-wp-upgrader', 'plugin-install', 'file'] as $lsm_admin_file) {
    if (!file_exists($lsm_test_root . 'wp-admin/includes/' . $lsm_admin_file . '.php')) {
        file_put_contents($lsm_test_root . 'wp-admin/includes/' . $lsm_admin_file . '.php', "<?php\n");
    }
}

// The class files exit silently without ABSPATH.
define('ABSPATH', $lsm_test_root);
define('WP_CONTENT_DIR', $lsm_test_root . 'wp-content');
define('DAY_IN_SECONDS', 86400);

define('LSM_VERSION', '0.0.0-test');
define('LSM_PLUGIN_DIR', dirname(__DIR__) . '/landeseiten-maintenance/');
define('LSM_PLUGIN_URL', 'http://example.test/wp-content/plugins/landeseiten-maintenance/');

require_once __DIR__ . '/stubs/wp-functions.php';
require_once __DIR__ . '/stubs/wp-upgrader.php';
require_once __DIR__ . '/FakeServer.php';

// Classes under test and their test doubles.
require_once LSM_PLUGIN_DIR . 'includes/class-lsm-hardening.php';
require_once __DIR__ . '/TestableHardening.php';
require_once __DIR__ . '/HardeningTestCase.php';
require_once __DIR__ . '/Fixtures.php';
require_once LSM_PLUGIN_DIR . 'includes/class-lsm-api.php';
require_once LSM_PLUGIN_DIR . 'includes/class-lsm-security-scanner.php';
require_once LSM_PLUGIN_DIR . 'includes/class-lsm-actions.php';

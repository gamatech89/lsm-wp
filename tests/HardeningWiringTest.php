<?php

use PHPUnit\Framework\TestCase;

/**
 * Wiring into the main plugin file and the scanner.
 *
 * The main file cannot be loaded without WordPress (it boots the whole plugin),
 * so its wiring is asserted on the source. The scanner is exercised for real.
 */
class HardeningWiringTest extends TestCase {

    /** @var string[] files created below the fake WP_CONTENT_DIR */
    private $created = [];

    protected function setUp(): void {
        LSM_Test_Env::reset();
    }

    protected function tearDown(): void {
        foreach ($this->created as $file) {
            @unlink($file);
        }
    }

    private function main_file() {
        return file_get_contents(LSM_PLUGIN_DIR . 'landeseiten-maintenance.php');
    }

    /**
     * Source of one method of the main class, from its signature to the next docblock.
     */
    private function method_source($name) {
        $this->assertSame(1, preg_match('/function ' . $name . '\(\) \{.*?\n    \}\n/s', $this->main_file(), $m), $name . '() not found');
        return $m[0];
    }

    private function touch_file($path, $content = 'x') {
        file_put_contents($path, $content);
        $this->created[] = $path;
    }

    public function test_the_class_file_is_required_with_the_other_includes() {
        $this->assertStringContainsString(
            "require_once LSM_PLUGIN_DIR . 'includes/class-lsm-hardening.php';",
            $this->method_source('includes')
        );
    }

    public function test_load_time_work_is_hooked_on_init_after_the_logger() {
        $init = $this->method_source('init');

        $logger    = strpos($init, 'LSM_Logger::init();');
        $hardening = strpos($init, 'LSM_Hardening::instance()->on_init();');
        $this->assertNotFalse($logger);
        $this->assertNotFalse($hardening);
        $this->assertGreaterThan($logger, $hardening, 'LSM_Logger::log() needs pluggable.php, so never earlier than init');

        $this->assertStringNotContainsString('LSM_Hardening', $this->method_source('init_security_filters'));
        $this->assertStringNotContainsString('LSM_Hardening', $this->method_source('__construct'));
    }

    public function test_deactivation_removes_the_blocks_and_activation_never_writes() {
        $this->assertStringContainsString('LSM_Hardening::instance()->deactivate();', $this->method_source('deactivate'));
        // activate() re-runs after every self-update: plugin updates must change nothing.
        $this->assertStringNotContainsString('LSM_Hardening', $this->method_source('activate'));
    }

    public function test_no_uninstall_handler_in_v1() {
        $this->assertFileDoesNotExist(LSM_PLUGIN_DIR . 'uninstall.php');
        $this->assertStringNotContainsString('register_uninstall_hook', $this->main_file());
    }

    public function test_the_three_file_collectors_skip_the_engines_own_artifacts() {
        $source = file_get_contents(LSM_PLUGIN_DIR . 'includes/class-lsm-security-scanner.php');

        foreach (['find_files_by_extension', 'find_double_extensions', 'find_hidden_files'] as $collector) {
            $this->assertSame(1, preg_match('/private function ' . $collector . '\(.*?\n    \}\n/s', $source, $m), $collector . '() not found');
            $this->assertStringContainsString('LSM_Hardening::is_own_artifact(', $m[0], $collector);
        }
    }

    public function test_the_scanner_never_hides_a_file_that_is_only_named_like_a_probe() {
        $uploads = WP_CONTENT_DIR . '/uploads';
        // The uploads PHP probe is never created: these can only be somebody else's files.
        $this->touch_file($uploads . '/lsm-probe-0123456789abcdef.php', '<?php // not ours');
        $this->touch_file($uploads . '/lsm-probe-0123456789abcdef.ico', '<?php // not ours');
        $this->touch_file(WP_CONTENT_DIR . '/lsm-probe-0123456789abcdef.php.zip');
        $this->touch_file($uploads . '/evil.php', '<?php');
        $this->touch_file(WP_CONTENT_DIR . '/invoice.php.jpg');
        // What a killed run of the engine really leaves behind.
        $this->touch_file(WP_CONTENT_DIR . '/lsm-probe-0123456789abcdef.zip');
        $this->touch_file(WP_CONTENT_DIR . '/lsm-probe-0123456789abcdef.wpress');
        $this->touch_file(WP_CONTENT_DIR . '/.htaccess.lsm-bak', "php_value auto_prepend_file x.php\n");

        $scanner  = new LSM_Security_Scanner();
        $findings = $scanner->public_detect_suspicious_files()['findings'];
        $files    = array_column($findings, 'file');

        $this->assertContains('wp-content/uploads/lsm-probe-0123456789abcdef.php', $files, 'PHP file in uploads');
        $this->assertContains('wp-content/uploads/lsm-probe-0123456789abcdef.ico', $files, 'PHP code inside image');
        $this->assertContains('wp-content/lsm-probe-0123456789abcdef.php.zip', $files, 'double extension');
        $this->assertContains('wp-content/uploads/evil.php', $files);
        $this->assertContains('wp-content/invoice.php.jpg', $files);

        $this->assertNotContains('wp-content/lsm-probe-0123456789abcdef.zip', $files);
        $this->assertNotContains('wp-content/lsm-probe-0123456789abcdef.wpress', $files);
        $this->assertNotContains('wp-content/.htaccess.lsm-bak', $files);
    }
}

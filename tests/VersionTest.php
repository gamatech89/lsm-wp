<?php

use PHPUnit\Framework\TestCase;

/**
 * The plugin header and the LSM_VERSION constant have drifted apart once before
 * (c632c98). The self-updater compares the release tag with the constant.
 */
class VersionTest extends TestCase {

    public function test_header_and_constant_agree_and_are_at_least_2_10_0() {
        $source = file_get_contents(LSM_PLUGIN_DIR . 'landeseiten-maintenance.php');

        $this->assertSame(1, preg_match('/^ \* Version: (\S+)$/m', $source, $header));
        $this->assertSame(1, preg_match("/define\('LSM_VERSION', '([^']+)'\);/", $source, $constant));

        $this->assertSame($header[1], $constant[1]);
        $this->assertTrue(version_compare($constant[1], '2.10.0', '>='), 'hardening needs 2.10.0: the platform reports older plugins as plugin_outdated');
    }
}

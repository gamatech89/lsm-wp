<?php

use PHPUnit\Framework\TestCase;

/**
 * The pre-release fleet check (tests/tools/check-manual-blocks.php).
 */
class ManualBlockToolTest extends TestCase {

    /** @var string */
    private $dir;

    protected function setUp(): void {
        $this->dir = rtrim(sys_get_temp_dir(), '/\\') . '/lsm-fleet-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void {
        array_map('unlink', glob($this->dir . '/*'));
        rmdir($this->dir);
    }

    private function run_tool() {
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/tests/tools/check-manual-blocks.php') . ' ' . escapeshellarg($this->dir), $output, $code);
        return [$code, $output];
    }

    public function test_recognised_blocks_pass() {
        file_put_contents($this->dir . '/midnightblue-duck.content.htaccess', LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT);
        file_put_contents($this->dir . '/drjung.ch.uploads.htaccess', LSM_Htaccess_Fixtures::AUDITED_UPLOADS);
        file_put_contents($this->dir . '/plain.content.htaccess', "Options -Indexes\n");

        list($code, $output) = $this->run_tool();

        $this->assertSame(0, $code);
        $this->assertSame([
            'ADOPTABLE     drjung.ch.uploads.htaccess  block_uploads_php',
            'ADOPTABLE     midnightblue-duck.content.htaccess  block_archives',
            'ADOPTABLE     midnightblue-duck.content.htaccess  block_debug_log',
        ], $output);
    }

    public function test_a_variant_the_matcher_does_not_know_fails_the_gate() {
        file_put_contents($this->dir . '/variant.content.htaccess', "<FilesMatch \"\\.(wpress|zip)$\">\nRequire all denied\n</FilesMatch>\n");

        list($code, $output) = $this->run_tool();

        $this->assertSame(1, $code);
        $this->assertSame(['UNRECOGNISED  variant.content.htaccess  block_archives'], $output);
    }
}

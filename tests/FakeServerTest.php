<?php

use PHPUnit\Framework\TestCase;

/**
 * The fake server is what every self-test in this suite talks to, so it gets its own proof.
 */
class FakeServerTest extends TestCase {

    /** @var string */
    private $root;

    /** @var LSM_Fake_Server */
    private $server;

    protected function setUp(): void {
        $this->root = rtrim(sys_get_temp_dir(), '/\\') . '/lsm-fake-server-' . bin2hex(random_bytes(6));
        mkdir($this->root . '/wp-content/uploads', 0777, true);
        $this->server = new LSM_Fake_Server($this->root . '/wp-content', $this->root . '/wp-content/uploads');
    }

    protected function tearDown(): void {
        foreach (['/wp-content/uploads/.htaccess', '/wp-content/uploads/a.php', '/wp-content/.htaccess', '/wp-content/backup.zip', '/wp-content/style.css'] as $file) {
            @unlink($this->root . $file);
        }
        rmdir($this->root . '/wp-content/uploads');
        rmdir($this->root . '/wp-content');
        rmdir($this->root);
    }

    private function code($url) {
        return $this->server->handle($url, [])['response']['code'];
    }

    public function test_serves_existing_files_and_404s_the_rest() {
        file_put_contents($this->root . '/wp-content/style.css', 'body{}');

        $response = $this->server->handle('http://example.test/wp-content/style.css?ver=1', ['timeout' => 5]);

        $this->assertSame(200, $response['response']['code']);
        $this->assertSame('body{}', $response['body']);
        $this->assertSame(404, $this->code('http://example.test/wp-content/missing.css'));
        $this->assertSame(200, $this->code('http://example.test/'), 'anything outside wp-content is the homepage');
        $this->assertSame(
            ['url' => 'http://example.test/wp-content/style.css?ver=1', 'args' => ['timeout' => 5], 'file_existed' => true],
            $this->server->requests[0]
        );
        $this->assertFalse($this->server->requests[1]['file_existed']);
    }

    public function test_honours_deny_containers_like_apache_even_for_missing_files() {
        file_put_contents($this->root . '/wp-content/backup.zip', 'PK');
        file_put_contents($this->root . '/wp-content/uploads/a.php', '<?php');
        $this->assertSame(200, $this->code('http://example.test/wp-content/backup.zip'));

        file_put_contents($this->root . '/wp-content/.htaccess', "<FilesMatch \"(?i)\\.(zip)$\">\n  Require all denied\n</FilesMatch>\n<Files \"debug.log\">\nDeny from all\n</Files>\n");
        file_put_contents($this->root . '/wp-content/uploads/.htaccess', "<FilesMatch \"\\.php$\">\nDeny from all\n</FilesMatch>\n");

        $this->assertSame(403, $this->code('http://example.test/wp-content/backup.zip'));
        $this->assertSame(403, $this->code('http://example.test/wp-content/uploads/2026/09/OTHER.ZIP'), 'wp-content rules are inherited by uploads');
        $this->assertSame(403, $this->code('http://example.test/wp-content/debug.log'), 'authorization comes before the 404');
        $this->assertSame(403, $this->code('http://example.test/wp-content/uploads/a.php'));
        $this->assertSame(403, $this->code('http://example.test/wp-content/uploads/not-there.php'));
        $this->assertSame(404, $this->code('http://example.test/wp-content/not-there.php'), 'the uploads rule does not apply one level up');
    }

    public function test_scripts_are_consumed_in_order_and_pass_means_simulate() {
        $this->server->script('~style~', [LSM_Fake_Server::response(503), 'pass', new WP_Error('http_request_failed', 'timeout')]);

        $this->assertSame(503, $this->code('http://example.test/wp-content/style.css'));
        $this->assertSame(404, $this->code('http://example.test/wp-content/style.css'));
        $this->assertTrue(is_wp_error($this->server->handle('http://example.test/wp-content/style.css', [])));
        $this->assertSame(404, $this->code('http://example.test/wp-content/style.css'), 'exhausted script falls through');
    }

    public function test_a_throwable_in_a_script_is_thrown() {
        $this->server->script('~.~', [new RuntimeException('killed')]);
        $this->expectException(RuntimeException::class);
        $this->server->handle('http://example.test/', []);
    }

    public function test_always_foreign_deny_bypass_and_rejected_directive() {
        file_put_contents($this->root . '/wp-content/backup.zip', 'PK');
        file_put_contents($this->root . '/wp-content/.htaccess', "<FilesMatch \"\\.zip$\">\nRequire all denied\n</FilesMatch>\n");

        $this->server->bypass_htaccess = '~\.zip$~';
        $this->assertSame(200, $this->code('http://example.test/wp-content/backup.zip'), 'nginx serves static files itself');
        $this->assertSame(200, $this->code('http://example.test/wp-content/backup.zip?lsm_hardening=0a1b2c3d'), 'the knob looks at the path, not at the query string');
        $this->server->bypass_htaccess = null;

        $this->server->foreign_deny = '~\.css$~';
        $this->assertSame(403, $this->code('http://example.test/wp-content/style.css'));
        $this->assertSame(403, $this->code('http://example.test/wp-content/style.css?ver=1'), 'the knob looks at the path, not at the query string');
        $this->server->foreign_deny = null;

        $this->server->rejected_directive = 'Require all denied';
        $this->assertSame(500, $this->code('http://example.test/wp-content/style.css'), 'a rejected directive breaks the whole directory');
        $this->assertSame(200, $this->code('http://example.test/'));
        $this->server->rejected_directive = null;

        $this->server->always('~^http://example\.test/$~', LSM_Fake_Server::response(301));
        $this->assertSame(301, $this->code('http://example.test/'));
        $this->assertCount(2, $this->server->requests_matching('~backup\.zip~'));
        $this->assertCount(1, $this->server->requests_matching('~backup\.zip$~'), 'requests_matching() sees the full URL, query string included');
    }
}

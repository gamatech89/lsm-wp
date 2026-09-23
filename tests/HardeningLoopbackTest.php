<?php

/**
 * Loopback helper, baselines, probes and their verdicts.
 */
class HardeningLoopbackTest extends HardeningTestCase {

    public function test_loopback_sends_the_spec_arguments() {
        $this->h->loopback('http://example.test/wp-content/x.txt');

        $this->assertSame([
            'timeout'     => 5,
            'redirection' => 0,
            'cookies'     => [],
            'sslverify'   => false,
            'headers'     => ['Cache-Control' => 'no-cache'],
        ], $this->server->requests[0]['args']);
    }

    public function test_sslverify_follows_the_https_local_ssl_verify_filter() {
        LSM_Test_Env::$filters['https_local_ssl_verify'] = true;
        $this->h->loopback('http://example.test/');
        $this->assertTrue($this->server->requests[0]['args']['sslverify']);
    }

    public function test_loopback_reduces_a_response() {
        file_put_contents($this->content . '/hello.txt', 'hi');
        $this->assertSame(
            ['error' => false, 'code' => 200, 'body' => 'hi', 'challenge' => false],
            $this->h->loopback('http://example.test/wp-content/hello.txt')
        );
    }

    public function test_loopback_reduces_a_wp_error_and_a_cloudflare_challenge() {
        $this->server->script('~x~', [
            new WP_Error('http_request_failed', 'cURL error 28'),
            LSM_Fake_Server::response(403, 'Just a moment...', ['cf-mitigated' => 'challenge']),
        ]);

        $this->assertSame(['error' => true, 'code' => 0, 'body' => '', 'challenge' => false], $this->h->loopback('http://example.test/x'));
        $this->assertTrue($this->h->loopback('http://example.test/x')['challenge']);
    }

    public function test_baseline_asset_is_the_plugin_css_with_a_cache_buster() {
        $asset = $this->h->baseline_asset();

        $this->assertSame(200, $asset['code']);
        $this->assertSame('.lsm-ticket{display:block}', $asset['body']);
        $this->assertMatchesRegularExpression(
            '~^http://example\.test/wp-content/plugins/landeseiten-maintenance/assets/css/ticket-ui\.css\?lsm_hardening=[a-f0-9]{8}$~',
            $this->server->requests[0]['url']
        );
    }

    public function test_baseline_asset_is_skipped_when_the_plugin_is_not_below_wp_content() {
        $this->h->plugin = $this->root . '/elsewhere/plugins/landeseiten-maintenance/';
        $this->assertNull($this->h->baseline_asset());
        $this->assertSame([], $this->server->requests);
    }

    public function test_baseline_home_is_a_plain_anonymous_request() {
        $home = $this->h->baseline_home();

        $this->assertSame(200, $home['code']);
        $this->assertSame('http://example.test/', $this->server->requests[0]['url']);
        $this->assertSame([], $this->server->requests[0]['args']['cookies']);
    }

    public function test_archive_probes_are_real_files_with_a_token() {
        $probes = $this->h->prepare_probes('block_archives');

        $this->assertSame(['.zip', '.wpress'], array_column($probes, 'label'));
        foreach ($probes as $probe) {
            $this->assertMatchesRegularExpression('~^http://example\.test/wp-content/lsm-probe-[a-f0-9]{16}\.(zip|wpress)$~', $probe['url']);
            $this->assertMatchesRegularExpression('~^[a-f0-9]{32}$~', $probe['token']);
            $this->assertSame($probe['token'], file_get_contents($this->content . '/' . basename($probe['url'])));
        }

        $fetched = $this->h->fetch_probes($probes);
        $this->assertSame([200, 200], array_column($fetched, 'code'));
        $this->assertSame([true, true], array_column($fetched, 'served'));
        $this->assertSame([false, false], array_column($fetched, 'inconclusive'));
    }

    public function test_the_uploads_php_probe_is_never_created() {
        $probes = $this->h->prepare_probes('block_uploads_php');

        $this->assertCount(1, $probes);
        $this->assertMatchesRegularExpression('~^http://example\.test/wp-content/uploads/lsm-probe-[a-f0-9]{16}\.php$~', $probes[0]['url']);
        $this->assertNull($probes[0]['token']);
        $this->assertSame([], glob($this->uploads . '/*'));

        $fetched = $this->h->fetch_probes($probes);
        $this->assertSame(404, $fetched[0]['code']);
        $this->assertFalse($this->server->requests[0]['file_existed']);
        $this->assertSame([], glob($this->uploads . '/*'));
    }

    public function test_the_debug_log_probe_needs_no_file() {
        $probes = $this->h->prepare_probes('block_debug_log');

        $this->assertSame('http://example.test/wp-content/debug.log', $probes[0]['url'], 'the cache-buster is added per fetch, not here');
        $this->assertSame(404, $this->h->fetch_probes($probes)[0]['code']);
        $this->assertMatchesRegularExpression('~/wp-content/debug\.log\?lsm_hardening=[a-f0-9]{8}$~', $this->server->requests[0]['url']);
        $this->assertFileDoesNotExist($this->content . '/debug.log');
    }

    public function test_every_probe_fetch_carries_a_fresh_cache_buster() {
        // The same probes are fetched before and after the write. An edge cache keyed by
        // URL + query (Cloudflare caches .zip by extension) must never see the same URL twice.
        $probes = $this->h->prepare_probes('block_archives');

        $first  = $this->h->fetch_probes($probes);
        $second = $this->h->fetch_probes($probes);

        $this->assertSame(array_column($probes, 'url'), array_column($first, 'url'), 'the probe list keeps the plain URLs');
        $this->assertSame(array_column($probes, 'url'), array_column($second, 'url'));

        $requested = array_column($this->server->requests, 'url');
        $this->assertCount(4, $requested);
        $this->assertCount(4, array_unique($requested));
        foreach ($requested as $url) {
            $this->assertMatchesRegularExpression('~^http://example\.test/wp-content/lsm-probe-[a-f0-9]{16}\.(zip|wpress)\?lsm_hardening=[a-f0-9]{8}$~', $url);
        }
    }

    public function test_probes_turn_403_once_the_rule_is_in_the_file() {
        $archives = $this->h->prepare_probes('block_archives');
        $php      = $this->h->prepare_probes('block_uploads_php');
        $log      = $this->h->prepare_probes('block_debug_log');

        $this->put('content', $this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n");
        $this->put('uploads', $this->h->build_block('uploads', ['block_uploads_php']) . "\n");

        $this->assertSame([403, 403], array_column($this->h->fetch_probes($archives), 'code'));
        $this->assertSame([403], array_column($this->h->fetch_probes($php), 'code'));
        $this->assertSame([403], array_column($this->h->fetch_probes($log), 'code'));
        $this->assertSame(200, $this->h->baseline_asset()['code'], 'the plugin CSS is not an archive');
    }

    private function probe($label, $code, $served = false, $inconclusive = false) {
        return ['label' => $label, 'url' => 'http://example.test/p', 'token' => null, 'code' => $code, 'served' => $served, 'inconclusive' => $inconclusive];
    }

    public function test_before_served_archives_are_fine() {
        $verdict = $this->h->judge_before('block_archives', [$this->probe('.zip', 200, true), $this->probe('.wpress', 200, true)], false);
        $this->assertSame(['reason' => null, 'message' => '', 'warnings' => []], $verdict);
    }

    public function test_before_an_unexplained_403_is_a_warning_not_a_failure() {
        foreach (LSM_Hardening::RULES as $rule) {
            $verdict = $this->h->judge_before($rule, [$this->probe('x', 403)], false);
            $this->assertNull($verdict['reason'], $rule);
            $this->assertSame(['already_blocked_elsewhere'], $verdict['warnings'], $rule);
        }
    }

    public function test_before_a_403_the_file_explains_is_no_warning() {
        $verdict = $this->h->judge_before('block_archives', [$this->probe('.zip', 403), $this->probe('.wpress', 403)], true);
        $this->assertSame([], $verdict['warnings']);
        $this->assertNull($verdict['reason']);
    }

    public function test_before_an_archive_probe_that_is_neither_served_nor_403_blocks_the_operation() {
        $cases = [
            'file not reachable (other docroot)' => $this->probe('.zip', 404),
            'soft 404 page without the token'    => $this->probe('.zip', 200, false),
            'redirect'                           => $this->probe('.wpress', 301),
        ];
        foreach ($cases as $case => $probe) {
            $verdict = $this->h->judge_before('block_archives', [$probe], false);
            $this->assertSame('loopback_blocked', $verdict['reason'], $case);
            $this->assertStringContainsString($probe['label'], $verdict['message'], $case);
        }
    }

    public function test_before_any_code_is_fine_for_the_url_only_probes() {
        foreach ([404, 200, 301] as $code) {
            $this->assertNull($this->h->judge_before('block_debug_log', [$this->probe('debug.log', $code, $code === 200)], false)['reason']);
            $this->assertNull($this->h->judge_before('block_uploads_php', [$this->probe('uploads .php', $code)], false)['reason']);
        }
    }

    public function test_inconclusive_responses_are_loopback_blocked_before_and_after() {
        $this->server->script('~inconclusive~', [
            new WP_Error('http_request_failed', 'timeout'),
            LSM_Fake_Server::response(401, 'Authorization Required'),
            LSM_Fake_Server::response(503, 'Service Unavailable'),
            LSM_Fake_Server::response(403, 'Just a moment...', ['cf-mitigated' => 'challenge']),
        ]);

        for ($i = 0; $i < 4; $i++) {
            $probes = $this->h->fetch_probes([['label' => 'uploads .php', 'url' => 'http://example.test/wp-content/uploads/inconclusive.php', 'token' => null]]);
            $this->assertTrue($probes[0]['inconclusive'], 'response ' . $i);
            $this->assertSame('loopback_blocked', $this->h->judge_before('block_uploads_php', $probes, false)['reason'], 'before ' . $i);
            $this->assertSame('loopback_blocked', $this->h->judge_after('block_uploads_php', true, $probes)['reason'], 'after on ' . $i);
            $this->assertSame('loopback_blocked', $this->h->judge_after('block_uploads_php', false, $probes)['reason'], 'after off ' . $i);
        }
    }

    public function test_after_a_rule_that_is_on_needs_exactly_403_on_every_probe() {
        $this->assertNull($this->h->judge_after('block_archives', true, [$this->probe('.zip', 403), $this->probe('.wpress', 403)])['reason']);

        $verdict = $this->h->judge_after('block_archives', true, [$this->probe('.zip', 200, true), $this->probe('.wpress', 403)]);
        $this->assertSame('rule_ineffective', $verdict['reason']);
        $this->assertStringContainsString('.zip', $verdict['message']);
        $this->assertStringContainsString('200', $verdict['message']);

        $this->assertSame('rule_ineffective', $this->h->judge_after('block_uploads_php', true, [$this->probe('uploads .php', 404)])['reason']);
        $this->assertSame('rule_ineffective', $this->h->judge_after('block_debug_log', true, [$this->probe('debug.log', 200, true)])['reason']);
    }

    public function test_after_archives_out_of_the_block_need_the_wpress_probe_served() {
        $served  = $this->probe('.wpress', 200, true);
        $blocked = $this->probe('.wpress', 403);

        $this->assertNull($this->h->judge_after('block_archives', false, [$this->probe('.zip', 403), $served])['reason'], 'a .zip blocked elsewhere does not matter');
        $this->assertSame('pause_ineffective_foreign_rule', $this->h->judge_after('block_archives', false, [$this->probe('.zip', 200, true), $blocked])['reason']);
        $this->assertSame('pause_ineffective_foreign_rule', $this->h->judge_after('block_archives', false, [$this->probe('.wpress', 200, false)])['reason'], '200 without the token is not our file');
    }

    public function test_after_turning_the_other_rules_off_needs_nothing_more() {
        $this->assertNull($this->h->judge_after('block_debug_log', false, [$this->probe('debug.log', 403)])['reason']);
        $this->assertNull($this->h->judge_after('block_uploads_php', false, [$this->probe('uploads .php', 404)])['reason']);
    }

    public function test_own_artifacts_are_recognised_by_their_exact_names() {
        $this->assertTrue(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.zip'));
        $this->assertTrue(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.wpress'));
        $this->assertTrue(LSM_Hardening::is_own_artifact('.htaccess.lsm-bak'));

        // The uploads PHP probe is never created: a PHP name with our prefix is somebody else's file.
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.php'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.php.zip'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.php.jpg'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-0123456789abcdef.ico'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-shell.zip'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('lsm-probe-0123456789ABCDEF.zip'));
        $this->assertFalse(LSM_Hardening::is_own_artifact("lsm-probe-0123456789abcdef.zip\n"));
        $this->assertFalse(LSM_Hardening::is_own_artifact('my-lsm-probe-0123456789abcdef.zip'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('.htaccess'));
        $this->assertFalse(LSM_Hardening::is_own_artifact('backup.zip'));
    }

    public function test_cleanup_deletes_probes_and_snapshots_in_both_directories_and_nothing_else() {
        $this->h->prepare_probes('block_archives');
        file_put_contents($this->content . '/.htaccess.lsm-bak', 'x');
        file_put_contents($this->uploads . '/.htaccess.lsm-bak', 'x');
        file_put_contents($this->uploads . '/lsm-probe-0123456789abcdef.php', '<?php // not ours: the PHP probe is never created');
        file_put_contents($this->content . '/backup.zip', 'keep');
        $this->put('content', "Options -Indexes\n");
        $this->assertCount(4, $this->artifacts());

        $this->h->cleanup_artifacts();

        $this->assertSame([], $this->artifacts());
        $this->assertFileExists($this->uploads . '/lsm-probe-0123456789abcdef.php', 'never delete what we cannot have created');
        $this->assertFileExists($this->content . '/backup.zip');
        $this->assertSame("Options -Indexes\n", $this->get('content'));
    }
}

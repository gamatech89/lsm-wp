<?php

/**
 * The full apply procedure: enable, disable, adopt — and every way it can fail.
 */
class HardeningApplyTest extends HardeningTestCase {

    const FOREIGN = "# BEGIN WebP Express\nAddType image/webp .webp\n# END WebP Express\n";

    /**
     * What every failed operation must leave behind: desired state, pause and file bytes
     * untouched, nothing pending, lock free, no artifacts, the failure recorded.
     */
    private function assertFailedCleanly(array $result, $reason, $rule, $target, $expected_file) {
        $this->assertFalse($result['success']);
        $this->assertSame($reason, $result['reason']);
        $this->assertNotSame('', $result['message']);

        $this->assertSame($expected_file, $this->get($target), 'file bytes');

        $state = $this->h->get_state();
        $this->assertSame(['block_archives' => false, 'block_debug_log' => false, 'block_uploads_php' => false], $state['rules']);
        $this->assertNull($state['pause_until']);
        $this->assertNull($state['pending']);
        $this->assertFalse(get_option('lsm_hardening_lock'), 'lock released');
        $this->assertSame([], $this->artifacts());

        $this->assertSame($reason, $state['rule_failures'][$rule]['reason']);
        $this->assertSame($this->h->time, $state['rule_failures'][$rule]['at']);
        $this->assertFalse($state['last_result']['ok']);
        $this->assertSame($reason, $state['last_result']['reason']);
        $this->assertSame($reason, $result['status']['rules'][$rule]['last_failure']['reason']);
        $this->assertSame(['hardening_failed', 'error'], array_slice(LSM_Test_Env::$log[0], 0, 2));
    }

    /**
     * Count writes to .htaccess files (not to probes or snapshots).
     */
    private function count_htaccess_writes() {
        $counter = new stdClass();
        $counter->n = 0;
        $this->h->put_hook = function ($file) use ($counter) {
            if (basename($file) === '.htaccess') {
                $counter->n++;
            }
            return null;
        };
        return $counter;
    }

    // -------------------------------------------------------------------------
    // Success
    // -------------------------------------------------------------------------

    public function test_enable_archives_on_a_fresh_site() {
        $result = $this->h->set_rule('block_archives', true);

        $this->assertSame(true, $result['success']);
        $this->assertNull($result['reason']);
        $this->assertSame('Applied and verified', $result['message']);
        $this->assertSame([], $result['warnings']);
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertTrue($result['status']['rules']['block_archives']['desired']);
        $this->assertSame(
            ['at' => $this->h->time, 'action' => 'enable', 'rule' => 'block_archives', 'ok' => true, 'reason' => null, 'warnings' => []],
            $result['status']['last_result']
        );

        $this->assertSame($this->h->build_block('content', ['block_archives']) . "\n", $this->get('content'));
        $this->assertNull($this->get('uploads'));

        $state = $this->h->get_state();
        $this->assertTrue($state['rules']['block_archives']);
        $this->assertNull($state['pending']);
        $this->assertFalse(get_option('lsm_hardening_lock'));
        $this->assertSame([], $this->artifacts());
        $this->assertSame(['hardening_applied', 'success'], array_slice(LSM_Test_Env::$log[0], 0, 2));
    }

    public function test_enable_runs_baselines_and_probes_before_and_after() {
        $this->h->set_rule('block_archives', true);

        $kinds = array_map(function ($request) {
            if (strpos($request['url'], 'ticket-ui.css') !== false) {
                return 'asset';
            }
            if ($request['url'] === 'http://example.test/') {
                return 'home';
            }
            return pathinfo(parse_url($request['url'], PHP_URL_PATH), PATHINFO_EXTENSION);
        }, $this->server->requests);

        $this->assertSame(['asset', 'home', 'zip', 'wpress', 'asset', 'home', 'zip', 'wpress'], $kinds);
        foreach ($this->server->requests_matching('~lsm-probe-~') as $request) {
            $this->assertTrue($request['file_existed'], 'archive probes are real files');
        }
    }

    public function test_enable_uploads_php_never_creates_a_php_file() {
        $result = $this->h->set_rule('block_uploads_php', true);

        $this->assertTrue($result['success']);
        $this->assertSame($this->h->build_block('uploads', ['block_uploads_php']) . "\n", $this->get('uploads'));
        $this->assertNull($this->get('content'));

        $probes = $this->server->requests_matching('~/uploads/lsm-probe-[a-f0-9]{16}\.php\?lsm_hardening=[a-f0-9]{8}$~');
        $this->assertCount(2, $probes);
        $this->assertSame([false, false], array_column($probes, 'file_existed'));
        $this->assertNotSame($probes[0]['url'], $probes[1]['url'], 'before and after never share a URL');
    }

    public function test_an_edge_cache_cannot_fake_rule_ineffective() {
        // Cloudflare in front of the site: the "before" 200 of the .zip probe is cached at the edge.
        // If the "after" fetch used the same URL it would be a HIT (200) and the enable would be
        // rolled back as rule_ineffective on every Cloudflare-proxied site.
        $edge = $this->put_an_edge_cache_in_front();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertTrue($result['success'], (string) $result['reason']);
        $this->assertCount(1, $edge, 'the edge did cache the "before" 200 of the .zip probe');
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
    }

    public function test_enable_debug_log_keeps_the_other_rule_and_foreign_bytes() {
        $this->put('content', self::FOREIGN);
        $this->h->set_rule('block_archives', true);

        $result = $this->h->set_rule('block_debug_log', true);

        $this->assertTrue($result['success']);
        $this->assertSame(
            self::FOREIGN . "\n" . $this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n",
            $this->get('content')
        );
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('on', $result['status']['rules']['block_debug_log']['state']);
    }

    public function test_enabling_one_rule_does_not_resurrect_a_drifted_one() {
        update_option('lsm_hardening', ['rules' => ['block_archives' => true]]);

        $result = $this->h->set_rule('block_debug_log', true);

        $this->assertTrue($result['success']);
        $this->assertSame($this->h->build_block('content', ['block_debug_log']) . "\n", $this->get('content'));
        $this->assertSame('drift', $result['status']['rules']['block_archives']['state']);
    }

    public function test_reapplying_a_drifted_rule_fixes_it() {
        update_option('lsm_hardening', ['rules' => ['block_archives' => true]]);
        $result = $this->h->set_rule('block_archives', true);
        $this->assertTrue($result['success']);
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
    }

    public function test_disable_removes_the_rule_and_with_the_last_rule_the_markers() {
        $this->h->set_rule('block_archives', true);
        $this->h->set_rule('block_debug_log', true);

        $result = $this->h->set_rule('block_archives', false);
        $this->assertTrue($result['success']);
        $this->assertSame('disable', $result['status']['last_result']['action']);
        $this->assertSame($this->h->build_block('content', ['block_debug_log']) . "\n", $this->get('content'));
        $this->assertFalse($this->h->get_state()['rules']['block_archives']);

        $this->assertTrue($this->h->set_rule('block_debug_log', false)['success']);
        // The file existed when this operation started, so it is emptied, not deleted.
        $this->assertSame('', $this->get('content'));
    }

    public function test_disabling_a_rule_on_a_site_without_the_file_creates_nothing() {
        $result = $this->h->set_rule('block_uploads_php', false);

        $this->assertTrue($result['success']);
        $this->assertNull($this->get('uploads'));
        $this->assertSame('off', $result['status']['rules']['block_uploads_php']['state']);
    }

    public function test_disable_gives_a_foreign_file_back_byte_for_byte() {
        $this->put('uploads', self::FOREIGN);
        $this->h->set_rule('block_uploads_php', true);

        $this->assertTrue($this->h->set_rule('block_uploads_php', false)['success']);
        $this->assertSame(self::FOREIGN, $this->get('uploads'));
    }

    public function test_a_rule_in_the_file_can_be_turned_off_even_when_desired_was_false() {
        // DB restored to before the enable: option says off, file still has the block.
        $this->put('content', $this->h->build_block('content', ['block_archives']) . "\n");

        $result = $this->h->set_rule('block_archives', false);

        $this->assertTrue($result['success']);
        $this->assertSame('off', $result['status']['rules']['block_archives']['state']);
    }

    public function test_enabling_a_rule_that_is_already_on_rewrites_nothing() {
        $this->h->set_rule('block_archives', true);
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertTrue($result['success']);
        $this->assertSame([], $result['warnings'], 'a 403 our own block explains is no warning');
        $this->assertSame(0, $writes->n);
    }

    public function test_adoption_replaces_the_manual_block_in_the_same_write() {
        $this->put('content', LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT);
        $this->assertSame('manual', $this->h->get_status()['rules']['block_archives']['state']);
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertTrue($result['success']);
        $this->assertSame([], $result['warnings'], 'the manual block explains the 403 before the write');
        $this->assertSame(1, $writes->n);
        $this->assertSame(
            "<IfModule litespeed>\nphp_value \n</IfModule>\n<Files \"debug.log\">\nRequire all denied\n</Files>\n\n"
                . $this->h->build_block('content', ['block_archives']) . "\n",
            $this->get('content')
        );
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('manual', $result['status']['rules']['block_debug_log']['state'], 'only the toggled rule is adopted');
    }

    public function test_adoption_of_the_uploads_block() {
        $this->put('uploads', LSM_Htaccess_Fixtures::AUDITED_UPLOADS);

        $this->assertTrue($this->h->set_rule('block_uploads_php', true)['success']);
        $this->assertSame($this->h->build_block('uploads', ['block_uploads_php']) . "\n", $this->get('uploads'));
    }

    public function test_warning_when_something_else_already_blocks_the_probes() {
        $this->server->foreign_deny = '~\.(zip|wpress)$~';

        $result = $this->h->set_rule('block_archives', true);

        $this->assertTrue($result['success']);
        $this->assertSame(['already_blocked_elsewhere'], $result['warnings']);
        $this->assertSame(['already_blocked_elsewhere'], $result['status']['last_result']['warnings']);
    }

    public function test_baseline_asset_is_skipped_when_the_plugin_lives_outside_wp_content() {
        $this->h->plugin = $this->root . '/elsewhere/landeseiten-maintenance/';

        $this->assertTrue($this->h->set_rule('block_archives', true)['success']);
        $this->assertSame([], $this->server->requests_matching('~ticket-ui\.css~'));
    }

    public function test_a_success_clears_the_sticky_failure_of_that_rule_only() {
        update_option('lsm_hardening', ['rule_failures' => [
            'block_archives'  => ['at' => 1, 'reason' => 'rule_ineffective'],
            'block_debug_log' => ['at' => 1, 'reason' => 'asset_broken'],
        ]]);

        $this->h->set_rule('block_archives', true);

        $this->assertSame(['block_debug_log'], array_keys($this->h->get_state()['rule_failures']));
    }

    // -------------------------------------------------------------------------
    // Rejections: nothing starts, nothing is recorded
    // -------------------------------------------------------------------------

    public function test_invalid_rule() {
        foreach (['block_everything', '', null, ['block_archives']] as $rule) {
            $result = $this->h->set_rule($rule, true);
            $this->assertFalse($result['success']);
            $this->assertSame('invalid_rule', $result['reason']);
        }
        $this->assertFalse(get_option('lsm_hardening'), 'no state written');
        $this->assertSame([], $this->server->requests);
    }

    public function test_unsupported() {
        $this->h->software = 'nginx/1.24.0';

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFalse($result['success']);
        $this->assertSame('unsupported', $result['reason']);
        $this->assertStringContainsString('unknown_server', $result['message']);
        $this->assertSame('unsupported', $result['status']['rules']['block_archives']['state']);
        $this->assertFalse(get_option('lsm_hardening'));
        $this->assertSame([], $this->server->requests);
        $this->assertNull($this->get('content'));
    }

    public function test_an_unreadable_htaccess_is_never_overwritten() {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('Running as root: every file is readable.');
        }
        // Writable but not readable. Read as "empty", the candidate would be nothing but our block,
        // the snapshot '' and the rollback would "restore" '' — the foreign rules would be gone.
        $this->put('content', self::FOREIGN);
        chmod($this->htaccess('content'), 0200);

        $result = $this->h->set_rule('block_debug_log', true);

        chmod($this->htaccess('content'), 0644);
        $this->assertFalse($result['success']);
        $this->assertSame('unsupported', $result['reason']);
        $this->assertStringContainsString('not_writable', $result['message']);
        $this->assertSame(self::FOREIGN, $this->get('content'));
        $this->assertSame([], $this->server->requests);
    }

    public function test_busy_changes_nothing_and_leaves_the_other_lock_alone() {
        $previous = ['at' => 5, 'action' => 'enable', 'rule' => 'block_debug_log', 'ok' => true, 'reason' => null, 'warnings' => []];
        update_option('lsm_hardening', ['last_result' => $previous]);
        add_option('lsm_hardening_lock', $this->h->time - 10, '', 'no');

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFalse($result['success']);
        $this->assertSame('busy', $result['reason']);
        $this->assertSame(['last_result' => $previous], get_option('lsm_hardening'), 'state untouched');
        $this->assertSame($this->h->time - 10, get_option('lsm_hardening_lock'), 'lock still held by the other operation');
        $this->assertSame([], $this->server->requests);
        $this->assertSame([], LSM_Test_Env::$log);
    }

    // -------------------------------------------------------------------------
    // Failures before the write: nothing is written
    // -------------------------------------------------------------------------

    public function test_markers_corrupt() {
        $corrupt = "# BEGIN LSM-HARDENING\n<Files \"debug.log\">\n";
        $this->put('content', $corrupt);
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'markers_corrupt', 'block_archives', 'content', $corrupt);
        $this->assertSame(0, $writes->n);
        $this->assertSame([], $this->server->requests);
    }

    public function test_loopback_blocked_when_every_loopback_is_403() {
        // Bot Fight Mode / host WAF: a uniform 403 must never read as "verified".
        $this->server->always('~.~', LSM_Fake_Server::response(403, 'Forbidden'));
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'loopback_blocked', 'block_archives', 'content', null);
        $this->assertSame(0, $writes->n);
    }

    public function test_loopback_blocked_when_the_asset_body_is_empty() {
        $this->server->always('~ticket-ui\.css~', LSM_Fake_Server::response(200, ''));
        $this->assertFailedCleanly($this->h->set_rule('block_debug_log', true), 'loopback_blocked', 'block_debug_log', 'content', null);
    }

    public function test_loopback_blocked_when_the_homepage_cannot_be_fetched() {
        $this->server->always('~^http://example\.test/$~', new WP_Error('http_request_failed', 'cURL error 28'));
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_uploads_php', true);

        $this->assertFailedCleanly($result, 'loopback_blocked', 'block_uploads_php', 'uploads', null);
        $this->assertSame(0, $writes->n);
    }

    public function test_loopback_blocked_when_the_archive_probe_file_is_not_reachable() {
        // home_url resolves to another server (pre-switch DNS): the probe file is not there.
        $this->server->always('~lsm-probe-~', LSM_Fake_Server::response(404, 'Not Found'));
        $writes = $this->count_htaccess_writes();

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'loopback_blocked', 'block_archives', 'content', null);
        $this->assertSame(0, $writes->n);
    }

    public function test_snapshot_failed() {
        $this->put('content', self::FOREIGN);
        $htaccess_writes = 0;
        $this->h->put_hook = function ($file) use (&$htaccess_writes) {
            if (basename($file) === '.htaccess.lsm-bak') {
                return false;
            }
            if (basename($file) === '.htaccess') {
                $htaccess_writes++;
            }
            return null;
        };

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'snapshot_failed', 'block_archives', 'content', self::FOREIGN);
        $this->assertSame(0, $htaccess_writes);
    }

    public function test_a_file_changed_by_something_else_during_the_self_test_is_never_overwritten() {
        $this->put('content', self::FOREIGN);
        $writes   = $this->count_htaccess_writes();
        $server   = $this->server;
        $htaccess = $this->htaccess('content');
        $appended = false;
        // WebP Express / a cache plugin rewrites wp-content/.htaccess while our "before" probe runs.
        LSM_Test_Env::$http = function ($url, $args) use ($server, $htaccess, &$appended) {
            if (!$appended && strpos($url, '/debug.log') !== false) {
                $appended = true;
                file_put_contents($htaccess, "ErrorDocument 404 /404.html\n", FILE_APPEND);
            }
            return $server->handle($url, $args);
        };

        $result = $this->h->set_rule('block_debug_log', true);

        $this->assertTrue($appended);
        $this->assertFailedCleanly($result, 'write_failed', 'block_debug_log', 'content', self::FOREIGN . "ErrorDocument 404 /404.html\n");
        $this->assertStringContainsString('changed by something else', $result['message']);
        $this->assertSame(0, $writes->n, 'the stale candidate never reached the disk');
    }

    // -------------------------------------------------------------------------
    // Failures after the write: rolled back
    // -------------------------------------------------------------------------

    public function test_snapshot_and_pending_exist_only_while_the_operation_runs() {
        $this->put('content', self::FOREIGN);
        $seen = [];
        $this->h->put_hook = function ($file) use (&$seen) {
            if (basename($file) === '.htaccess') {
                $seen = [
                    'snapshot' => file_get_contents(dirname($file) . '/.htaccess.lsm-bak'),
                    'pending'  => get_option('lsm_hardening')['pending'],
                    'lock'     => get_option('lsm_hardening_lock'),
                ];
            }
            return null;
        };

        $this->h->set_rule('block_archives', true);

        $this->assertSame(self::FOREIGN, $seen['snapshot']);
        $this->assertSame(['target' => 'content', 'op' => 'enable', 'started_at' => $this->h->time, 'existed' => true], $seen['pending']);
        $this->assertSame($this->h->time, $seen['lock']);
        $this->assertFileDoesNotExist($this->content . '/.htaccess.lsm-bak');
    }

    public function test_the_state_is_committed_before_the_snapshot_is_deleted() {
        // A kill between the two may leave a stray snapshot (the next operation removes it), but never
        // a `pending` without a snapshot: recovery could not undo a killed pause then.
        $engine = new class extends LSM_Testable_Hardening {
            /** @var array|null the stored option at the moment the artifacts are deleted */
            public $state_at_cleanup = null;

            public function cleanup_artifacts() {
                $this->state_at_cleanup = get_option('lsm_hardening');
                parent::cleanup_artifacts();
            }
        };
        $engine->content = $this->content;
        $engine->uploads = $this->uploads;
        $engine->plugin  = $this->h->plugin;
        $this->put('content', self::FOREIGN);

        $this->assertTrue($engine->set_rule('block_archives', true)['success']);

        $this->assertIsArray($engine->state_at_cleanup);
        $this->assertNull($engine->state_at_cleanup['pending'], 'pending is cleared before the snapshot goes');
        $this->assertTrue($engine->state_at_cleanup['rules']['block_archives'], 'rules are committed before the snapshot goes');
        $this->assertSame([], $this->artifacts());
    }

    public function test_write_failed_restores_the_original_bytes() {
        $this->put('content', self::FOREIGN);
        $failed = false;
        $this->h->put_hook = function ($file, $content) use (&$failed) {
            if (basename($file) === '.htaccess' && !$failed) {
                $failed = true;
                return file_put_contents($file, substr($content, 0, 60));
            }
            return null;
        };

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'write_failed', 'block_archives', 'content', self::FOREIGN);
    }

    public function test_asset_broken_when_the_server_rejects_the_directive() {
        // AllowOverride without AuthConfig: "Require" in .htaccess is a 500 for everything below wp-content.
        $this->server->rejected_directive = 'Require all denied';
        $this->put('content', self::FOREIGN);

        $result = $this->h->set_rule('block_debug_log', true);

        $this->assertFailedCleanly($result, 'asset_broken', 'block_debug_log', 'content', self::FOREIGN);
        $this->assertStringContainsString('500', $result['message']);
        $this->assertStringContainsString('rolled back', $result['message']);
    }

    public function test_asset_broken_when_the_anonymous_homepage_changes() {
        // A rewrite-mode page cache serves "/" from wp-content/cache/: the visitor sees the damage, the asset does not.
        $this->server->script('~^http://example\.test/$~', ['pass', LSM_Fake_Server::response(403, 'Forbidden')]);

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'asset_broken', 'block_archives', 'content', null);
        $this->assertStringContainsString('homepage', $result['message']);
    }

    public function test_asset_broken_when_the_homepage_body_goes_empty() {
        $this->server->script('~^http://example\.test/$~', ['pass', LSM_Fake_Server::response(200, '')]);
        $this->assertFailedCleanly($this->h->set_rule('block_archives', true), 'asset_broken', 'block_archives', 'content', null);
    }

    public function test_rule_ineffective_names_the_probe_a_front_end_nginx_still_serves() {
        $this->server->bypass_htaccess = '~\.zip$~';

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFailedCleanly($result, 'rule_ineffective', 'block_archives', 'content', null);
        $this->assertStringContainsString('.zip', $result['message']);
    }

    public function test_rule_ineffective_when_the_server_ignores_htaccess_for_the_php_probe() {
        $this->server->bypass_htaccess = '~\.php$~';
        $this->put('uploads', self::FOREIGN);

        $result = $this->h->set_rule('block_uploads_php', true);

        $this->assertFailedCleanly($result, 'rule_ineffective', 'block_uploads_php', 'uploads', self::FOREIGN);
    }

    public function test_loopback_blocked_after_the_write_is_rolled_back() {
        // Before: 404. After: the uploads directory answers 500 — never "403 effective".
        $this->server->script('~/uploads/lsm-probe-~', ['pass', LSM_Fake_Server::response(500, 'Internal Server Error')]);

        $result = $this->h->set_rule('block_uploads_php', true);

        $this->assertFailedCleanly($result, 'loopback_blocked', 'block_uploads_php', 'uploads', null);
    }

    public function test_a_cloudflare_challenge_403_is_not_an_effective_rule() {
        $challenge = LSM_Fake_Server::response(403, 'Just a moment...', ['cf-mitigated' => 'challenge']);
        $this->server->script('~/uploads/lsm-probe-~', ['pass', $challenge]);

        $result = $this->h->set_rule('block_uploads_php', true);

        $this->assertFailedCleanly($result, 'loopback_blocked', 'block_uploads_php', 'uploads', null);
    }

    public function test_pause_ineffective_foreign_rule_when_turning_archives_off_changes_nothing() {
        $this->h->set_rule('block_archives', true);
        $with_rule = $this->get('content');
        LSM_Test_Env::$log = [];
        $this->server->foreign_deny = '~\.wpress$~';

        $result = $this->h->set_rule('block_archives', false);

        $this->assertFalse($result['success']);
        $this->assertSame('pause_ineffective_foreign_rule', $result['reason']);
        $this->assertSame($with_rule, $this->get('content'), 'rolled back: our rule is still in the file');
        $this->assertTrue($this->h->get_state()['rules']['block_archives'], 'desired state unchanged');
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('pause_ineffective_foreign_rule', $result['status']['rules']['block_archives']['last_failure']['reason']);
        $this->assertSame([], $this->artifacts());
    }

    public function test_rollback_failed_when_the_original_cannot_be_restored() {
        $this->put('content', self::FOREIGN);
        $this->server->bypass_htaccess = '~\.zip$~';
        $writes = 0;
        $this->h->put_hook = function ($file) use (&$writes) {
            if (basename($file) !== '.htaccess') {
                return null;
            }
            $writes++;
            // 1 = our block, 2 = the restore (fails), 3 = the last-resort strip.
            return $writes === 2 ? false : null;
        };

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFalse($result['success']);
        $this->assertSame('rollback_failed', $result['reason']);
        $this->assertSame(3, $writes);
        $this->assertStringNotContainsString('LSM-HARDENING', $this->get('content'), 'last resort: the managed block is stripped');
        $this->assertStringContainsString('WebP Express', $this->get('content'));
        $this->assertSame('rollback_failed', $this->h->get_state()['rule_failures']['block_archives']['reason']);
        $this->assertNull($this->h->get_state()['pending']);
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_rollback_failed_when_wp_content_stays_broken_after_the_restore() {
        $this->put('content', self::FOREIGN);
        $broken = LSM_Fake_Server::response(500, 'Internal Server Error');
        $this->server->script('~ticket-ui\.css~', ['pass', $broken, $broken]);

        $result = $this->h->set_rule('block_archives', true);

        $this->assertFalse($result['success']);
        $this->assertSame('rollback_failed', $result['reason']);
        $this->assertSame(self::FOREIGN, $this->get('content'), 'the original bytes are back all the same');
        $this->assertFalse($this->h->get_state()['rules']['block_archives']);
    }
}

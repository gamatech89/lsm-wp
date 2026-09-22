<?php

/**
 * Crash recovery. A crash is simulated by a throwable from the fake server after
 * the write: like a killed PHP process, it leaves lock, pending, snapshot and probes behind.
 */
class HardeningRecoveryTest extends HardeningTestCase {

    const FOREIGN = "# BEGIN WebP Express\nAddType image/webp .webp\n# END WebP Express\n";

    /**
     * Run $operation and kill it at the first stylesheet request after the write.
     */
    private function crash_after_write(callable $operation) {
        $this->server->script('~ticket-ui\.css~', ['pass', new RuntimeException('killed')]);
        try {
            $operation();
            $this->fail('the operation was expected to die');
        } catch (RuntimeException $e) {
            $this->assertSame('killed', $e->getMessage());
        }
        $this->server->requests = [];
    }

    private function assertRecovered($rule) {
        $state = $this->h->get_state();
        $this->assertNull($state['pending']);
        $this->assertSame(
            ['at' => $this->h->time, 'action' => 'crash_recovery', 'rule' => $rule, 'ok' => false, 'reason' => 'crash_recovered', 'warnings' => []],
            $state['last_result']
        );
        $this->assertSame([], $this->artifacts(), 'snapshot and probe files are gone');
        $this->assertFalse(get_option('lsm_hardening_lock'));
        $this->assertSame([], $this->server->requests, 'recovery makes no HTTP request');
        $this->assertSame(['hardening_crash_recovered', 'warning'], array_slice(end(LSM_Test_Env::$log), 0, 2));
    }

    public function test_a_killed_operation_leaves_lock_pending_snapshot_and_probes_behind() {
        $this->put('content', self::FOREIGN);

        $this->crash_after_write(function () {
            $this->h->set_rule('block_archives', true);
        });

        $this->assertStringContainsString('LSM-HARDENING', $this->get('content'), 'the write had happened');
        $this->assertSame(['target' => 'content', 'op' => 'enable', 'started_at' => $this->h->time, 'existed' => true], $this->h->get_state()['pending']);
        $this->assertSame($this->h->time, get_option('lsm_hardening_lock'));
        $this->assertCount(3, $this->artifacts());
        $this->assertFalse($this->h->get_state()['rules']['block_archives'], 'rules are only committed after the self-test');
    }

    public function test_nothing_is_recovered_before_180_seconds_have_passed() {
        $this->put('content', self::FOREIGN);
        $this->crash_after_write(function () {
            $this->h->set_rule('block_archives', true);
        });

        $this->h->time += 180;
        $this->h->on_init();

        $this->assertNotNull($this->h->get_state()['pending']);
        $this->assertStringContainsString('LSM-HARDENING', $this->get('content'));
        $this->assertSame('busy', $this->h->set_rule('block_debug_log', true)['reason'], 'the dead lock still holds');
    }

    public function test_killed_enable_is_restored_from_the_snapshot() {
        $this->put('content', self::FOREIGN);
        $this->crash_after_write(function () {
            $this->h->set_rule('block_archives', true);
        });

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertSame(self::FOREIGN, $this->get('content'));
        $this->assertRecovered(null);
        $this->assertSame('off', $this->h->get_status()['rules']['block_archives']['state']);
    }

    public function test_killed_enable_on_a_site_without_the_file_deletes_it_again() {
        $this->crash_after_write(function () {
            $this->h->set_rule('block_uploads_php', true);
        });
        $this->assertFalse($this->h->get_state()['pending']['existed']);
        $this->assertSame('uploads', $this->h->get_state()['pending']['target']);

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertNull($this->get('uploads'));
        $this->assertRecovered(null);
    }

    public function test_killed_enable_without_snapshot_keeps_what_others_wrote_since() {
        $this->crash_after_write(function () {
            $this->h->set_rule('block_uploads_php', true);
        });
        file_put_contents($this->htaccess('uploads'), "Options -Indexes\n", FILE_APPEND);

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertSame("Options -Indexes\n", $this->get('uploads'));
    }

    public function test_killed_pause_puts_the_archive_rule_back() {
        $this->h->set_rule('block_archives', true);
        $with_rule = $this->get('content');
        $this->crash_after_write(function () {
            $this->h->pause(60);
        });
        $this->assertStringNotContainsString('wpress', $this->get('content'));

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertSame($with_rule, $this->get('content'));
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);
        $this->assertRecovered('block_archives');
    }

    public function test_killed_disable_puts_the_rule_back() {
        $this->h->set_rule('block_debug_log', true);
        $with_rule = $this->get('content');
        $this->crash_after_write(function () {
            $this->h->set_rule('block_debug_log', false);
        });
        $this->assertSame('disable', $this->h->get_state()['pending']['op']);

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertSame($with_rule, $this->get('content'));
        $this->assertTrue($this->h->get_state()['rules']['block_debug_log']);
        $this->assertRecovered(null);
    }

    public function test_killed_resume_is_rolled_forward_never_back() {
        $this->h->set_rule('block_archives', true);
        $with_rule = $this->get('content');
        $this->h->pause(15);
        $this->h->time += 901;
        $this->crash_after_write(function () {
            $this->h->auto_resume();
        });
        $this->assertSame('resume', $this->h->get_state()['pending']['op']);
        // Worst case: the process died before its write reached the disk.
        $this->put('content', '');

        $this->h->time += 181;
        $this->h->on_init();

        $this->assertSame($with_rule, $this->get('content'), 'the archive rule is in the file');
        $this->assertNull($this->h->get_state()['pause_until'], 'cleared after the read-back');
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);
        $this->assertRecovered('block_archives');
        $this->assertSame([], LSM_Test_Env::$actions, 'nothing left to auto-resume');
    }

    public function test_killed_resume_with_corrupt_markers_stays_paused_and_overdue() {
        $until = $this->h->time - 10;
        update_option('lsm_hardening', [
            'rules'       => ['block_archives' => true],
            'pause_until' => $until,
            'pending'     => ['target' => 'content', 'op' => 'resume', 'started_at' => $this->h->time - 500, 'existed' => true],
        ]);
        $this->put('content', "# END LSM-HARDENING\n");

        $this->h->on_init();

        $this->assertSame("# END LSM-HARDENING\n", $this->get('content'));
        $this->assertSame($until, $this->h->get_state()['pause_until']);
        $this->assertNull($this->h->get_state()['pending']);
        $this->assertTrue($this->h->get_status()['pause_overdue']);
        $this->assertCount(1, LSM_Test_Env::$actions, 'auto-resume is retried on this very request');
    }

    public function test_recovery_takes_the_lock_first() {
        $this->put('content', self::FOREIGN);
        $this->crash_after_write(function () {
            $this->h->set_rule('block_archives', true);
        });
        $this->h->time += 181;
        // Another request got there first and is recovering right now.
        update_option('lsm_hardening_lock', $this->h->time);
        $written = $this->get('content');

        $this->h->on_init();

        $this->assertSame($written, $this->get('content'));
        $this->assertNotNull($this->h->get_state()['pending']);
    }

    public function test_the_target_file_comes_from_the_enum_never_from_a_path() {
        $victim = $this->root . '/wp-config.php';
        file_put_contents($victim, '<?php // secrets');
        $this->put('content', $this->h->build_block('content', ['block_archives']) . "\n");
        file_put_contents($this->content . '/.htaccess.lsm-bak', self::FOREIGN);
        update_option('lsm_hardening', ['pending' => [
            'target'     => $victim,
            'file'       => $victim,
            'op'         => 'enable',
            'started_at' => $this->h->time - 181,
            'existed'    => false,
        ]]);

        $this->h->on_init();

        $this->assertSame('<?php // secrets', file_get_contents($victim));
        $this->assertSame(self::FOREIGN, $this->get('content'), 'an unknown target means wp-content/.htaccess');
    }

    public function test_a_damaged_pending_without_a_start_time_counts_as_old_and_is_recovered() {
        // DB restore, partial write, manual edit. on_init() runs on every request: an undefined
        // array key here would be a PHP warning on every page load.
        update_option('lsm_hardening', ['pending' => ['target' => 'content']]);

        $this->h->on_init();

        $state = $this->h->get_state();
        $this->assertNull($state['pending']);
        $this->assertSame('crash_recovered', $state['last_result']['reason']);
        $this->assertNull($this->get('content'), 'nothing to restore, nothing created');
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_recovery_also_runs_on_our_own_rest_routes_so_the_next_call_is_not_busy() {
        $this->put('content', self::FOREIGN);
        $this->crash_after_write(function () {
            $this->h->set_rule('block_archives', true);
        });
        $this->h->time += 181;
        $_SERVER['REQUEST_URI'] = '/wp-json/lsm/v1/hardening/rule';

        $this->h->on_init();
        $result = $this->h->set_rule('block_archives', true);

        $this->assertTrue($result['success']);
        $this->assertSame(self::FOREIGN . "\n" . $this->h->build_block('content', ['block_archives']) . "\n", $this->get('content'));
    }
}

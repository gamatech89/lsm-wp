<?php

/**
 * Auto-resume: cheap detection on init, the light path on shutdown, fail closed.
 */
class HardeningAutoResumeTest extends HardeningTestCase {

    /** @var string content of wp-content/.htaccess while paused */
    private $paused_file;

    /** @var int */
    private $until;

    protected function setUp(): void {
        parent::setUp();
        $this->h->set_rule('block_archives', true);
        $this->h->set_rule('block_debug_log', true);
        $this->h->pause(15);

        $this->paused_file = $this->get('content');
        $this->until       = $this->h->get_state()['pause_until'];

        $this->server->requests = [];
        LSM_Test_Env::$log      = [];
        LSM_Test_Env::$actions  = [];
    }

    private function expire() {
        $this->h->time = $this->until + 1;
    }

    private function assertStillPausedAndOverdue() {
        $this->assertSame($this->until, $this->h->get_state()['pause_until'], 'pause_until stays in the past');
        $status = $this->h->get_status();
        $this->assertSame('paused', $status['rules']['block_archives']['state']);
        $this->assertTrue($status['pause_overdue']);
    }

    // -------------------------------------------------------------------------
    // Detection on init
    // -------------------------------------------------------------------------

    public function test_init_registers_a_late_shutdown_callback_once_the_pause_is_overdue() {
        $this->expire();

        $this->h->on_init();

        $this->assertSame([['shutdown', [$this->h, 'run_auto_resume'], 9999]], LSM_Test_Env::$actions);
        $this->assertSame([], $this->server->requests, 'nothing runs inline');
        $this->assertSame($this->paused_file, $this->get('content'));
    }

    public function test_init_does_nothing_while_the_pause_is_running_or_absent() {
        $this->h->on_init();
        $this->h->time = $this->until;
        $this->h->on_init();
        $this->assertSame([], LSM_Test_Env::$actions, 'pause_until must be < now');

        $this->h->resume();
        $this->expire();
        $this->h->on_init();
        $this->assertSame([], LSM_Test_Env::$actions, 'nothing paused');
    }

    public function test_init_never_registers_in_cli() {
        $this->expire();
        $this->h->cli = true;
        $this->h->on_init();
        $this->assertSame([], LSM_Test_Env::$actions);
    }

    public function test_init_never_registers_on_our_own_hardening_routes() {
        $this->expire();

        $_SERVER['REQUEST_URI'] = '/wp-json/lsm/v1/hardening/resume';
        $this->h->on_init();
        unset($_SERVER['REQUEST_URI']);

        $_GET['rest_route'] = '/lsm/v1/hardening/status';
        $this->h->on_init();
        unset($_GET['rest_route']);

        $this->assertSame([], LSM_Test_Env::$actions);

        $_SERVER['REQUEST_URI'] = '/wp-json/lsm/v1/health';
        $this->h->on_init();
        $this->assertCount(1, LSM_Test_Env::$actions, 'other LSM routes (the uptime ping) do trigger it');
    }

    public function test_attempts_are_throttled_to_one_per_300_seconds() {
        $this->expire();
        // A failed attempt: the write never reaches the disk.
        $this->h->put_hook = function ($file, $content) {
            return basename($file) === '.htaccess' ? strlen($content) : null;
        };
        $this->h->auto_resume();
        $this->h->put_hook = null;
        $this->assertSame($this->h->time, $this->h->get_state()['last_attempt_at']);

        $this->h->on_init();
        $this->h->time += 300;
        $this->h->on_init();
        $this->assertSame([], LSM_Test_Env::$actions, '300 s later is still too early');

        $this->h->time += 1;
        $this->h->on_init();
        $this->assertCount(1, LSM_Test_Env::$actions);
    }

    // -------------------------------------------------------------------------
    // The light path
    // -------------------------------------------------------------------------

    public function test_shutdown_callback_answers_the_client_before_it_works() {
        $this->expire();
        $order = [];
        $this->h->put_hook = function ($file) use (&$order) {
            $order[] = 'write while finished=' . $this->h->finished;
            return null;
        };

        $this->h->run_auto_resume();

        $this->assertSame(1, $this->h->finished);
        $this->assertSame('write while finished=1', $order[0]);
        $this->assertNull($this->h->get_state()['pause_until']);
    }

    public function test_without_a_finish_function_the_shutdown_callback_does_nothing() {
        $this->expire();
        $this->h->can_finish = false;
        $before = get_option('lsm_hardening');

        $this->h->run_auto_resume();

        $this->assertSame($before, get_option('lsm_hardening'));
        $this->assertSame([], $this->server->requests);
        $this->assertSame($this->paused_file, $this->get('content'));
        $this->assertFalse(get_option('lsm_hardening_lock'));
        $this->assertSame(0, $this->h->finished);
        $this->assertSame([], $this->artifacts());
    }

    public function test_light_path_puts_the_rule_back_with_two_loopbacks_and_no_probes() {
        $this->expire();
        $seen_pending = null;
        $this->h->put_hook = function ($file) use (&$seen_pending) {
            if (basename($file) === '.htaccess') {
                $seen_pending = get_option('lsm_hardening')['pending'];
            }
            return null;
        };

        $this->h->auto_resume();

        $this->assertSame($this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n", $this->get('content'));
        $this->assertSame(['target' => 'content', 'op' => 'resume', 'started_at' => $this->h->time, 'existed' => true], $seen_pending);

        $state = $this->h->get_state();
        $this->assertNull($state['pause_until']);
        $this->assertNull($state['pending']);
        $this->assertSame($this->h->time, $state['last_attempt_at']);
        $this->assertSame(
            ['at' => $this->h->time, 'action' => 'auto_resume', 'rule' => 'block_archives', 'ok' => true, 'reason' => null, 'warnings' => []],
            $state['last_result']
        );
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);

        $this->assertCount(2, $this->server->requests);
        $this->assertCount(2, $this->server->requests_matching('~ticket-ui\.css~'));
        $this->assertSame([], $this->artifacts());
        $this->assertFalse(get_option('lsm_hardening_lock'));
        $this->assertSame('hardening_applied', LSM_Test_Env::$log[0][0]);
    }

    private function assertBlockKeptUnverified() {
        $state = $this->h->get_state();
        $this->assertSame($this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n", $this->get('content'), 'the block is kept');
        $this->assertNull($state['pause_until']);
        $this->assertTrue($state['last_result']['ok']);
        $this->assertSame(['unverified'], $state['last_result']['warnings']);
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);
    }

    public function test_fail_closed_when_the_loopback_gets_no_answer_before_the_write() {
        $this->expire();
        $this->server->script('~ticket-ui\.css~', [new WP_Error('http_request_failed', 'cURL error 28')]);
        $this->h->auto_resume();
        $this->assertBlockKeptUnverified();
    }

    public function test_fail_closed_when_a_waf_answers_every_loopback_with_403() {
        $this->expire();
        $this->server->always('~.~', LSM_Fake_Server::response(403, 'Forbidden'));
        $this->h->auto_resume();
        $this->assertBlockKeptUnverified();
    }

    public function test_fail_closed_when_the_loopback_gets_no_answer_after_the_write() {
        $this->expire();
        $this->server->script('~ticket-ui\.css~', ['pass', new WP_Error('http_request_failed', 'cURL error 28')]);
        $this->h->auto_resume();
        $this->assertBlockKeptUnverified();
    }

    public function test_unverified_when_the_plugin_lives_outside_wp_content() {
        $this->expire();
        $this->h->plugin = $this->root . '/elsewhere/landeseiten-maintenance/';

        $this->h->auto_resume();

        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame(['unverified'], $this->h->get_state()['last_result']['warnings']);
        $this->assertSame([], $this->server->requests);
    }

    public function test_rolls_back_only_when_the_stylesheet_goes_from_200_to_non_200() {
        $this->expire();
        $this->server->rejected_directive = 'Require all denied';
        // The paused file still holds the debug.log rule, so take "Require" out of it for a clean 200 before.
        $this->put('content', "Options -Indexes\n");

        $this->h->auto_resume();

        $this->assertSame("Options -Indexes\n", $this->get('content'), 'rolled back to the paused file');
        $this->assertStillPausedAndOverdue();

        $state = $this->h->get_state();
        $this->assertFalse($state['last_result']['ok']);
        $this->assertSame('auto_resume', $state['last_result']['action']);
        $this->assertSame('asset_broken', $state['last_result']['reason']);
        $this->assertSame('asset_broken', $state['rule_failures']['block_archives']['reason']);
        $this->assertNull($state['pending']);
        $this->assertSame([], $this->artifacts());
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_pause_until_is_only_cleared_after_the_read_back() {
        $this->expire();
        // The write "succeeds" but nothing reaches the disk.
        $this->h->put_hook = function ($file, $content) {
            return basename($file) === '.htaccess' ? strlen($content) : null;
        };

        $this->h->auto_resume();

        $this->assertSame($this->paused_file, $this->get('content'));
        $this->assertStillPausedAndOverdue();
        $this->assertSame('write_failed', $this->h->get_state()['last_result']['reason']);
    }

    public function test_corrupt_markers_leave_the_pause_overdue() {
        $this->expire();
        $this->put('content', "# BEGIN LSM-HARDENING\n");

        $this->h->auto_resume();

        $this->assertSame("# BEGIN LSM-HARDENING\n", $this->get('content'));
        $this->assertStillPausedAndOverdue();
        $this->assertSame('markers_corrupt', $this->h->get_state()['last_result']['reason']);
    }

    public function test_a_file_changed_while_the_stylesheet_was_fetched_is_never_overwritten() {
        $this->expire();
        $server   = $this->server;
        $htaccess = $this->htaccess('content');
        $appended = false;
        // Something else rewrites wp-content/.htaccess while our "before" loopback runs.
        LSM_Test_Env::$http = function ($url, $args) use ($server, $htaccess, &$appended) {
            if (!$appended) {
                $appended = true;
                file_put_contents($htaccess, "ErrorDocument 404 /404.html\n", FILE_APPEND);
            }
            return $server->handle($url, $args);
        };

        $this->h->auto_resume();

        $this->assertTrue($appended);
        $this->assertSame($this->paused_file . "ErrorDocument 404 /404.html\n", $this->get('content'), 'the stale candidate never reached the disk');
        $this->assertStillPausedAndOverdue();
        $this->assertSame('write_failed', $this->h->get_state()['last_result']['reason']);
        $this->assertNull($this->h->get_state()['pending']);
        $this->assertSame([], $this->artifacts());
        $this->assertFalse(get_option('lsm_hardening_lock'));

        // The next attempt starts from the fresh bytes and keeps the foreign line.
        $this->h->auto_resume();
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertStringContainsString("ErrorDocument 404 /404.html\n", $this->get('content'));
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);
    }

    public function test_busy_returns_silently() {
        $this->expire();
        $before = get_option('lsm_hardening');
        add_option('lsm_hardening_lock', $this->h->time, '', 'no');

        $this->h->auto_resume();

        $this->assertSame($before, get_option('lsm_hardening'), 'no last_attempt_at, no last_result');
        $this->assertSame([], $this->server->requests);
        $this->assertSame([], LSM_Test_Env::$log);
        $this->assertSame($this->h->time, get_option('lsm_hardening_lock'));
    }

    public function test_nothing_happens_when_the_pause_ended_between_init_and_shutdown() {
        $this->expire();
        $this->h->on_init();
        $this->h->resume();
        $this->server->requests = [];
        $last_result = $this->h->get_state()['last_result'];

        $this->h->run_auto_resume();

        $this->assertSame($last_result, $this->h->get_state()['last_result']);
        $this->assertSame([], $this->server->requests);
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_a_rule_somebody_already_put_back_just_clears_the_pause() {
        $this->expire();
        $this->put('content', $this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n");
        $writes = 0;
        $this->h->put_hook = function ($file) use (&$writes) {
            if (basename($file) === '.htaccess') {
                $writes++;
            }
            return null;
        };

        $this->h->auto_resume();

        $this->assertSame(0, $writes);
        $this->assertNull($this->h->get_state()['pause_until']);
    }
}

<?php

/**
 * pause(), pause while paused, failed pause, resume().
 */
class HardeningPauseTest extends HardeningTestCase {

    protected function setUp(): void {
        parent::setUp();
        $this->h->set_rule('block_archives', true);
        $this->h->set_rule('block_debug_log', true);
        $this->server->requests = [];
        LSM_Test_Env::$log      = [];
    }

    private function htaccess_writes() {
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

    public function test_invalid_minutes() {
        foreach ([0, 45, 61, -15, '60', 60.0, null] as $minutes) {
            $result = $this->h->pause($minutes);
            $this->assertFalse($result['success']);
            $this->assertSame('invalid_minutes', $result['reason']);
        }
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame([], $this->server->requests);
    }

    public function test_pause_takes_only_the_archive_rule_out_and_keeps_it_desired() {
        $seen_op = null;
        $this->h->put_hook = function ($file) use (&$seen_op) {
            if (basename($file) === '.htaccess') {
                $seen_op = get_option('lsm_hardening')['pending']['op'];
            }
            return null;
        };

        $result = $this->h->pause(60);

        $this->assertTrue($result['success']);
        $this->assertSame([], $result['warnings']);
        $this->assertSame('pause', $seen_op);
        $this->assertSame($this->h->build_block('content', ['block_debug_log']) . "\n", $this->get('content'));

        $state = $this->h->get_state();
        $this->assertTrue($state['rules']['block_archives'], 'desired stays true');
        $this->assertSame($this->h->time + 3600, $state['pause_until']);

        $this->assertSame('paused', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('on', $result['status']['rules']['block_debug_log']['state']);
        $this->assertSame($this->h->time + 3600, $result['status']['pause_until']);
        $this->assertFalse($result['status']['pause_overdue']);
        $this->assertSame('pause', $result['status']['last_result']['action']);
        $this->assertSame([], $this->artifacts());
    }

    public function test_each_allowed_duration() {
        foreach ([15 => 900, 30 => 1800] as $minutes => $seconds) {
            $this->assertTrue($this->h->pause($minutes)['success']);
            $this->assertSame($this->h->time + $seconds, $this->h->get_state()['pause_until']);
            $this->h->resume();
        }
    }

    public function test_pause_requires_the_rule_to_be_on() {
        $this->h->set_rule('block_archives', false);

        $result = $this->h->pause(30);
        $this->assertSame('not_enabled', $result['reason']);

        // manual: a hand-written block cannot be paused, it has to be adopted first.
        $this->put('content', LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT);
        $this->assertSame('manual', $this->h->get_status()['rules']['block_archives']['state']);
        $this->assertSame('not_enabled', $this->h->pause(30)['reason']);

        // drift: desired, but not in the file.
        $this->put('content', '');
        update_option('lsm_hardening', ['rules' => ['block_archives' => true]]);
        $this->assertSame('not_enabled', $this->h->pause(30)['reason']);

        $this->assertNull($this->h->get_state()['pause_until']);
    }

    public function test_pause_on_an_unsupported_server() {
        $this->h->software = '';
        $result = $this->h->pause(15);
        $this->assertSame('unsupported', $result['reason']);
        $this->assertStringContainsString('unknown_server', $result['message']);
    }

    public function test_pausing_while_paused_only_moves_pause_until() {
        $this->h->pause(60);
        $paused_file = $this->get('content');
        $this->server->requests = [];
        $writes = $this->htaccess_writes();
        $this->h->time += 600;

        $result = $this->h->pause(15);

        $this->assertTrue($result['success']);
        $this->assertSame($this->h->time + 900, $this->h->get_state()['pause_until'], 'now + minutes, even when that is earlier than before');
        $this->assertSame(0, $writes->n);
        $this->assertSame($paused_file, $this->get('content'));
        $this->assertSame([], $this->server->requests);
        $this->assertSame('paused', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('pause', $result['status']['last_result']['action']);
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_pausing_while_paused_respects_the_lock() {
        $this->h->pause(60);
        $until = $this->h->get_state()['pause_until'];
        add_option('lsm_hardening_lock', $this->h->time, '', 'no');

        $result = $this->h->pause(15);

        $this->assertSame('busy', $result['reason']);
        $this->assertSame($until, $this->h->get_state()['pause_until']);
    }

    public function test_a_failed_pause_restores_the_whole_previous_state() {
        $with_rule = $this->get('content');
        $before    = $this->h->get_state();
        $this->server->foreign_deny = '~\.wpress$~';

        $result = $this->h->pause(60);

        $this->assertFalse($result['success']);
        $this->assertSame('pause_ineffective_foreign_rule', $result['reason']);
        $this->assertSame($with_rule, $this->get('content'), 'the archive rule is back in the file');

        $after = $this->h->get_state();
        $this->assertNull($after['pause_until'], 'pause_until as before');
        $this->assertSame($before['rules'], $after['rules']);
        $this->assertNull($after['pending']);
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('pause', $result['status']['last_result']['action']);
        $this->assertFalse($result['status']['last_result']['ok']);
        $this->assertSame([], $this->artifacts());
    }

    public function test_a_failed_pause_while_the_site_breaks_is_rolled_back_too() {
        $with_rule = $this->get('content');
        $this->server->script('~^http://example\.test/$~', ['pass', LSM_Fake_Server::response(500, 'Internal Server Error')]);

        $result = $this->h->pause(30);

        $this->assertSame('asset_broken', $result['reason']);
        $this->assertSame($with_rule, $this->get('content'));
        $this->assertNull($this->h->get_state()['pause_until']);
    }

    public function test_resume_is_an_idempotent_no_op_when_nothing_is_paused() {
        $before = get_option('lsm_hardening');

        $result = $this->h->resume();

        $this->assertTrue($result['success']);
        $this->assertNull($result['reason']);
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame($before, get_option('lsm_hardening'));
        $this->assertSame([], $this->server->requests);
    }

    public function test_resume_puts_the_rule_back_and_clears_the_pause() {
        $this->h->pause(60);

        $result = $this->h->resume();

        $this->assertTrue($result['success']);
        $this->assertSame($this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n", $this->get('content'));
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertSame('resume', $result['status']['last_result']['action']);
        $this->assertNull($result['status']['pause_until']);
    }

    public function test_an_edge_cache_cannot_fake_a_failed_resume() {
        // During the pause the "before" fetch of the fresh .zip probe is a 200 and lands in the edge
        // cache. Were the "after" fetch to use the same URL, "Re-enable now" and the platform backstop
        // would fail with rule_ineffective on every Cloudflare-proxied site and the rule would stay out.
        $this->h->pause(60);
        $edge = $this->put_an_edge_cache_in_front();

        $result = $this->h->resume();

        $this->assertTrue($result['success'], (string) $result['reason']);
        $this->assertCount(1, $edge, 'the edge did cache the "before" 200 of the .zip probe');
        $this->assertSame('on', $result['status']['rules']['block_archives']['state']);
        $this->assertNull($this->h->get_state()['pause_until']);
    }

    public function test_a_failed_resume_stays_paused_and_turns_overdue() {
        $this->h->pause(15);
        $paused_file = $this->get('content');
        $until       = $this->h->get_state()['pause_until'];
        $this->server->bypass_htaccess = '~\.zip$~';

        $result = $this->h->resume();

        $this->assertSame('rule_ineffective', $result['reason']);
        $this->assertSame($paused_file, $this->get('content'));
        $this->assertSame($until, $this->h->get_state()['pause_until']);
        $this->assertSame('paused', $result['status']['rules']['block_archives']['state']);

        $this->h->time = $until + 1;
        $this->assertTrue($this->h->get_status()['pause_overdue']);
    }

    public function test_turning_the_rule_on_or_off_ends_a_pause() {
        $this->h->pause(60);
        $this->assertTrue($this->h->set_rule('block_archives', true)['success']);
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame('on', $this->h->get_status()['rules']['block_archives']['state']);

        $this->h->pause(60);
        $result = $this->h->set_rule('block_archives', false);
        $this->assertTrue($result['success']);
        $this->assertNull($this->h->get_state()['pause_until']);
        $this->assertSame('off', $result['status']['rules']['block_archives']['state']);
    }
}

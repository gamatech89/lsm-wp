<?php

/**
 * Deactivation cleanup.
 */
class HardeningDeactivateTest extends HardeningTestCase {

    const FOREIGN = "# BEGIN WebP Express\nAddType image/webp .webp\n# END WebP Express\n";

    public function test_deactivation_removes_both_blocks_and_resets_the_state() {
        $this->put('content', self::FOREIGN);
        $this->h->set_rule('block_archives', true);
        $this->h->set_rule('block_debug_log', true);
        $this->h->set_rule('block_uploads_php', true);
        $this->h->pause(60);
        $this->server->requests = [];
        LSM_Test_Env::$log      = [];

        $this->h->deactivate();

        $this->assertSame(self::FOREIGN, $this->get('content'), 'foreign bytes untouched');
        $this->assertSame('', $this->get('uploads'), 'the uploads file held nothing but our block');

        $state = $this->h->get_state();
        $this->assertSame(['block_archives' => false, 'block_debug_log' => false, 'block_uploads_php' => false], $state['rules']);
        $this->assertNull($state['pause_until']);
        $this->assertNull($state['pending']);
        $this->assertSame(
            ['at' => $this->h->time, 'action' => 'deactivate', 'rule' => null, 'ok' => true, 'reason' => null, 'warnings' => []],
            $state['last_result']
        );
        $this->assertFalse(get_option('lsm_hardening_lock'));

        $this->assertSame([], $this->server->requests, 'no self-test');
        $this->assertSame([['hardening_deactivated', 'info', ['removed_from' => ['content', 'uploads']]]], LSM_Test_Env::$log);

        $rules = $this->h->get_status()['rules'];
        $this->assertSame(['off', 'off', 'off'], array_column($rules, 'state'), 'reactivation truthfully shows Off');
    }

    public function test_deactivation_skips_the_server_preflight() {
        $this->h->set_rule('block_archives', true);
        // WP-CLI: no SERVER_SOFTWARE.
        $this->h->software = '';
        $this->h->cli      = true;

        $this->h->deactivate();

        $this->assertStringNotContainsString('LSM-HARDENING', (string) $this->get('content'));
    }

    public function test_deactivation_leaves_manual_blocks_and_corrupt_files_alone() {
        $this->put('uploads', LSM_Htaccess_Fixtures::AUDITED_UPLOADS);
        $corrupt = "# BEGIN LSM-HARDENING\n<Files \"debug.log\">\n";
        $this->put('content', $corrupt);

        $this->h->deactivate();

        $this->assertSame(LSM_Htaccess_Fixtures::AUDITED_UPLOADS, $this->get('uploads'));
        $this->assertSame($corrupt, $this->get('content'));
    }

    public function test_deactivation_cleans_up_after_a_killed_operation() {
        file_put_contents($this->content . '/.htaccess.lsm-bak', 'x');
        file_put_contents($this->content . '/lsm-probe-0123456789abcdef.wpress', 'x');
        update_option('lsm_hardening', ['pending' => ['target' => 'content', 'op' => 'enable', 'started_at' => $this->h->time, 'existed' => true]]);
        add_option('lsm_hardening_lock', $this->h->time, '', 'no');

        $this->h->deactivate();

        $this->assertSame([], $this->artifacts());
        $this->assertNull($this->h->get_state()['pending']);
        $this->assertFalse(get_option('lsm_hardening_lock'));
    }

    public function test_deactivation_on_a_site_that_never_used_the_feature_touches_no_file() {
        $this->h->deactivate();

        $this->assertNull($this->get('content'));
        $this->assertNull($this->get('uploads'));
    }
}

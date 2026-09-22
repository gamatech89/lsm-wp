<?php

/**
 * State storage, static preflight and status-from-file.
 */
class HardeningStatusTest extends HardeningTestCase {

    private function state_of($rule) {
        return $this->h->get_status()['rules'][$rule]['state'];
    }

    public function test_default_state_has_everything_off_and_nothing_pending() {
        $this->assertSame([
            'rules'           => ['block_archives' => false, 'block_debug_log' => false, 'block_uploads_php' => false],
            'pause_until'     => null,
            'last_attempt_at' => null,
            'pending'         => null,
            'last_result'     => null,
            'rule_failures'   => [],
        ], $this->h->get_state());
    }

    public function test_a_damaged_option_is_read_as_defaults() {
        update_option('lsm_hardening', 'not-an-array');
        $this->assertFalse($this->h->get_state()['rules']['block_archives']);

        update_option('lsm_hardening', ['rules' => ['block_archives' => 1, 'bogus' => true], 'pause_until' => '1790000600']);
        $state = $this->h->get_state();
        $this->assertSame(['block_archives' => true, 'block_debug_log' => false, 'block_uploads_php' => false], $state['rules']);
        $this->assertSame(1790000600, $state['pause_until']);
    }

    public function test_status_shape_on_a_fresh_site() {
        LSM_Test_Env::$db_var = 7;

        $off = ['state' => 'off', 'desired' => false, 'unsupported_reason' => null, 'last_failure' => null];
        $this->assertSame([
            'plugin_version'      => LSM_VERSION,
            'server'              => 'Apache',
            'rules'               => ['block_archives' => $off, 'block_debug_log' => $off, 'block_uploads_php' => $off],
            'pause_until'         => null,
            'pause_overdue'       => false,
            'archive_attachments' => 7,
            'last_result'         => null,
        ], $this->h->get_status());

        $this->assertCount(1, LSM_Test_Env::$db_queries);
        $this->assertStringContainsString("FROM wp_posts WHERE post_type = 'attachment'", LSM_Test_Env::$db_queries[0]);
        $this->assertStringContainsString("'application/zip'", LSM_Test_Env::$db_queries[0]);
        $this->assertStringContainsString("'application/x-gzip'", LSM_Test_Env::$db_queries[0]);
    }

    public function test_on_is_read_from_the_file_even_when_desired_is_false() {
        $this->put('content', "Options -Indexes\n\n" . $this->h->build_block('content', ['block_archives']) . "\n");

        $rules = $this->h->get_status()['rules'];
        $this->assertSame('on', $rules['block_archives']['state']);
        $this->assertFalse($rules['block_archives']['desired']);
        $this->assertSame('off', $rules['block_debug_log']['state']);
    }

    public function test_on_survives_reindenting_inside_the_markers() {
        $block = str_replace("\n  ", "\n\t\t", $this->h->build_block('uploads', ['block_uploads_php']));
        $this->put('uploads', $block . "\n");
        $this->assertSame('on', $this->state_of('block_uploads_php'));
    }

    public function test_drift_when_desired_but_not_in_the_file() {
        update_option('lsm_hardening', ['rules' => ['block_uploads_php' => true, 'block_debug_log' => true]]);
        // The content file has a block, but only with the archive rule.
        $this->put('content', $this->h->build_block('content', ['block_archives']) . "\n");

        $rules = $this->h->get_status()['rules'];
        $this->assertSame('drift', $rules['block_uploads_php']['state']);
        $this->assertTrue($rules['block_uploads_php']['desired']);
        $this->assertSame('drift', $rules['block_debug_log']['state']);
        $this->assertSame('on', $rules['block_archives']['state']);
    }

    public function test_manual_when_a_recognised_hand_written_block_is_in_the_file() {
        $this->put('uploads', "<FilesMatch \"\\.php$\">\nRequire all denied\n</FilesMatch>\n");
        $this->put('content', "<Files \"debug.log\">\nDeny from all\n</Files>\n");

        $this->assertSame('manual', $this->state_of('block_uploads_php'));
        $this->assertSame('manual', $this->state_of('block_debug_log'));
        $this->assertSame('off', $this->state_of('block_archives'));
    }

    public function test_manual_wins_over_drift_and_on_wins_over_manual() {
        update_option('lsm_hardening', ['rules' => ['block_debug_log' => true]]);
        $manual = "<Files \"debug.log\">\nDeny from all\n</Files>\n";

        $this->put('content', $manual);
        $this->assertSame('manual', $this->state_of('block_debug_log'));

        $this->put('content', $manual . "\n" . $this->h->build_block('content', ['block_debug_log']) . "\n");
        $this->assertSame('on', $this->state_of('block_debug_log'));
    }

    public function test_paused_and_overdue() {
        update_option('lsm_hardening', ['rules' => ['block_archives' => true], 'pause_until' => $this->h->time + 600]);

        $status = $this->h->get_status();
        $this->assertSame('paused', $status['rules']['block_archives']['state']);
        $this->assertSame($this->h->time + 600, $status['pause_until']);
        $this->assertFalse($status['pause_overdue']);

        $this->h->time += 601;
        $status = $this->h->get_status();
        $this->assertSame('paused', $status['rules']['block_archives']['state']);
        $this->assertTrue($status['pause_overdue']);
    }

    public function test_pause_only_ever_shows_on_the_archive_rule() {
        update_option('lsm_hardening', ['pause_until' => $this->h->time + 600]);
        $this->assertSame('off', $this->state_of('block_debug_log'));
        $this->assertSame('off', $this->state_of('block_uploads_php'));
    }

    public function test_corrupt_markers_are_not_on() {
        update_option('lsm_hardening', ['rules' => ['block_archives' => true]]);
        $this->put('content', "# BEGIN LSM-HARDENING\n" . implode("\n", $this->h->rule_lines('block_archives')) . "\n");
        $this->assertSame('drift', $this->state_of('block_archives'));
    }

    public function test_last_failure_and_last_result_are_passed_through() {
        $failure = ['at' => 1790000000, 'reason' => 'rule_ineffective'];
        $result  = ['at' => 1790000000, 'action' => 'enable', 'rule' => 'block_uploads_php', 'ok' => false, 'reason' => 'rule_ineffective', 'warnings' => []];
        update_option('lsm_hardening', ['rule_failures' => ['block_uploads_php' => $failure], 'last_result' => $result]);

        $status = $this->h->get_status();
        $this->assertSame($failure, $status['rules']['block_uploads_php']['last_failure']);
        $this->assertNull($status['rules']['block_archives']['last_failure']);
        $this->assertSame($result, $status['last_result']);
    }

    public function test_unsupported_multisite() {
        LSM_Test_Env::$multisite = true;
        foreach (LSM_Hardening::RULES as $rule) {
            $this->assertSame('multisite', $this->h->preflight($rule));
        }
        $rules = $this->h->get_status()['rules'];
        $this->assertSame('unsupported', $rules['block_archives']['state']);
        $this->assertSame('multisite', $rules['block_archives']['unsupported_reason']);
    }

    public function test_unsupported_openlitespeed() {
        $this->h->software        = 'LiteSpeed';
        $_SERVER['LSWS_EDITION'] = 'Openlitespeed 1.7.19';

        $this->assertSame('openlitespeed', $this->h->preflight('block_archives'));
        $this->assertSame('OpenLiteSpeed', $this->h->get_status()['server']);
    }

    public function test_litespeed_enterprise_is_supported() {
        $this->h->software        = 'LiteSpeed';
        $_SERVER['LSWS_EDITION'] = 'LiteSpeed Web Server/Enterprise';

        $this->assertNull($this->h->preflight('block_archives'));
        $this->assertSame('LiteSpeed', $this->h->get_status()['server']);
    }

    public function test_unsupported_unknown_server() {
        $this->h->software = 'nginx/1.24.0';
        $this->assertSame('unknown_server', $this->h->preflight('block_debug_log'));
        $this->assertSame('nginx/1.24.0', $this->h->get_status()['server']);

        // WP-CLI: wp_fix_server_vars() leaves SERVER_SOFTWARE empty.
        $this->h->software = '';
        $this->assertSame('unknown_server', $this->h->preflight('block_debug_log'));
        $this->assertSame('unknown', $this->h->get_status()['server']);
    }

    /**
     * chmod proves nothing for root (CI containers): it may write everywhere.
     */
    private function skip_as_root() {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('Running as root: every file is writable.');
        }
    }

    public function test_unsupported_not_writable_file() {
        $this->skip_as_root();
        $this->put('uploads', "Options -Indexes\n");
        chmod($this->htaccess('uploads'), 0444);

        $this->assertSame('not_writable', $this->h->preflight('block_uploads_php'));
        $this->assertNull($this->h->preflight('block_archives'), 'the content file is a different file');

        $rules = $this->h->get_status()['rules'];
        $this->assertSame('unsupported', $rules['block_uploads_php']['state']);
        $this->assertSame('not_writable', $rules['block_uploads_php']['unsupported_reason']);
        $this->assertSame('off', $rules['block_archives']['state']);
    }

    public function test_unsupported_not_writable_directory_when_the_file_is_absent() {
        $this->skip_as_root();
        chmod($this->uploads, 0555);
        $this->assertSame('not_writable', $this->h->preflight('block_uploads_php'));
        chmod($this->uploads, 0777);
        $this->assertNull($this->h->preflight('block_uploads_php'));
    }

    public function test_a_file_that_cannot_be_read_is_unsupported_and_never_taken_for_empty() {
        $this->skip_as_root();
        $this->put('content', "<Files \"debug.log\">\nDeny from all\n</Files>\n");
        // Writable but not readable: a write built from "empty" would destroy what is in it.
        chmod($this->htaccess('content'), 0200);

        $this->assertSame('not_writable', $this->h->preflight('block_archives'));
        $this->assertTrue($this->h->file_facts('content')['corrupt'], 'the writers that skip the preflight must refuse too');

        $rules = $this->h->get_status()['rules'];
        $this->assertSame('unsupported', $rules['block_debug_log']['state']);
        $this->assertSame('not_writable', $rules['block_debug_log']['unsupported_reason']);
        $this->assertSame('off', $rules['block_uploads_php']['state'], 'the uploads file is a different file');
    }

    public function test_unsupported_wins_over_paused() {
        LSM_Test_Env::$multisite = true;
        update_option('lsm_hardening', ['pause_until' => $this->h->time + 600]);
        $this->assertSame('unsupported', $this->state_of('block_archives'));
    }
}

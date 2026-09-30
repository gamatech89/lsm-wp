<?php

use PHPUnit\Framework\TestCase;

/**
 * With LSM_TICKETING_ENABLED false (the shipped default in 2.10.1) nothing in
 * the plugin may send a ticket: every ticket AJAX action answers 503
 * "temporarily disabled" and the real handlers are never registered.
 */
class TicketingKillSwitchTest extends TestCase {

    const ACTIONS = ['lsm_submit_support', 'lsm_tickets_list', 'lsm_ticket_detail', 'lsm_ticket_reply', 'lsm_ticket_attachment', 'lsm_tickets_unread'];

    protected function setUp(): void {
        LSM_Test_Env::reset();
        LSM_Test_Json::$errors = [];
    }

    public function test_the_shipped_default_is_off() {
        $source = file_get_contents(LSM_PLUGIN_DIR . 'landeseiten-maintenance.php');

        $this->assertSame(1, preg_match("/define\('LSM_TICKETING_ENABLED', (true|false)\);/", $source, $m));
        $this->assertSame('false', $m[1]);
    }

    public function test_every_ticket_action_is_routed_to_the_disabled_answer() {
        new LSM_Support();

        $hooked = [];
        foreach (LSM_Test_Env::$actions as [$hook, $callback]) {
            $hooked[$hook] = is_array($callback) ? $callback[1] : $callback;
        }

        foreach (self::ACTIONS as $action) {
            $this->assertSame('ajax_ticketing_disabled', $hooked['wp_ajax_' . $action] ?? null, $action);
        }
        $this->assertNotContains('handle_submit', $hooked, 'the real submit handler must not be registered');
        $this->assertNotContains('ajax_ticket_reply', $hooked);
    }

    public function test_the_disabled_answer_is_a_503_with_a_message() {
        (new LSM_Support())->ajax_ticketing_disabled();

        $this->assertCount(1, LSM_Test_Json::$errors);
        [$payload, $status] = LSM_Test_Json::$errors[0];
        $this->assertSame(503, $status);
        $this->assertStringContainsString('temporarily disabled', $payload['message']);
    }
}

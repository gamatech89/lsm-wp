<?php

/**
 * The four lsm/v1/hardening/* endpoints.
 */
class HardeningRestTest extends HardeningTestCase {

    /** @var LSM_API */
    private $api;

    protected function setUp(): void {
        parent::setUp();
        $this->api = new LSM_API();
    }

    private function assertHardeningShape(WP_REST_Response $response) {
        $this->assertSame(200, $response->get_status());
        $this->assertSame(['Cache-Control' => 'no-store, private'], $response->get_headers());

        $data = $response->get_data();
        $this->assertSame(['success', 'reason', 'message', 'warnings', 'status'], array_keys($data), 'top level, no data wrapper');
        $this->assertIsBool($data['success']);
        $this->assertIsString($data['message']);
        $this->assertIsArray($data['warnings']);
        $this->assertSame(
            ['plugin_version', 'server', 'rules', 'pause_until', 'pause_overdue', 'archive_attachments', 'last_result'],
            array_keys($data['status'])
        );
        $this->assertSame(LSM_Hardening::RULES, array_keys($data['status']['rules']));
        foreach ($data['status']['rules'] as $rule) {
            $this->assertSame(['state', 'desired', 'unsupported_reason', 'last_failure'], array_keys($rule));
        }
        return $data;
    }

    public function test_the_four_routes_are_registered_behind_authenticate() {
        $this->api->register_routes();

        $expected = [
            'GET lsm/v1/hardening/status'  => 'get_hardening_status',
            'POST lsm/v1/hardening/rule'   => 'set_hardening_rule',
            'POST lsm/v1/hardening/pause'  => 'pause_hardening',
            'POST lsm/v1/hardening/resume' => 'resume_hardening',
        ];
        foreach ($expected as $route => $method) {
            $this->assertArrayHasKey($route, LSM_Test_Env::$routes);
            $this->assertSame([$this->api, $method], LSM_Test_Env::$routes[$route]['callback']);
            $this->assertSame([$this->api, 'authenticate'], LSM_Test_Env::$routes[$route]['permission_callback']);
            $this->assertArrayNotHasKey('args', LSM_Test_Env::$routes[$route], 'house style: manual validation in the callback');
        }
    }

    public function test_status() {
        LSM_Test_Env::$db_var = 3;

        $data = $this->assertHardeningShape($this->api->get_hardening_status());

        $this->assertTrue($data['success']);
        $this->assertNull($data['reason']);
        $this->assertSame([], $data['warnings']);
        $this->assertSame(3, $data['status']['archive_attachments']);
        $this->assertSame('off', $data['status']['rules']['block_archives']['state']);
        $this->assertSame([], $this->server->requests, 'a status read makes no loopback request');
    }

    public function test_rule_enable_and_the_exact_json() {
        $response = $this->api->set_hardening_rule(new WP_REST_Request(['rule' => 'block_archives', 'enabled' => true]));
        $data     = $this->assertHardeningShape($response);

        $off = ['state' => 'off', 'desired' => false, 'unsupported_reason' => null, 'last_failure' => null];
        $this->assertSame([
            'success'  => true,
            'reason'   => null,
            'message'  => 'Applied and verified',
            'warnings' => [],
            'status'   => [
                'plugin_version' => LSM_VERSION,
                'server'         => 'Apache',
                'rules'          => [
                    'block_archives'    => ['state' => 'on', 'desired' => true, 'unsupported_reason' => null, 'last_failure' => null],
                    'block_debug_log'   => $off,
                    'block_uploads_php' => $off,
                ],
                'pause_until'         => null,
                'pause_overdue'       => false,
                'archive_attachments' => 0,
                'last_result'         => ['at' => $this->h->time, 'action' => 'enable', 'rule' => 'block_archives', 'ok' => true, 'reason' => null, 'warnings' => []],
            ],
        ], $data);
    }

    public function test_rule_accepts_the_boolean_spellings_a_form_post_sends() {
        $this->api->set_hardening_rule(new WP_REST_Request(['rule' => 'block_debug_log', 'enabled' => 'true']));
        $this->assertSame('on', $this->h->get_status()['rules']['block_debug_log']['state']);

        // (bool) "false" would be true.
        $this->api->set_hardening_rule(new WP_REST_Request(['rule' => 'block_debug_log', 'enabled' => 'false']));
        $this->assertSame('off', $this->h->get_status()['rules']['block_debug_log']['state']);
    }

    public function test_rule_validation() {
        $bad = [
            'unknown rule'     => ['rule' => 'block_xmlrpc', 'enabled' => true],
            'missing rule'     => ['enabled' => true],
            'array rule'       => ['rule' => ['block_archives'], 'enabled' => true],
            'missing enabled'  => ['rule' => 'block_archives'],
            'garbage enabled'  => ['rule' => 'block_archives', 'enabled' => 'yes please'],
            'numeric enabled'  => ['rule' => 'block_archives', 'enabled' => 2],
        ];
        foreach ($bad as $case => $params) {
            $data = $this->assertHardeningShape($this->api->set_hardening_rule(new WP_REST_Request($params)));
            $this->assertFalse($data['success'], $case);
            $this->assertSame('invalid_rule', $data['reason'], $case);
        }
        $this->assertNull($this->get('content'));
        $this->assertSame([], $this->server->requests);
    }

    public function test_a_failure_is_still_http_200_with_the_reason_at_the_top_level() {
        $this->server->bypass_htaccess = '~\.zip$~';

        $data = $this->assertHardeningShape($this->api->set_hardening_rule(new WP_REST_Request(['rule' => 'block_archives', 'enabled' => true])));

        $this->assertFalse($data['success']);
        $this->assertSame('rule_ineffective', $data['reason']);
        $this->assertSame('rule_ineffective', $data['status']['rules']['block_archives']['last_failure']['reason']);
    }

    public function test_pause_and_resume() {
        $this->h->set_rule('block_archives', true);

        $data = $this->assertHardeningShape($this->api->pause_hardening(new WP_REST_Request(['minutes' => 30])));
        $this->assertTrue($data['success']);
        $this->assertSame('paused', $data['status']['rules']['block_archives']['state']);
        $this->assertSame($this->h->time + 1800, $data['status']['pause_until']);

        $data = $this->assertHardeningShape($this->api->resume_hardening());
        $this->assertTrue($data['success']);
        $this->assertSame('on', $data['status']['rules']['block_archives']['state']);
        $this->assertNull($data['status']['pause_until']);

        $data = $this->assertHardeningShape($this->api->resume_hardening());
        $this->assertTrue($data['success'], 'resume is idempotent');
    }

    public function test_pause_accepts_a_numeric_string() {
        $this->h->set_rule('block_archives', true);
        $data = $this->assertHardeningShape($this->api->pause_hardening(new WP_REST_Request(['minutes' => '15'])));
        $this->assertTrue($data['success']);
        $this->assertSame($this->h->time + 900, $data['status']['pause_until']);
    }

    public function test_pause_validation() {
        $this->h->set_rule('block_archives', true);

        foreach ([null, 45, '45', 0, '60abc', 15.5, '15.5', true, [60]] as $minutes) {
            $data = $this->assertHardeningShape($this->api->pause_hardening(new WP_REST_Request(['minutes' => $minutes])));
            $this->assertFalse($data['success']);
            $this->assertSame('invalid_minutes', $data['reason']);
        }
        $this->assertNull($this->h->get_state()['pause_until']);
    }

    public function test_pause_when_the_rule_is_off() {
        $data = $this->assertHardeningShape($this->api->pause_hardening(new WP_REST_Request(['minutes' => 60])));
        $this->assertSame('not_enabled', $data['reason']);
    }
}

<?php

use PHPUnit\Framework\TestCase;

/**
 * Proves the hand-written WordPress fakes behave the way the plugin relies on.
 */
class HarnessTest extends TestCase {

    protected function setUp(): void {
        LSM_Test_Env::reset();
    }

    public function test_add_option_refuses_an_existing_option() {
        $this->assertTrue(add_option('lsm_x', 1, '', 'no'));
        $this->assertFalse(add_option('lsm_x', 2, '', 'no'));
        $this->assertSame(1, get_option('lsm_x'));
    }

    public function test_update_get_and_delete_option() {
        $this->assertSame('fallback', get_option('lsm_y', 'fallback'));
        update_option('lsm_y', ['a' => 1], true);
        $this->assertSame(['a' => 1], get_option('lsm_y'));
        $this->assertTrue(delete_option('lsm_y'));
        $this->assertFalse(delete_option('lsm_y'));
    }

    public function test_canned_http_goes_through_the_env_handler() {
        $seen = [];
        LSM_Test_Env::$http = function ($url, $args) use (&$seen) {
            $seen[] = [$url, $args];
            return ['response' => ['code' => 403], 'body' => 'denied', 'headers' => ['cf-mitigated' => 'challenge']];
        };

        $response = wp_remote_get('http://example.test/x', ['timeout' => 5]);

        $this->assertSame([['http://example.test/x', ['timeout' => 5]]], $seen);
        $this->assertSame(403, wp_remote_retrieve_response_code($response));
        $this->assertSame('denied', wp_remote_retrieve_body($response));
        $this->assertSame('challenge', wp_remote_retrieve_header($response, 'CF-Mitigated'));
    }

    public function test_http_without_a_handler_is_a_wp_error() {
        $this->assertTrue(is_wp_error(wp_remote_get('http://example.test/')));
    }

    public function test_rest_fakes_record_routes_and_carry_headers() {
        register_rest_route('lsm/v1', '/x', ['methods' => 'POST', 'callback' => 'strtoupper']);
        $this->assertSame(['POST lsm/v1/x'], array_keys(LSM_Test_Env::$routes));

        $response = rest_ensure_response(['success' => true]);
        $response->header('Cache-Control', 'no-store, private');
        $this->assertSame(200, $response->get_status());
        $this->assertSame(['success' => true], $response->get_data());
        $this->assertSame(['Cache-Control' => 'no-store, private'], $response->get_headers());

        $request = new WP_REST_Request(['enabled' => 'false']);
        $this->assertNull($request->get_param('rule'));
        $this->assertTrue(rest_is_boolean($request->get_param('enabled')));
        $this->assertFalse(rest_sanitize_boolean($request->get_param('enabled')), '(bool) "false" would be true');
        $this->assertFalse(rest_is_boolean('yes please'));
    }
}

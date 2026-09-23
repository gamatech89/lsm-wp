<?php

use PHPUnit\Framework\TestCase;

/**
 * The concurrency guard around LSM_Actions::update_all_plugins(): one run at a
 * time, the plugin never updates itself inside the loop, the lock is always
 * released, and the front end is probed afterwards.
 */
class UpdateAllPluginsGuardTest extends TestCase {

    const LOCK = 'lsm_bulk_plugin_update.lock';

    protected function setUp(): void {
        LSM_Test_Env::reset();
        LSM_Test_Upgrader_Env::reset();
        LSM_Test_Env::$http = function ($url, $args) {
            return ['response' => ['code' => 200], 'body' => '<html>ok</html>', 'headers' => []];
        };
        LSM_Test_Upgrader_Env::$plugin_updates = [
            'other/other.php'      => (object) ['Name' => 'Other'],
            LSM_PLUGIN_BASENAME    => (object) ['Name' => 'Landeseiten Maintenance'],
        ];
        LSM_Test_Env::$options['active_plugins'] = ['other/other.php', LSM_PLUGIN_BASENAME];
        LSM_Test_Env::$options['_site_transient_update_plugins'] = (object) ['response' => []];
    }

    public function test_a_second_run_while_locked_is_refused_without_touching_plugins() {
        LSM_Test_Env::$options[self::LOCK] = time() - 60;

        $result = LSM_Actions::update_all_plugins();

        $this->assertFalse($result['success']);
        $this->assertTrue($result['locked']);
        $this->assertSame([], $result['updated']);
        $this->assertSame(0, $result['updated_count']);
        $this->assertSame([], LSM_Test_Upgrader_Env::$upgraded, 'no upgrader ran');
        $this->assertSame(time() - 60, LSM_Test_Env::$options[self::LOCK], 'the running lock is left alone');
        $this->assertSame([], LSM_Test_Env::$log, 'a refused run logs nothing');
    }

    public function test_a_lock_older_than_fifteen_minutes_is_taken_over() {
        LSM_Test_Env::$options[self::LOCK] = time() - 16 * MINUTE_IN_SECONDS;

        $result = LSM_Actions::update_all_plugins();

        $this->assertTrue($result['success']);
        $this->assertSame(['other/other.php'], LSM_Test_Upgrader_Env::$upgraded);
    }

    public function test_own_plugin_is_skipped_and_the_others_are_updated() {
        $result = LSM_Actions::update_all_plugins();

        $this->assertTrue($result['success']);
        $this->assertSame(['other/other.php'], LSM_Test_Upgrader_Env::$upgraded);
        $this->assertSame(['Other'], $result['updated']);
        $this->assertSame(['Landeseiten Maintenance'], $result['skipped']);
        $this->assertSame(1, $result['updated_count']);
        $this->assertSame(['Other'], $result['reactivated']);
        $this->assertSame(1, LSM_Test_Upgrader_Env::$current_user);
    }

    public function test_the_lock_is_released_after_a_run() {
        LSM_Actions::update_all_plugins();

        $this->assertArrayNotHasKey(self::LOCK, LSM_Test_Env::$options);
        $this->assertTrue(WP_Upgrader::create_lock('lsm_bulk_plugin_update', 15 * MINUTE_IN_SECONDS));
    }

    public function test_the_lock_is_released_when_the_update_check_throws() {
        LSM_Test_Upgrader_Env::$refresh_throws = true;

        $thrown = null;
        try {
            LSM_Actions::update_all_plugins();
        } catch (\Throwable $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(RuntimeException::class, $thrown, 'the failure is not swallowed');
        $this->assertArrayNotHasKey(self::LOCK, LSM_Test_Env::$options, 'a crashed run must not wedge the lock');
    }

    public function test_a_failed_upgrade_is_reported_and_the_rest_still_runs() {
        LSM_Test_Upgrader_Env::$upgrade_results['other/other.php'] = new WP_Error('download_failed', 'Download failed.');

        $result = LSM_Actions::update_all_plugins();

        $this->assertTrue($result['success']);
        $this->assertSame([], $result['updated']);
        $this->assertSame(['Other (Download failed.)'], $result['failed']);
        $this->assertArrayNotHasKey(self::LOCK, LSM_Test_Env::$options);
    }

    public function test_the_front_end_is_probed_and_a_500_is_reported_and_logged() {
        $probed = [];
        LSM_Test_Env::$http = function ($url, $args) use (&$probed) {
            $probed[] = $url;
            return ['response' => ['code' => 500], 'body' => '', 'headers' => []];
        };

        $result = LSM_Actions::update_all_plugins();

        $this->assertTrue($result['success'], 'a broken front end is reported, not turned into a failed run');
        $this->assertSame(500, $result['health_after']);
        $this->assertCount(1, $probed);
        $this->assertStringStartsWith('http://example.test/?lsm_health=', $probed[0]);
        $actions = array_column(LSM_Test_Env::$log, 0);
        $this->assertContains('plugins_updated_site_unhealthy', $actions);
        $this->assertContains('plugins_updated', $actions);
    }

    public function test_an_unreachable_front_end_leaves_health_unknown() {
        LSM_Test_Env::$http = function ($url, $args) {
            return new WP_Error('http_request_failed', 'timeout');
        };

        $result = LSM_Actions::update_all_plugins();

        $this->assertTrue($result['success']);
        $this->assertNull($result['health_after']);
        $this->assertNotContains('plugins_updated_site_unhealthy', array_column(LSM_Test_Env::$log, 0));
    }
}

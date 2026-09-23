<?php
/**
 * In-memory fakes for the plugin-update path of LSM_Actions::update_all_plugins():
 * the core upgrade lock, Plugin_Upgrader, transients and the admin user context.
 */

class LSM_Test_Upgrader_Env {

    /** @var array plugin file => object with ->Name, as get_plugin_updates() returns */
    public static $plugin_updates = [];

    /** @var array plugin file => true | false | WP_Error returned by Plugin_Upgrader::upgrade() */
    public static $upgrade_results = [];

    /** @var array plugin files handed to Plugin_Upgrader::upgrade(), in order */
    public static $upgraded = [];

    /** @var array plugin files handed to activate_plugin() */
    public static $activated = [];

    /** @var bool make wp_update_plugins() throw, like a fatal outside the per-plugin try/catch */
    public static $refresh_throws = false;

    /** @var int|null user id passed to wp_set_current_user() */
    public static $current_user = null;

    public static function reset() {
        self::$plugin_updates  = [];
        self::$upgrade_results = [];
        self::$upgraded        = [];
        self::$activated       = [];
        self::$refresh_throws  = false;
        self::$current_user    = null;
    }
}

LSM_Test_Upgrader_Env::reset();

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}
if (!defined('LSM_PLUGIN_BASENAME')) {
    define('LSM_PLUGIN_BASENAME', 'landeseiten-maintenance/landeseiten-maintenance.php');
}

function __($text, $domain = 'default') {
    return $text;
}

function wp_set_current_user($id) {
    LSM_Test_Upgrader_Env::$current_user = $id;
}

function wp_update_plugins() {
    if (LSM_Test_Upgrader_Env::$refresh_throws) {
        throw new RuntimeException('update check exploded');
    }
}

function get_plugin_updates() {
    return LSM_Test_Upgrader_Env::$plugin_updates;
}

function get_site_transient($transient) {
    return get_option('_site_transient_' . $transient, false);
}

function set_site_transient($transient, $value, $expiration = 0) {
    return update_option('_site_transient_' . $transient, $value);
}

function activate_plugin($plugin, $redirect = '', $network_wide = false, $silent = false) {
    LSM_Test_Upgrader_Env::$activated[] = $plugin;
    $active = get_option('active_plugins', []);
    if (!in_array($plugin, $active, true)) {
        $active[] = $plugin;
        update_option('active_plugins', $active);
    }
    return null;
}

function is_plugin_active($plugin) {
    return in_array($plugin, get_option('active_plugins', []), true);
}

class LSM_Auth {

    public static function get_admin_user_id() {
        return 1;
    }
}

/**
 * Copy of the core lock (wp-admin/includes/class-wp-upgrader.php), on top of the
 * fake $wpdb->query() INSERT IGNORE and the in-memory options.
 */
class WP_Upgrader {

    public static function create_lock($lock_name, $release_timeout = null) {
        global $wpdb;

        if (!$release_timeout) {
            $release_timeout = HOUR_IN_SECONDS;
        }
        $lock_option = $lock_name . '.lock';

        $lock_result = $wpdb->query(
            $wpdb->prepare(
                "INSERT IGNORE INTO $wpdb->options ( option_name, option_value, autoload ) VALUES (%s, %s, 'no') /* LOCK */",
                $lock_option,
                time()
            )
        );

        if (!$lock_result) {
            $lock_result = get_option($lock_option);
            if (!$lock_result) {
                return false;
            }
            if ($lock_result > (time() - $release_timeout)) {
                return false;
            }
            self::release_lock($lock_name);
            return self::create_lock($lock_name, $release_timeout);
        }

        update_option($lock_option, time());
        return true;
    }

    public static function release_lock($lock_name) {
        return delete_option($lock_name . '.lock');
    }
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

class Automatic_Upgrader_Skin {

    public function get_upgrade_messages() {
        return [];
    }
}

class Plugin_Upgrader extends WP_Upgrader {

    public $skin;

    public function __construct($skin) {
        $this->skin = $skin;
    }

    public function upgrade($plugin) {
        LSM_Test_Upgrader_Env::$upgraded[] = $plugin;
        return array_key_exists($plugin, LSM_Test_Upgrader_Env::$upgrade_results)
            ? LSM_Test_Upgrader_Env::$upgrade_results[$plugin]
            : true;
    }
}

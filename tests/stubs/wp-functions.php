<?php
/**
 * In-memory fakes for the WordPress functions the plugin classes under test call.
 *
 * Everything mutable lives on LSM_Test_Env so a test can reset it in setUp().
 */

class LSM_Test_Env {

    /** @var array option name => value */
    public static $options = [];

    /** @var array list of [hook, callback, priority] */
    public static $actions = [];

    /** @var array filter name => value returned by apply_filters() */
    public static $filters = [];

    /** @var bool */
    public static $multisite = false;

    /** @var callable|null function($url, $args) returning a response array or WP_Error */
    public static $http = null;

    /** @var string uploads basedir returned by wp_upload_dir() */
    public static $uploads_dir = '';

    /** @var array list of [action, status, context] recorded by the LSM_Logger stub */
    public static $log = [];

    /** @var int value returned by the fake $wpdb->get_var() */
    public static $db_var = 0;

    /** @var array SQL strings passed to the fake $wpdb->get_var() */
    public static $db_queries = [];

    /** @var array "METHOD namespace/route" => args passed to register_rest_route() */
    public static $routes = [];

    public static function reset() {
        self::$options     = [];
        self::$actions     = [];
        self::$filters     = [];
        self::$multisite   = false;
        self::$http        = null;
        self::$uploads_dir = WP_CONTENT_DIR . '/uploads';
        self::$log         = [];
        self::$db_var      = 0;
        self::$db_queries  = [];
        self::$routes      = [];
    }
}

LSM_Test_Env::reset();

// -----------------------------------------------------------------------------
// Options. add_option() refuses an existing option, as WordPress does.
// (Real WordPress checks get_option() first and then upserts, so it is not strictly
// atomic; this single-process fake cannot show the difference.)
// -----------------------------------------------------------------------------

function get_option($option, $default = false) {
    return array_key_exists($option, LSM_Test_Env::$options) ? LSM_Test_Env::$options[$option] : $default;
}

function add_option($option, $value = '', $deprecated = '', $autoload = 'yes') {
    if (array_key_exists($option, LSM_Test_Env::$options)) {
        return false;
    }
    LSM_Test_Env::$options[$option] = $value;
    return true;
}

function update_option($option, $value, $autoload = null) {
    LSM_Test_Env::$options[$option] = $value;
    return true;
}

function delete_option($option) {
    if (!array_key_exists($option, LSM_Test_Env::$options)) {
        return false;
    }
    unset(LSM_Test_Env::$options[$option]);
    return true;
}

// -----------------------------------------------------------------------------
// Hooks and environment.
// -----------------------------------------------------------------------------

function add_action($hook, $callback, $priority = 10, $accepted_args = 1) {
    LSM_Test_Env::$actions[] = [$hook, $callback, $priority];
    return true;
}

function apply_filters($hook, $value) {
    return array_key_exists($hook, LSM_Test_Env::$filters) ? LSM_Test_Env::$filters[$hook] : $value;
}

function is_multisite() {
    return LSM_Test_Env::$multisite;
}

function wp_upload_dir() {
    return [
        'basedir' => LSM_Test_Env::$uploads_dir,
        'baseurl' => 'http://example.test/wp-content/uploads',
    ];
}

function content_url($path = '') {
    return 'http://example.test/wp-content' . ($path !== '' ? '/' . ltrim($path, '/') : '');
}

function home_url($path = '') {
    return 'http://example.test' . ($path !== '' ? '/' . ltrim($path, '/') : '');
}

function add_query_arg($key, $value, $url) {
    return $url . (strpos($url, '?') === false ? '?' : '&') . rawurlencode($key) . '=' . rawurlencode($value);
}

// -----------------------------------------------------------------------------
// HTTP. Canned: every request goes to LSM_Test_Env::$http.
// A response is ['response' => ['code' => int], 'body' => string, 'headers' => [lowercase-name => value]].
// -----------------------------------------------------------------------------

class WP_Error {

    private $code;
    private $message;

    public function __construct($code = '', $message = '') {
        $this->code    = $code;
        $this->message = $message;
    }

    public function get_error_code() {
        return $this->code;
    }

    public function get_error_message() {
        return $this->message;
    }
}

function is_wp_error($thing) {
    return $thing instanceof WP_Error;
}

function wp_remote_get($url, $args = []) {
    if (LSM_Test_Env::$http === null) {
        return new WP_Error('http_request_failed', 'No canned HTTP handler set');
    }
    return call_user_func(LSM_Test_Env::$http, $url, $args);
}

function wp_remote_retrieve_response_code($response) {
    if (is_wp_error($response) || !isset($response['response']['code'])) {
        return '';
    }
    return $response['response']['code'];
}

function wp_remote_retrieve_body($response) {
    if (is_wp_error($response) || !isset($response['body'])) {
        return '';
    }
    return $response['body'];
}

function wp_remote_retrieve_header($response, $header) {
    if (is_wp_error($response) || !isset($response['headers'][strtolower($header)])) {
        return '';
    }
    return $response['headers'][strtolower($header)];
}

// -----------------------------------------------------------------------------
// Database: just enough of $wpdb for one COUNT query and the INSERT IGNORE lock.
// -----------------------------------------------------------------------------

class LSM_Test_Wpdb {

    public $posts = 'wp_posts';

    public $options = 'wp_options';

    /**
     * Only understands the lock's INSERT IGNORE: 1 when the row was inserted,
     * 0 when the option already exists — the same answer MySQL gives.
     */
    public function query($query) {
        if (!preg_match("/^INSERT IGNORE INTO wp_options .*VALUES \\('([^']*)', '([^']*)'/", $query, $m)) {
            return false;
        }
        if (array_key_exists($m[1], LSM_Test_Env::$options)) {
            return 0;
        }
        LSM_Test_Env::$options[$m[1]] = $m[2];
        return 1;
    }

    public function prepare($query, $args = []) {
        $args = is_array($args) ? $args : array_slice(func_get_args(), 1);
        return vsprintf(str_replace('%s', "'%s'", $query), $args);
    }

    public function get_var($query) {
        LSM_Test_Env::$db_queries[] = $query;
        return (string) LSM_Test_Env::$db_var;
    }
}

$GLOBALS['wpdb'] = new LSM_Test_Wpdb();

// -----------------------------------------------------------------------------
// LSM_Logger stub: records calls instead of writing the activity log.
// -----------------------------------------------------------------------------

class LSM_Logger {

    public static function log($action, $status = 'info', $context = []) {
        LSM_Test_Env::$log[] = [$action, $status, $context];
    }
}

// -----------------------------------------------------------------------------
// REST: just enough to register routes and call the callbacks directly.
// -----------------------------------------------------------------------------

class WP_REST_Request {

    private $params;

    public function __construct(array $params = []) {
        $this->params = $params;
    }

    public function get_param($key) {
        return array_key_exists($key, $this->params) ? $this->params[$key] : null;
    }
}

class WP_REST_Response {

    private $data;
    private $status = 200;
    private $headers = [];

    public function __construct($data = null) {
        $this->data = $data;
    }

    public function get_data() {
        return $this->data;
    }

    public function get_status() {
        return $this->status;
    }

    public function header($key, $value) {
        $this->headers[$key] = $value;
    }

    public function get_headers() {
        return $this->headers;
    }
}

function rest_ensure_response($response) {
    return $response instanceof WP_REST_Response ? $response : new WP_REST_Response($response);
}

function register_rest_route($namespace, $route, $args = []) {
    LSM_Test_Env::$routes[$args['methods'] . ' ' . $namespace . $route] = $args;
    return true;
}

// Copies of the core functions (wp-includes/rest-api.php).
function rest_is_boolean($maybe_bool) {
    if (is_bool($maybe_bool)) {
        return true;
    }
    if (is_string($maybe_bool)) {
        $maybe_bool = strtolower($maybe_bool);
        return in_array($maybe_bool, ['false', 'true', '0', '1'], true);
    }
    if (is_int($maybe_bool)) {
        return in_array($maybe_bool, [0, 1], true);
    }
    return false;
}

function rest_sanitize_boolean($value) {
    if (is_string($value)) {
        $value = strtolower($value);
        if (in_array($value, ['false', '0'], true)) {
            $value = false;
        }
    }
    return (bool) $value;
}

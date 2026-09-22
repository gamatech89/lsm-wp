<?php
/**
 * Managed .htaccess hardening for Landeseiten Maintenance.
 *
 * Three deny rules, written between "# BEGIN LSM-HARDENING" / "# END LSM-HARDENING"
 * markers in wp-content/.htaccess and uploads/.htaccess. Every platform-initiated
 * write is snapshotted, self-tested over loopback HTTP and rolled back on failure.
 * Nothing here ever touches the root .htaccess.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Hardening class.
 */
class LSM_Hardening {

    /**
     * Option holding the desired state, pause, pending operation and last result.
     */
    const OPTION = 'lsm_hardening';

    /**
     * Lock option (one row, taken with INSERT IGNORE) and the age after which it is stale.
     */
    const LOCK_OPTION = 'lsm_hardening_lock';
    const LOCK_TTL    = 180;

    /**
     * A pending operation older than this was killed mid-run.
     */
    const RECOVERY_AFTER = 180;

    /**
     * Minimum seconds between two auto-resume attempts.
     */
    const RESUME_THROTTLE = 300;

    /**
     * Timeout of every loopback request, in seconds.
     */
    const LOOPBACK_TIMEOUT = 5;

    /**
     * Block markers, snapshot file name and probe file prefix.
     */
    const MARKER_BEGIN  = '# BEGIN LSM-HARDENING';
    const MARKER_END    = '# END LSM-HARDENING';
    const SNAPSHOT_FILE = '.htaccess.lsm-bak';
    const PROBE_PREFIX  = 'lsm-probe-';

    /**
     * Rule keys, in the order they are written into a block.
     */
    const RULES = ['block_archives', 'block_debug_log', 'block_uploads_php'];

    /**
     * Allowed pause durations in minutes.
     */
    const PAUSE_MINUTES = [15, 30, 60];

    /**
     * Instance.
     *
     * @var LSM_Hardening|null
     */
    private static $instance = null;

    /**
     * Get the shared instance.
     *
     * @return LSM_Hardening
     */
    public static function instance() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Replace the shared instance (tests only).
     *
     * @param LSM_Hardening|null $instance Instance, or null to reset.
     */
    public static function set_instance($instance) {
        self::$instance = $instance;
    }

    // =========================================================================
    // SEAMS (overridden by the unit tests)
    // =========================================================================

    /**
     * Perform one HTTP GET.
     *
     * @param string $url  URL.
     * @param array  $args wp_remote_get() arguments.
     * @return array|WP_Error
     */
    protected function http_request($url, $args) {
        return wp_remote_get($url, $args);
    }

    /**
     * Absolute path of wp-content, no trailing slash.
     *
     * @return string
     */
    protected function content_dir() {
        return rtrim(WP_CONTENT_DIR, '/\\');
    }

    /**
     * Absolute path of the uploads base directory, no trailing slash.
     *
     * @return string
     */
    protected function uploads_dir() {
        $upload_dir = wp_upload_dir();
        return rtrim($upload_dir['basedir'], '/\\');
    }

    /**
     * Current unix time.
     *
     * @return int
     */
    protected function now() {
        return time();
    }

    /**
     * Raw SERVER_SOFTWARE string ('' under WP-CLI).
     *
     * @return string
     */
    protected function server_software() {
        return isset($_SERVER['SERVER_SOFTWARE']) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
    }

    // =========================================================================
    // RULES AND BLOCK BUILDER
    // =========================================================================

    /**
     * Rule definitions: target file plus the opening and closing container line.
     *
     * @return array
     */
    private static function definitions() {
        return [
            'block_archives' => [
                'target' => 'content',
                'open'   => '<FilesMatch "(?i)\.((wpress|sql|zip|tar|tgz|bak)|(sql|tar|bak|wpress|zip)\.gz)$">',
                'close'  => '</FilesMatch>',
            ],
            'block_debug_log' => [
                'target' => 'content',
                'open'   => '<Files "debug.log">',
                'close'  => '</Files>',
            ],
            'block_uploads_php' => [
                'target' => 'uploads',
                'open'   => '<FilesMatch "(?i)\.(php[0-9]?|phtml?|pht|phps|phar)(\.|$)">',
                'close'  => '</FilesMatch>',
            ],
        ];
    }

    /**
     * Which file a rule lives in.
     *
     * @param string $rule Rule key.
     * @return string 'content' or 'uploads'.
     */
    public function target_of($rule) {
        return self::definitions()[$rule]['target'];
    }

    /**
     * Rule keys that live in a target file, in block order.
     *
     * @param string $target 'content' or 'uploads'.
     * @return array
     */
    public function rules_of($target) {
        $rules = [];
        foreach (self::RULES as $rule) {
            if ($this->target_of($rule) === $target) {
                $rules[] = $rule;
            }
        }
        return $rules;
    }

    /**
     * The lines of one rule. Both branches deny: LiteSpeed Enterprise ignores
     * <IfModule> tests and executes both, so neither may ever grant.
     *
     * @param string $rule Rule key.
     * @return array
     */
    public function rule_lines($rule) {
        $definition = self::definitions()[$rule];

        return [
            $definition['open'],
            '  <IfModule mod_authz_core.c>',
            '    Require all denied',
            '  </IfModule>',
            '  <IfModule !mod_authz_core.c>',
            '    Order deny,allow',
            '    Deny from all',
            '  </IfModule>',
            $definition['close'],
        ];
    }

    /**
     * Build the whole managed block for one target file.
     *
     * @param string $target  'content' or 'uploads'.
     * @param array  $enabled Rule keys that must be in the block; keys of other targets are ignored.
     * @return string Block without a trailing newline, or '' when no rule of this target is enabled.
     */
    public function build_block($target, array $enabled) {
        $lines = [];
        foreach ($this->rules_of($target) as $rule) {
            if (in_array($rule, $enabled, true)) {
                $lines = array_merge($lines, $this->rule_lines($rule));
            }
        }

        if (empty($lines)) {
            return '';
        }

        return implode("\n", array_merge(
            [self::MARKER_BEGIN, '# Managed by the Landeseiten Maintenance plugin. Do not edit between these markers.'],
            $lines,
            [self::MARKER_END]
        ));
    }
}

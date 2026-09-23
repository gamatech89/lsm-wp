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

    // =========================================================================
    // STRICT FILE HANDLING
    // =========================================================================

    /**
     * Absolute path of a target's .htaccess.
     *
     * @param string $target 'content' or 'uploads'.
     * @return string
     */
    public function target_file($target) {
        return ($target === 'uploads' ? $this->uploads_dir() : $this->content_dir()) . '/.htaccess';
    }

    /**
     * Read a target file.
     *
     * @param string $target 'content' or 'uploads'.
     * @return array ['existed' => bool, 'content' => string], plus 'unreadable' => true when the
     *               file exists but cannot be read (content is '' then — and nobody may write).
     */
    public function read_target($target) {
        $file = $this->target_file($target);
        if (!is_file($file)) {
            return ['existed' => false, 'content' => ''];
        }
        $content = @file_get_contents($file);
        if ($content === false) {
            // Exists but cannot be read: never treat it as empty — a write would destroy it.
            return ['existed' => true, 'content' => '', 'unreadable' => true];
        }
        return ['existed' => true, 'content' => $content];
    }

    /**
     * Byte offsets of every line that consists of exactly one marker.
     *
     * @param string $content File content.
     * @param string $marker  Marker text.
     * @return array List of [offset, length].
     */
    private function marker_offsets($content, $marker) {
        $found = [];
        if (preg_match_all('/^[ \t]*' . preg_quote($marker, '/') . '[ \t]*\r?$/m', $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $found[] = [$match[1], strlen($match[0])];
            }
        }
        return $found;
    }

    /**
     * Strict marker parser: exactly zero or one BEGIN, followed by its END,
     * no END without a BEGIN. Anything else is corrupt and must not be written to.
     *
     * @param string $content File content.
     * @return array ['corrupt' => bool, 'found' => bool, 'start' => int, 'end' => int, 'lines' => array]
     *               start/end are the byte range of the block (BEGIN line up to the end of the END line,
     *               without its line break); lines are the block's body lines.
     */
    public function parse_markers($content) {
        $result = ['corrupt' => false, 'found' => false, 'start' => 0, 'end' => 0, 'lines' => []];

        $begin = $this->marker_offsets($content, self::MARKER_BEGIN);
        $end   = $this->marker_offsets($content, self::MARKER_END);

        if (empty($begin) && empty($end)) {
            return $result;
        }

        if (count($begin) !== 1 || count($end) !== 1 || $end[0][0] < $begin[0][0]) {
            $result['corrupt'] = true;
            return $result;
        }

        $body_start = $begin[0][0] + $begin[0][1];
        $body       = substr($content, $body_start, $end[0][0] - $body_start);

        $result['found'] = true;
        $result['start'] = $begin[0][0];
        $result['end']   = $end[0][0] + $end[0][1];
        foreach (explode("\n", trim($body, "\r\n")) as $line) {
            $result['lines'][] = rtrim($line, "\r");
        }

        return $result;
    }

    /**
     * Put $block where the managed block is (or append it), or remove the managed
     * block when $block is ''. Everything outside the markers is kept byte for byte.
     *
     * @param string $content File content.
     * @param string $block   Block from build_block(), '' to remove.
     * @return string|null New content, or null when the markers are corrupt.
     */
    public function replace_block($content, $block) {
        $parsed = $this->parse_markers($content);
        if ($parsed['corrupt']) {
            return null;
        }

        if (!$parsed['found']) {
            if ($block === '') {
                return $content;
            }
            if ($content === '') {
                return $block . "\n";
            }
            // A file without a trailing newline would fuse its last line onto our marker.
            $separator = substr($content, -1) === "\n" ? "\n" : "\n\n";
            return $content . $separator . $block . "\n";
        }

        $before = substr($content, 0, $parsed['start']);
        $after  = (string) substr($content, $parsed['end']);

        if ($block !== '') {
            return $before . $block . $after;
        }

        // Removal: take the END line's line break and the blank line we put in front with it.
        if (substr($after, 0, 2) === "\r\n") {
            $after = (string) substr($after, 2);
        } elseif (substr($after, 0, 1) === "\n") {
            $after = (string) substr($after, 1);
        }
        if (substr($before, -2) === "\n\n") {
            $before = substr($before, 0, -1);
        }

        return $before . $after;
    }

    /**
     * Write a file. A seam so tests can simulate short or failing writes.
     *
     * @param string $file    Absolute path.
     * @param string $content Content.
     * @return int|false Bytes written.
     */
    protected function put_contents($file, $content) {
        return @file_put_contents($file, $content, LOCK_EX);
    }

    /**
     * Write new content into a target file and verify it by reading it back.
     * A file this operation would leave empty, and that did not exist before, is deleted.
     * Does not restore anything on failure — the caller still holds the original bytes.
     *
     * @param string $target   'content' or 'uploads'.
     * @param string $content  New full content.
     * @param string $original Content before the operation ('' when the file did not exist).
     * @param bool   $existed  Whether the file existed before the operation.
     * @return bool False when the read-back does not match.
     */
    public function commit_target($target, $content, $original, $existed) {
        $file = $this->target_file($target);

        if ($content === $original) {
            return true;
        }

        if (!$existed && trim($content) === '') {
            if (file_exists($file)) {
                @unlink($file);
            }
            return !file_exists($file);
        }

        $this->put_contents($file, $content);

        $written = @file_get_contents($file);
        return $written !== false && sha1($written) === sha1($content);
    }

    /**
     * Put a target file back to its original bytes (or delete it if it did not exist).
     *
     * @param string $target   'content' or 'uploads'.
     * @param string $original Original bytes held in memory.
     * @param bool   $existed  Whether the file existed before the operation.
     * @return bool True when the file is back to its original state.
     */
    public function restore_target($target, $original, $existed) {
        $file = $this->target_file($target);

        if (!$existed) {
            if (file_exists($file)) {
                @unlink($file);
            }
            return !file_exists($file);
        }

        $this->put_contents($file, $original);

        $written = @file_get_contents($file);
        return $written !== false && sha1($written) === sha1($original);
    }

    // =========================================================================
    // MANUAL RULES ALREADY ON A SITE (ADOPTION)
    // =========================================================================

    /**
     * Opening lines of the hand-written blocks the security-audit procedure appends.
     *
     * @return array Rule key => opening line (whitespace-normalised).
     */
    private static function manual_openings() {
        return [
            'block_archives'    => '<FilesMatch "\.(wpress|sql|zip|tar|gz|bak)$">',
            'block_debug_log'   => '<Files "debug.log">',
            'block_uploads_php' => '<FilesMatch "\.php$">',
        ];
    }

    /**
     * Trim a line and collapse inner whitespace runs to one space.
     *
     * @param string $line Raw line.
     * @return string
     */
    private function normalize_line($line) {
        return trim(preg_replace('/\s+/', ' ', $line));
    }

    /**
     * Find hand-written deny blocks for a rule, outside our markers.
     *
     * A small grammar, not exact text: a known opening line, then only deny /
     * IfModule lines (at least one deny, IfModule balanced), then the matching
     * close tag. Anything else is somebody else's rule and is never touched.
     *
     * @param string $content File content.
     * @param string $rule    Rule key.
     * @return array List of ['start' => int, 'length' => int] byte ranges (whole lines).
     */
    public function find_manual_blocks($content, $rule) {
        $opening = self::manual_openings()[$rule];
        $close   = self::definitions()[$rule]['close'];
        $deny    = ['Require all denied', 'Deny from all'];
        $neutral = ['Order deny,allow', 'Order allow,deny'];
        $if_open = ['<IfModule mod_authz_core.c>', '<IfModule !mod_authz_core.c>'];

        $managed = $this->parse_markers($content);
        $blocks  = [];
        $offset  = 0;
        $start   = null;
        $denies  = 0;
        $depth   = 0;

        foreach (preg_split('/(?<=\n)/', $content) as $line) {
            $length     = strlen($line);
            $normalized = $this->normalize_line($line);
            $in_managed = $managed['found'] && $offset >= $managed['start'] && $offset < $managed['end'];

            if ($in_managed) {
                $start = null;
            } elseif ($start !== null && $normalized === $close) {
                if ($denies > 0 && $depth === 0) {
                    $blocks[] = ['start' => $start, 'length' => $offset + $length - $start];
                }
                $start = null;
            } elseif ($start !== null && in_array($normalized, $deny, true)) {
                $denies++;
            } elseif ($start !== null && in_array($normalized, $if_open, true)) {
                $depth++;
            } elseif ($start !== null && $normalized === '</IfModule>' && $depth > 0) {
                $depth--;
            } elseif ($start !== null && ($normalized === '' || in_array($normalized, $neutral, true))) {
                // Allowed filler.
            } elseif ($normalized === $opening) {
                $start  = $offset;
                $denies = 0;
                $depth  = 0;
            } else {
                $start = null;
            }

            $offset += $length;
        }

        return $blocks;
    }

    /**
     * Remove every recognised manual block of a rule.
     *
     * @param string $content File content.
     * @param string $rule    Rule key.
     * @return string
     */
    public function strip_manual_blocks($content, $rule) {
        foreach (array_reverse($this->find_manual_blocks($content, $rule)) as $block) {
            $content = substr($content, 0, $block['start']) . (string) substr($content, $block['start'] + $block['length']);
        }
        return $content;
    }

    // =========================================================================
    // STATE, PREFLIGHT AND STATUS
    // =========================================================================

    /**
     * Read the lsm_hardening option, filled up with defaults.
     *
     * @return array
     */
    public function get_state() {
        $stored = get_option(self::OPTION, []);
        if (!is_array($stored)) {
            $stored = [];
        }

        $state = array_merge([
            'rules'           => [],
            'pause_until'     => null,
            'last_attempt_at' => null,
            'pending'         => null,
            'last_result'     => null,
            'rule_failures'   => [],
        ], $stored);

        $desired        = is_array($state['rules']) ? $state['rules'] : [];
        $state['rules'] = [];
        foreach (self::RULES as $rule) {
            $state['rules'][$rule] = !empty($desired[$rule]);
        }

        // A damaged option (false, '', 0, '0', 'abc', a float, ...) must read as null, never as
        // the epoch: on_init() would otherwise treat it as "overdue since 1970" and re-apply.
        $until                  = $state['pause_until'];
        $state['pause_until']   = (is_int($until) || (is_string($until) && ctype_digit($until))) && (int) $until > 0 ? (int) $until : null;
        $state['rule_failures'] = is_array($state['rule_failures']) ? $state['rule_failures'] : [];

        return $state;
    }

    /**
     * Static preflight: no write, no HTTP.
     *
     * @param string $rule Rule key.
     * @return string|null Reason the rule is unsupported here, or null.
     */
    public function preflight($rule) {
        if (is_multisite()) {
            return 'multisite';
        }

        $edition = isset($_SERVER['LSWS_EDITION']) ? (string) $_SERVER['LSWS_EDITION'] : '';
        if (stripos($edition, 'Openlitespeed') === 0) {
            return 'openlitespeed';
        }

        // SERVER_SOFTWARE cannot see an nginx in front of Apache — only the probes can.
        $software = $this->server_software();
        if (stripos($software, 'Apache') === false && stripos($software, 'LiteSpeed') === false) {
            return 'unknown_server';
        }

        // A file we can write but not read is as good as not writable: the candidate would be
        // built from "empty" and the write would destroy whatever is in it.
        $file     = $this->target_file($this->target_of($rule));
        $writable = file_exists($file) ? (is_writable($file) && is_readable($file)) : is_writable(dirname($file));
        if (!$writable) {
            return 'not_writable';
        }

        return null;
    }

    /**
     * Does the managed block contain a rule's lines (in order, whitespace-insensitive)?
     *
     * @param array  $block_lines Body lines from parse_markers().
     * @param string $rule        Rule key.
     * @return bool
     */
    private function block_has_rule(array $block_lines, $rule) {
        $haystack = array_map([$this, 'normalize_line'], $block_lines);
        $needle   = array_map([$this, 'normalize_line'], $this->rule_lines($rule));
        $last     = count($haystack) - count($needle);

        for ($i = 0; $i <= $last; $i++) {
            if (array_slice($haystack, $i, count($needle)) === $needle) {
                return true;
            }
        }
        return false;
    }

    /**
     * What a target file says right now.
     *
     * @param string $target 'content' or 'uploads'.
     * @return array ['existed' => bool, 'content' => string, 'corrupt' => bool,
     *                'in_block' => [rule => bool], 'manual' => [rule => bool]]
     *               (plus read_target()'s 'unreadable' => true when it applies)
     */
    public function file_facts($target) {
        $facts  = $this->read_target($target);
        $parsed = $this->parse_markers($facts['content']);

        // An unreadable file counts as corrupt: every writer refuses to touch a corrupt file,
        // also the ones that skip the preflight (auto-resume, crash recovery).
        $facts['corrupt']  = $parsed['corrupt'] || !empty($facts['unreadable']);
        $facts['in_block'] = [];
        $facts['manual']   = [];
        foreach ($this->rules_of($target) as $rule) {
            $facts['in_block'][$rule] = $parsed['found'] && $this->block_has_rule($parsed['lines'], $rule);
            $facts['manual'][$rule]   = !empty($this->find_manual_blocks($facts['content'], $rule));
        }

        return $facts;
    }

    /**
     * Per-rule status, computed from the files — the option only says what is desired.
     *
     * @return array Rule key => ['state', 'desired', 'unsupported_reason', 'last_failure'].
     */
    public function rule_statuses() {
        $state = $this->get_state();
        $facts = [
            'content' => $this->file_facts('content'),
            'uploads' => $this->file_facts('uploads'),
        ];

        $rules = [];
        foreach (self::RULES as $rule) {
            $file        = $facts[$this->target_of($rule)];
            $unsupported = $this->preflight($rule);

            if ($unsupported !== null) {
                $name = 'unsupported';
            } elseif ($rule === 'block_archives' && $state['pause_until'] !== null) {
                $name = 'paused';
            } elseif ($file['in_block'][$rule]) {
                $name = 'on';
            } elseif ($file['manual'][$rule]) {
                $name = 'manual';
            } elseif ($state['rules'][$rule]) {
                $name = 'drift';
            } else {
                $name = 'off';
            }

            $rules[$rule] = [
                'state'              => $name,
                'desired'            => $state['rules'][$rule],
                'unsupported_reason' => $unsupported,
                'last_failure'       => isset($state['rule_failures'][$rule]) ? $state['rule_failures'][$rule] : null,
            ];
        }

        return $rules;
    }

    /**
     * Short server name for the panel.
     *
     * @return string
     */
    private function server_label() {
        $software = $this->server_software();
        $edition  = isset($_SERVER['LSWS_EDITION']) ? (string) $_SERVER['LSWS_EDITION'] : '';

        if (stripos($edition, 'Openlitespeed') === 0) {
            return 'OpenLiteSpeed';
        }
        if (stripos($software, 'LiteSpeed') !== false) {
            return 'LiteSpeed';
        }
        if (stripos($software, 'Apache') !== false) {
            return 'Apache';
        }
        return $software !== '' ? $software : 'unknown';
    }

    /**
     * Media Library attachments block_archives would stop serving (one COUNT query).
     *
     * @return int
     */
    protected function count_archive_attachments() {
        global $wpdb;

        $mime_types = [
            'application/zip',
            'application/x-zip-compressed',
            'application/gzip',
            'application/x-gzip',
            'application/x-tar',
            'application/rar',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
        ];
        $placeholders = implode(', ', array_fill(0, count($mime_types), '%s'));

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type IN ($placeholders)",
            $mime_types
        ));
    }

    /**
     * Full status object of the REST responses.
     *
     * @return array
     */
    public function get_status() {
        $state = $this->get_state();

        return [
            'plugin_version'      => LSM_VERSION,
            'server'              => $this->server_label(),
            'rules'               => $this->rule_statuses(),
            'pause_until'         => $state['pause_until'],
            'pause_overdue'       => $state['pause_until'] !== null && $state['pause_until'] < $this->now(),
            'archive_attachments' => $this->count_archive_attachments(),
            'last_result'         => $state['last_result'],
        ];
    }

    // =========================================================================
    // LOCK
    // =========================================================================

    /**
     * Take the operation lock.
     *
     * One options row, inserted with INSERT IGNORE so the database decides who wins
     * (the statement WP_Upgrader::create_lock() uses). An option (unlike a transient)
     * survives cache flushes and transient purges. A lock older than LOCK_TTL belongs
     * to a dead process: delete it and retry once.
     *
     * @return bool False when another operation holds the lock.
     */
    public function acquire_lock() {
        if ($this->insert_lock_row()) {
            return true;
        }

        $taken_at = (int) get_option(self::LOCK_OPTION, 0);
        if ($this->now() - $taken_at <= self::LOCK_TTL) {
            return false;
        }

        delete_option(self::LOCK_OPTION);
        return $this->insert_lock_row();
    }

    /**
     * Insert the lock row. add_option() is not atomic (it checks, then upserts), so the
     * insert goes straight to the database; update_option() afterwards only teaches the
     * options cache about the row, as core does after its own lock insert.
     *
     * @return bool True when this process inserted the row.
     */
    protected function insert_lock_row() {
        global $wpdb;

        $inserted = $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no') /* LOCK */",
            self::LOCK_OPTION,
            (string) $this->now()
        ));
        if (!$inserted) {
            return false;
        }

        update_option(self::LOCK_OPTION, $this->now(), false);
        return true;
    }

    /**
     * Release the operation lock.
     */
    public function release_lock() {
        delete_option(self::LOCK_OPTION);
    }

    // =========================================================================
    // LOOPBACK, BASELINE AND PROBES
    // =========================================================================

    /**
     * Absolute path of this plugin's directory.
     *
     * @return string
     */
    protected function plugin_dir() {
        return LSM_PLUGIN_DIR;
    }

    /**
     * One loopback GET, reduced to what the self-test looks at.
     *
     * @param string $url URL on this site.
     * @return array ['error' => bool, 'code' => int, 'body' => string, 'challenge' => bool]
     */
    public function loopback($url) {
        $response = $this->http_request($url, [
            'timeout'     => self::LOOPBACK_TIMEOUT,
            // An "ErrorDocument 403 https://..." would turn a 403 into 302 -> 200.
            'redirection' => 0,
            'cookies'     => [],
            'sslverify'   => apply_filters('https_local_ssl_verify', false, $url),
            'headers'     => ['Cache-Control' => 'no-cache'],
        ]);

        if (is_wp_error($response)) {
            return ['error' => true, 'code' => 0, 'body' => '', 'challenge' => false];
        }

        return [
            'error'     => false,
            'code'      => (int) wp_remote_retrieve_response_code($response),
            'body'      => (string) wp_remote_retrieve_body($response),
            'challenge' => strtolower((string) wp_remote_retrieve_header($response, 'cf-mitigated')) === 'challenge',
        ];
    }

    /**
     * A response that proves nothing about our rule: no answer, basic auth,
     * a server error or a Cloudflare challenge. Never counts as "403 effective".
     *
     * @param array $response Result of loopback().
     * @return bool
     */
    private function is_inconclusive(array $response) {
        return $response['error'] || $response['challenge'] || $response['code'] === 401 || $response['code'] >= 500;
    }

    /**
     * Append a fresh cache-buster, so a CDN or nginx cached 200 can neither mask a 500
     * (baseline) nor answer the "after" fetch of a probe with its cached "before" response.
     *
     * @param string $url URL.
     * @return string
     */
    private function bust($url) {
        return add_query_arg('lsm_hardening', bin2hex(random_bytes(4)), $url);
    }

    /**
     * Baseline 2a: a static file of this plugin, served from below wp-content.
     *
     * @return array|null loopback() result, or null when the plugin does not live below wp-content.
     */
    public function baseline_asset() {
        $plugin_dir  = rtrim(str_replace('\\', '/', $this->plugin_dir()), '/') . '/';
        $content_dir = rtrim(str_replace('\\', '/', $this->content_dir()), '/') . '/';
        if (strpos($plugin_dir, $content_dir) !== 0) {
            return null;
        }

        return $this->loopback($this->bust(LSM_PLUGIN_URL . 'assets/css/ticket-ui.css'));
    }

    /**
     * Was baseline 2a fine (or not applicable)?
     *
     * @param array|null $asset Result of baseline_asset().
     * @return bool
     */
    private function asset_ok($asset) {
        return $asset === null || (!$asset['error'] && $asset['code'] === 200 && $asset['body'] !== '');
    }

    /**
     * Baseline 2b: the homepage as an anonymous visitor — no query string, no cookies —
     * because rewrite-mode page caches serve exactly that request from wp-content/cache/.
     *
     * @return array loopback() result.
     */
    public function baseline_home() {
        return $this->loopback(home_url('/'));
    }

    /**
     * Prepare the probes of a rule.
     *
     * Archives: two real files (.zip is what a front-end nginx serves itself, .wpress is
     * what the team downloads) with a random token as body. debug.log and the uploads PHP
     * probe are plain URLs: Apache answers 403 for a covered name before it looks for the
     * file, so the PHP probe is never created. No cache-buster here: fetch_probes() adds a
     * fresh one to every single request.
     *
     * @param string $rule Rule key.
     * @return array List of ['label' => string, 'url' => string, 'token' => string|null].
     */
    public function prepare_probes($rule) {
        if ($rule === 'block_debug_log') {
            return [['label' => 'debug.log', 'url' => content_url('debug.log'), 'token' => null]];
        }

        if ($rule === 'block_uploads_php') {
            $upload_dir = wp_upload_dir();
            $name       = self::PROBE_PREFIX . bin2hex(random_bytes(8)) . '.php';
            return [['label' => 'uploads .php', 'url' => rtrim($upload_dir['baseurl'], '/') . '/' . $name, 'token' => null]];
        }

        $probes = [];
        foreach (['zip', 'wpress'] as $extension) {
            $name  = self::PROBE_PREFIX . bin2hex(random_bytes(8)) . '.' . $extension;
            $token = bin2hex(random_bytes(16));
            $this->put_contents($this->content_dir() . '/' . $name, $token);
            $probes[] = ['label' => '.' . $extension, 'url' => content_url($name), 'token' => $token];
        }
        return $probes;
    }

    /**
     * Fetch every probe once.
     *
     * @param array $probes Result of prepare_probes().
     * @return array The probes with 'code' (int), 'inconclusive' (bool) and 'served' (bool: 200, and the token when there is one).
     */
    public function fetch_probes(array $probes) {
        foreach ($probes as $i => $probe) {
            // Fresh cache-buster per fetch: the same URL is fetched before and after the write, and an
            // edge cache (Cloudflare caches .zip by extension, a 200 for ~2 h, keyed by URL + query, and
            // ignores our "Cache-Control: no-cache") would answer the "after" fetch with the cached
            // "before" 200 -> a false rule_ineffective.
            $response = $this->loopback($this->bust($probe['url']));

            $probes[$i]['code']         = $response['code'];
            $probes[$i]['inconclusive'] = $this->is_inconclusive($response);
            $probes[$i]['served']       = $response['code'] === 200
                && ($probe['token'] === null || strpos($response['body'], $probe['token']) !== false);
        }
        return $probes;
    }

    /**
     * Judge the probes fetched before the write.
     *
     * @param string $rule      Rule key.
     * @param array  $probes    Result of fetch_probes().
     * @param bool   $explained Whether the file itself already explains a 403 (rule in our block, or a manual block).
     * @return array ['reason' => string|null, 'message' => string, 'warnings' => array]
     */
    public function judge_before($rule, array $probes, $explained) {
        $warnings = [];

        foreach ($probes as $probe) {
            // Archive probes are real files: only "served with the token" or "already 403" make sense.
            $plausible = $rule !== 'block_archives' || $probe['served'] || $probe['code'] === 403;
            if ($probe['inconclusive'] || !$plausible) {
                return [
                    'reason'   => 'loopback_blocked',
                    'message'  => sprintf('The site could not fetch its own %s probe (HTTP %d), so the rule cannot be verified. Nothing was changed.', $probe['label'], $probe['code']),
                    'warnings' => [],
                ];
            }
            if ($probe['code'] === 403 && !$explained) {
                $warnings = ['already_blocked_elsewhere'];
            }
        }

        return ['reason' => null, 'message' => '', 'warnings' => $warnings];
    }

    /**
     * Judge the probes fetched after the write.
     *
     * @param string $rule     Rule key.
     * @param bool   $in_block Whether the rule is in the block that was just written.
     * @param array  $probes   Result of fetch_probes().
     * @return array ['reason' => string|null, 'message' => string]
     */
    public function judge_after($rule, $in_block, array $probes) {
        foreach ($probes as $probe) {
            if ($probe['inconclusive']) {
                return [
                    'reason'  => 'loopback_blocked',
                    'message' => sprintf('The %s probe could not be evaluated after the write (HTTP %d).', $probe['label'], $probe['code']),
                ];
            }
            if ($in_block && $probe['code'] !== 403) {
                return [
                    'reason'  => 'rule_ineffective',
                    'message' => sprintf('The rule has no effect on this server: the %s probe was still answered with HTTP %d instead of 403 (a front-end nginx or CDN serving static files?).', $probe['label'], $probe['code']),
                ];
            }
            if (!$in_block && $rule === 'block_archives' && $probe['label'] === '.wpress' && !$probe['served']) {
                return [
                    'reason'  => 'pause_ineffective_foreign_rule',
                    'message' => sprintf('Our rule is out of the file, but the .wpress probe is still answered with HTTP %d: another rule on this server blocks it.', $probe['code']),
                ];
            }
        }

        return ['reason' => null, 'message' => ''];
    }

    /**
     * Is this file name one of our own short-lived artifacts (probe file or snapshot)?
     * cleanup_artifacts() deletes these and the plugin's suspicious-file collectors skip them,
     * so the match is exact — a bare prefix match would be an evasion name for malware.
     *
     * @param string $name File name without directory.
     * @return bool
     */
    public static function is_own_artifact($name) {
        if ($name === self::SNAPSHOT_FILE) {
            return true;
        }
        // Exactly what prepare_probes() creates. Never a PHP name: the uploads PHP probe is never
        // created, so a "lsm-probe-*.php" on disk is somebody else's file and must be reported.
        return preg_match('/^' . preg_quote(self::PROBE_PREFIX, '/') . '[a-f0-9]{16}\.(zip|wpress)\z/', $name) === 1;
    }

    /**
     * Delete every probe file and snapshot in both directories. Paths are derived, never stored.
     */
    public function cleanup_artifacts() {
        foreach ([$this->content_dir(), $this->uploads_dir()] as $dir) {
            foreach ((array) @scandir($dir) as $name) {
                if (is_string($name) && self::is_own_artifact($name) && is_file($dir . '/' . $name)) {
                    @unlink($dir . '/' . $name);
                }
            }
        }
    }

    // =========================================================================
    // FULL APPLY PROCEDURE
    // =========================================================================

    /**
     * Store the lsm_hardening option (autoloaded: on_init() reads it on every request).
     *
     * @param array $state State.
     */
    private function save_state(array $state) {
        update_option(self::OPTION, $state, true);
    }

    /**
     * Build the top-level shape every REST response has.
     *
     * @param bool        $success  Outcome.
     * @param string|null $reason   Reason code on failure.
     * @param string      $message  Human-readable message.
     * @param array       $warnings Warning codes.
     * @return array
     */
    public function respond($success, $reason, $message, array $warnings = []) {
        return [
            'success'  => (bool) $success,
            'reason'   => $reason,
            'message'  => $message,
            'warnings' => array_values($warnings),
            'status'   => $this->get_status(),
        ];
    }

    /**
     * Turn a rule on (also: adopt a manual block, re-apply after drift) or off.
     *
     * @param string $rule    Rule key.
     * @param bool   $enabled Desired state.
     * @return array respond() shape.
     */
    public function set_rule($rule, $enabled) {
        if (!is_string($rule) || !in_array($rule, self::RULES, true)) {
            return $this->respond(false, 'invalid_rule', 'Unknown hardening rule.');
        }

        $enabled = (bool) $enabled;
        $commit  = ['rules' => [$rule => $enabled]];
        if ($rule === 'block_archives') {
            // Turning the archive rule on or off ends any pause.
            $commit['pause_minutes'] = null;
        }

        return $this->apply($enabled ? 'enable' : 'disable', $rule, $enabled, $commit);
    }

    /**
     * The full safe procedure: preflight, lock, run, finish.
     *
     * A throwable inside execute() is treated like a killed process: lock, `pending`
     * and the snapshot stay where they are and crash recovery cleans up.
     *
     * @param string $action   enable|disable|pause|resume — also pending.op and last_result.action.
     * @param string $rule     Rule the operation is about.
     * @param bool   $in_block Whether the rule must be in the managed block afterwards.
     * @param array  $commit   Committed on success only: ['rules' => [rule => bool]] and/or
     *                         ['pause_minutes' => int|null] (null clears pause_until).
     * @return array respond() shape.
     */
    private function apply($action, $rule, $in_block, array $commit) {
        $unsupported = $this->preflight($rule);
        if ($unsupported !== null) {
            return $this->respond(false, 'unsupported', sprintf('Not supported on this server (%s).', $unsupported));
        }

        if (!$this->acquire_lock()) {
            return $this->respond(false, 'busy', 'Another hardening operation is running on this site. Try again in a moment.');
        }

        if (function_exists('set_time_limit')) {
            @set_time_limit(120);
        }

        $outcome = $this->execute($action, $rule, $in_block);

        return $this->finish($action, $rule, $outcome, $commit);
    }

    /**
     * Steps 2-7 of the procedure. Runs under the lock.
     *
     * @param string $action   Operation.
     * @param string $rule     Rule key.
     * @param bool   $in_block Whether the rule must be in the block afterwards.
     * @return array ['reason' => string|null, 'message' => string, 'warnings' => array]
     */
    private function execute($action, $rule, $in_block) {
        $target  = $this->target_of($rule);
        $current = $this->file_facts($target);

        if ($current['corrupt']) {
            return [
                'reason'   => 'markers_corrupt',
                'message'  => 'The LSM-HARDENING markers in this .htaccess are damaged (a BEGIN without END, or more than one block). Nothing was changed — repair the file by hand.',
                'warnings' => [],
            ];
        }

        // Candidate block: what the file holds right now, plus or minus this rule. The file is
        // the truth — a drifted rule is never re-added as a side effect of touching another one.
        $enabled = [];
        foreach ($this->rules_of($target) as $other) {
            if ($other === $rule ? $in_block : $current['in_block'][$other]) {
                $enabled[] = $other;
            }
        }
        $candidate = $in_block ? $this->strip_manual_blocks($current['content'], $rule) : $current['content'];
        $candidate = $this->replace_block($candidate, $this->build_block($target, $enabled));

        // 2. Baseline before.
        $asset = $this->baseline_asset();
        if (!$this->asset_ok($asset)) {
            return [
                'reason'   => 'loopback_blocked',
                'message'  => sprintf('The site could not fetch its own plugin stylesheet (HTTP %d), so a change could not be verified. Nothing was changed.', $asset['code']),
                'warnings' => [],
            ];
        }
        $home_before = $this->baseline_home();
        if ($home_before['error']) {
            return [
                'reason'   => 'loopback_blocked',
                'message'  => 'The site could not fetch its own homepage, so a change could not be verified. Nothing was changed.',
                'warnings' => [],
            ];
        }

        // 3. Probes before.
        $probes = $this->prepare_probes($rule);
        $before = $this->judge_before($rule, $this->fetch_probes($probes), $current['in_block'][$rule] || $current['manual'][$rule]);
        if ($before['reason'] !== null) {
            return $before;
        }
        $warnings = $before['warnings'];

        // The loopbacks above can take tens of seconds: never write a candidate built from stale bytes.
        $fresh = $this->read_target($target);
        if ($fresh['existed'] !== $current['existed'] || $fresh['content'] !== $current['content']) {
            return [
                'reason'   => 'write_failed',
                'message'  => 'The .htaccess was changed by something else while the self-test was running. Nothing was changed — try again.',
                'warnings' => $warnings,
            ];
        }

        // 4. Snapshot + pending. The original bytes stay in $current for the same-request rollback.
        if (!$this->write_snapshot($target, $current)) {
            return [
                'reason'   => 'snapshot_failed',
                'message'  => 'The backup copy of the .htaccess could not be written and read back. Nothing was changed.',
                'warnings' => $warnings,
            ];
        }
        $state            = $this->get_state();
        $state['pending'] = [
            'target'     => $target,
            'op'         => $action,
            'started_at' => $this->now(),
            'existed'    => $current['existed'],
        ];
        $this->save_state($state);

        // 5. Write, 6. self-test after.
        if (!$this->commit_target($target, $candidate, $current['content'], $current['existed'])) {
            $failure = ['reason' => 'write_failed', 'message' => 'The .htaccess did not read back the way it was written.'];
        } else {
            $failure = $this->self_test_after($rule, $in_block, $probes, $home_before);
        }

        if ($failure['reason'] === null) {
            return ['reason' => null, 'message' => 'Applied and verified', 'warnings' => $warnings];
        }

        // 7. Rollback.
        $failure             = $this->rollback($target, $current, $failure);
        $failure['warnings'] = $warnings;
        return $failure;
    }

    /**
     * Step 4: write .htaccess.lsm-bak beside the file and read it back identical.
     * A file that does not exist has nothing to snapshot (pending.existed covers it).
     *
     * @param string $target  'content' or 'uploads'.
     * @param array  $current Result of file_facts().
     * @return bool
     */
    private function write_snapshot($target, array $current) {
        $snapshot = dirname($this->target_file($target)) . '/' . self::SNAPSHOT_FILE;

        if (!$current['existed']) {
            if (file_exists($snapshot)) {
                @unlink($snapshot);
            }
            return true;
        }

        $this->put_contents($snapshot, $current['content']);
        return @file_get_contents($snapshot) === $current['content'];
    }

    /**
     * Step 6: both baselines again, then the probes.
     *
     * @param string $rule        Rule key.
     * @param bool   $in_block    Whether the rule is in the block that was just written.
     * @param array  $probes      Result of prepare_probes().
     * @param array  $home_before Baseline 2b from before the write.
     * @return array ['reason' => string|null, 'message' => string]
     */
    private function self_test_after($rule, $in_block, array $probes, array $home_before) {
        $asset = $this->baseline_asset();
        if (!$this->asset_ok($asset)) {
            return [
                'reason'  => 'asset_broken',
                'message' => sprintf('After the write the plugin stylesheet below wp-content answered HTTP %d instead of 200.', $asset['code']),
            ];
        }

        $home = $this->baseline_home();
        if ($home['error'] || $home['code'] !== $home_before['code'] || ($home_before['body'] !== '' && $home['body'] === '')) {
            return [
                'reason'  => 'asset_broken',
                'message' => sprintf('After the write the homepage answered HTTP %d (before: %d) for an anonymous visitor.', $home['code'], $home_before['code']),
            ];
        }

        return $this->judge_after($rule, $in_block, $this->fetch_probes($probes));
    }

    /**
     * Step 7: restore the original bytes (or delete a file that did not exist) and
     * re-check baseline 2a.
     *
     * @param string $target  'content' or 'uploads'.
     * @param array  $current Result of file_facts() from before the write.
     * @param array  $failure ['reason', 'message'] that triggered the rollback.
     * @return array ['reason', 'message'] — the original failure, or rollback_failed.
     */
    private function rollback($target, array $current, array $failure) {
        if (!$this->restore_target($target, $current['content'], $current['existed'])) {
            // Last resort: whatever is in the file now, at least take our block out of it.
            $this->strip_managed_block($target);
            return [
                'reason'  => 'rollback_failed',
                'message' => $failure['message'] . ' The original .htaccess could not be restored; the managed block was stripped instead. Check the file by hand.',
            ];
        }

        if (!$this->asset_ok($this->baseline_asset())) {
            return [
                'reason'  => 'rollback_failed',
                'message' => $failure['message'] . ' The original .htaccess was restored, but files below wp-content still do not load. Check the site now.',
            ];
        }

        $failure['message'] .= ' The change was rolled back.';
        return $failure;
    }

    /**
     * Remove the managed block from a target file, best effort.
     *
     * @param string $target 'content' or 'uploads'.
     */
    private function strip_managed_block($target) {
        $current  = $this->read_target($target);
        $stripped = $this->replace_block($current['content'], '');
        if ($stripped !== null && $stripped !== $current['content']) {
            $this->put_contents($this->target_file($target), $stripped);
        }
    }

    /**
     * Step 8, both paths: commit on success, clear pending, write last_result, then delete the
     * snapshot and the probe files, release the lock, log.
     *
     * The state is saved BEFORE the artifacts are deleted: a kill in between then leaves a stray
     * snapshot (harmless, the next operation removes it) instead of a `pending` without a
     * snapshot, which crash recovery could not undo.
     *
     * @param string $action  last_result.action.
     * @param string $rule    Rule key.
     * @param array  $outcome ['reason' => string|null, 'message' => string, 'warnings' => array]
     * @param array  $commit  See apply().
     * @return array respond() shape.
     */
    private function finish($action, $rule, array $outcome, array $commit) {
        $ok    = $outcome['reason'] === null;
        $state = $this->get_state();

        if ($ok) {
            if (isset($commit['rules'])) {
                foreach ($commit['rules'] as $key => $value) {
                    $state['rules'][$key] = $value;
                }
            }
            if (array_key_exists('pause_minutes', $commit)) {
                $state['pause_until'] = $commit['pause_minutes'] === null ? null : $this->now() + $commit['pause_minutes'] * 60;
            }
            unset($state['rule_failures'][$rule]);
        } else {
            $state['rule_failures'][$rule] = ['at' => $this->now(), 'reason' => $outcome['reason']];
        }

        $state['pending']     = null;
        $state['last_result'] = [
            'at'       => $this->now(),
            'action'   => $action,
            'rule'     => $rule,
            'ok'       => $ok,
            'reason'   => $outcome['reason'],
            'warnings' => array_values($outcome['warnings']),
        ];
        $this->save_state($state);
        $this->cleanup_artifacts();
        $this->release_lock();

        LSM_Logger::log($ok ? 'hardening_applied' : 'hardening_failed', $ok ? 'success' : 'error', [
            'action'   => $action,
            'rule'     => $rule,
            'reason'   => $outcome['reason'],
            'warnings' => $outcome['warnings'],
        ]);

        return $this->respond($ok, $outcome['reason'], $outcome['message'], $outcome['warnings']);
    }

    // =========================================================================
    // PAUSE AND RESUME
    // =========================================================================

    /**
     * Take the archive rule out of the file for a download.
     *
     * @param int $minutes 15, 30 or 60.
     * @return array respond() shape.
     */
    public function pause($minutes) {
        if (!is_int($minutes) || !in_array($minutes, self::PAUSE_MINUTES, true)) {
            return $this->respond(false, 'invalid_minutes', 'The pause must be 15, 30 or 60 minutes.');
        }

        $statuses = $this->rule_statuses();
        $archives = $statuses['block_archives'];

        if ($archives['state'] === 'unsupported') {
            return $this->respond(false, 'unsupported', sprintf('Not supported on this server (%s).', $archives['unsupported_reason']));
        }

        if ($archives['state'] === 'paused') {
            return $this->move_pause($minutes);
        }

        if ($archives['state'] !== 'on') {
            return $this->respond(false, 'not_enabled', 'The archive rule is not on, so there is nothing to pause.');
        }

        // Desired state stays true: the pause only leaves the rule out of the block.
        return $this->apply('pause', 'block_archives', false, ['pause_minutes' => $minutes]);
    }

    /**
     * Pausing while already paused only moves pause_until. No file change, no self-test.
     *
     * @param int $minutes 15, 30 or 60.
     * @return array respond() shape.
     */
    private function move_pause($minutes) {
        if (!$this->acquire_lock()) {
            return $this->respond(false, 'busy', 'Another hardening operation is running on this site. Try again in a moment.');
        }

        $state                = $this->get_state();
        $state['pause_until'] = $this->now() + $minutes * 60;
        $state['last_result'] = [
            'at'       => $this->now(),
            'action'   => 'pause',
            'rule'     => 'block_archives',
            'ok'       => true,
            'reason'   => null,
            'warnings' => [],
        ];
        $this->save_state($state);
        $this->release_lock();

        LSM_Logger::log('hardening_applied', 'success', ['action' => 'pause', 'rule' => 'block_archives', 'moved' => true]);

        return $this->respond(true, null, sprintf('Already paused — the pause now ends in %d minutes.', $minutes));
    }

    /**
     * Put the archive rule back now. Idempotent: a no-op when nothing is paused.
     *
     * @return array respond() shape.
     */
    public function resume() {
        $state = $this->get_state();
        if ($state['pause_until'] === null) {
            return $this->respond(true, null, 'Nothing is paused.');
        }

        return $this->apply('resume', 'block_archives', true, ['pause_minutes' => null]);
    }

    // =========================================================================
    // AUTO-RESUME (LIGHT PATH)
    // =========================================================================

    /**
     * Are we running under WP-CLI / CLI cron?
     *
     * @return bool
     */
    protected function is_cli() {
        return PHP_SAPI === 'cli';
    }

    /**
     * Flush the response to the client so the work after it costs the visitor nothing.
     *
     * @return bool Whether the response was handed off to the client.
     */
    protected function finish_request() {
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return true;
        }
        if (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
            return true;
        }
        return false;
    }

    /**
     * Is this a request to one of our own lsm/v1/hardening/* routes?
     *
     * @return bool
     */
    private function is_hardening_request() {
        $checks = [
            $_SERVER['REQUEST_URI'] ?? '',
            $_GET['rest_route'] ?? '',
            $_SERVER['PATH_INFO'] ?? '',
            $_SERVER['REDIRECT_URL'] ?? '',
        ];
        foreach ($checks as $value) {
            // A crafted ?rest_route[]=x turns this into an array: it can never name our
            // route, and (string) $value would raise "Array to string conversion".
            if (!is_string($value)) {
                continue;
            }
            if (strpos(urldecode($value), '/lsm/v1/hardening') !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Load-time work, hooked on `init`. One cheap compare on the autoloaded option;
     * the actual re-apply runs on `shutdown`, never inline in a visitor or uptime request.
     */
    public function on_init() {
        $state = $this->get_state();

        // isset(): this runs on every request, and a damaged option must not raise a warning on
        // every page load. A pending without a start time counts as old.
        if (is_array($state['pending']) && $this->now() - (isset($state['pending']['started_at']) ? (int) $state['pending']['started_at'] : 0) > self::RECOVERY_AFTER) {
            $this->recover();
            $state = $this->get_state();
        }

        $overdue = $state['pause_until'] !== null && $state['pause_until'] < $this->now();
        if (!$overdue || $this->is_cli() || $this->is_hardening_request()) {
            return;
        }

        $last_attempt = (int) $state['last_attempt_at'];
        if ($this->now() - $last_attempt > self::RESUME_THROTTLE) {
            add_action('shutdown', [$this, 'run_auto_resume'], 9999);
        }
    }

    /**
     * Shutdown callback: answer the client first, then put the archive rule back.
     */
    public function run_auto_resume() {
        if (!$this->finish_request()) {
            // Neither finisher exists on this SAPI (mod_php, CGI): the light path would run
            // inside the visitor's — or the uptime probe's — connection. Do nothing at all and
            // leave it to the platform backstop and the REST resume endpoint.
            return;
        }
        $this->auto_resume();
    }

    /**
     * Put the archive rule back after an expired pause. Fails closed: the block was
     * verified on this host when it was enabled, so it is only rolled back when the
     * plugin stylesheet goes from 200 to non-200. pause_until is cleared only after
     * the read-back shows the rule in the block; a failed attempt leaves it in the
     * past (paused + overdue) and is retried after RESUME_THROTTLE seconds.
     */
    public function auto_resume() {
        if (!$this->acquire_lock()) {
            return;
        }

        if (function_exists('set_time_limit')) {
            @set_time_limit(120);
        }

        $state = $this->get_state();
        if ($state['pause_until'] === null || $state['pause_until'] >= $this->now()) {
            // Resumed or moved between init and shutdown.
            $this->release_lock();
            return;
        }

        $state['last_attempt_at'] = $this->now();
        $this->save_state($state);

        $this->finish('auto_resume', 'block_archives', $this->execute_auto_resume(), ['pause_minutes' => null]);
    }

    /**
     * The light path. Runs under the lock.
     *
     * @return array ['reason' => string|null, 'message' => string, 'warnings' => array]
     */
    private function execute_auto_resume() {
        $current = $this->file_facts('content');
        if ($current['corrupt']) {
            // Damaged markers — or a file that cannot be read (file_facts() reports both as corrupt).
            return ['reason' => 'markers_corrupt', 'message' => 'The .htaccess cannot be read or its LSM-HARDENING markers are damaged.', 'warnings' => []];
        }

        $enabled = ['block_archives'];
        foreach ($this->rules_of('content') as $other) {
            if ($current['in_block'][$other]) {
                $enabled[] = $other;
            }
        }
        $candidate = $this->replace_block($current['content'], $this->build_block('content', $enabled));

        $asset_before = $this->baseline_asset();
        $comparable   = $asset_before !== null && $this->asset_ok($asset_before);

        // The loopback above can take seconds: never write a candidate built from stale bytes.
        // The attempt fails, the pause stays overdue and the next attempt starts from the new bytes.
        $fresh = $this->read_target('content');
        if ($fresh['existed'] !== $current['existed'] || $fresh['content'] !== $current['content']) {
            return [
                'reason'   => 'write_failed',
                'message'  => 'The .htaccess was changed by something else while the self-test was running. Nothing was changed.',
                'warnings' => [],
            ];
        }

        if (!$this->write_snapshot('content', $current)) {
            return ['reason' => 'snapshot_failed', 'message' => 'The backup copy of the .htaccess could not be written.', 'warnings' => []];
        }
        $state            = $this->get_state();
        $state['pending'] = [
            'target'     => 'content',
            'op'         => 'resume',
            'started_at' => $this->now(),
            'existed'    => $current['existed'],
        ];
        $this->save_state($state);

        $written = $this->commit_target('content', $candidate, $current['content'], $current['existed']);
        $after   = $this->file_facts('content');
        if (!$written || !$after['in_block']['block_archives']) {
            $failure             = $this->rollback('content', $current, ['reason' => 'write_failed', 'message' => 'The archive rule did not read back from the .htaccess.']);
            $failure['warnings'] = [];
            return $failure;
        }

        if (!$comparable) {
            // The loopback itself does not work here: keep the block, say so.
            return ['reason' => null, 'message' => 'Archive rule restored (not verified).', 'warnings' => ['unverified']];
        }

        $asset_after = $this->baseline_asset();
        if ($asset_after['error']) {
            return ['reason' => null, 'message' => 'Archive rule restored (not verified).', 'warnings' => ['unverified']];
        }
        if ($asset_after['code'] !== 200) {
            $failure             = $this->rollback('content', $current, ['reason' => 'asset_broken', 'message' => sprintf('After the write the plugin stylesheet answered HTTP %d instead of 200.', $asset_after['code'])]);
            $failure['warnings'] = [];
            return $failure;
        }

        return ['reason' => null, 'message' => 'Archive rule restored.', 'warnings' => []];
    }

    // =========================================================================
    // CRASH RECOVERY
    // =========================================================================

    /**
     * A pending operation older than RECOVERY_AFTER was killed between write and finish.
     * No HTTP here: this runs inline on `init`.
     *
     * - op resume: roll forward — make sure the archive rule is in the block, then clear the pause.
     * - any other op: put the snapshot back (or take our block out of a file that did not exist).
     * - on success: delete the snapshot and the probe files, clear pending, record crash_recovered.
     * - on a failed restore: restore_from_snapshot() already stripped our block as a last resort,
     *   but the snapshot is the only remaining copy of the original bytes, so only the probe files
     *   are deleted; pending is still cleared and the outcome is recorded as rollback_failed.
     */
    private function recover() {
        if (!$this->acquire_lock()) {
            return;
        }

        $state   = $this->get_state();
        $pending = $state['pending'];
        // A pending without a start time (damaged option) counts as old and is recovered.
        if (!is_array($pending) || $this->now() - (isset($pending['started_at']) ? (int) $pending['started_at'] : 0) <= self::RECOVERY_AFTER) {
            $this->release_lock();
            return;
        }

        // The file comes from the enum, never from a stored path.
        $target   = isset($pending['target']) && $pending['target'] === 'uploads' ? 'uploads' : 'content';
        $op       = isset($pending['op']) ? (string) $pending['op'] : '';
        $resumed  = false;
        $restored = true;

        if ($op === 'resume') {
            $resumed = $this->roll_forward_resume();
        } else {
            $restored = $this->restore_from_snapshot($target, !empty($pending['existed']));
        }

        if ($restored) {
            $this->cleanup_artifacts();
        } else {
            // Keep the snapshot: it is the only copy of the original bytes left.
            $this->cleanup_probes();
        }

        if ($resumed) {
            $state['pause_until'] = null;
        }
        $state['pending'] = null;
        $reason           = $restored ? 'crash_recovered' : 'rollback_failed';

        $state['last_result'] = [
            'at'       => $this->now(),
            'action'   => 'crash_recovery',
            'rule'     => in_array($op, ['pause', 'resume'], true) ? 'block_archives' : null,
            'ok'       => false,
            'reason'   => $reason,
            'warnings' => [],
        ];
        $this->save_state($state);
        $this->release_lock();

        LSM_Logger::log('hardening_crash_recovered', $restored ? 'warning' : 'error', ['op' => $op, 'target' => $target, 'reason' => $reason]);
    }

    /**
     * Recovery of a killed resume: the light path without HTTP.
     *
     * @return bool True when the read-back shows the archive rule in the block.
     */
    private function roll_forward_resume() {
        $current = $this->file_facts('content');
        if ($current['corrupt']) {
            return false;
        }

        $enabled = ['block_archives'];
        foreach ($this->rules_of('content') as $other) {
            if ($current['in_block'][$other]) {
                $enabled[] = $other;
            }
        }
        $candidate = $this->replace_block($current['content'], $this->build_block('content', $enabled));

        if (!$this->commit_target('content', $candidate, $current['content'], $current['existed'])) {
            $this->restore_target('content', $current['content'], $current['existed']);
            return false;
        }

        $after = $this->file_facts('content');
        return $after['in_block']['block_archives'];
    }

    /**
     * Recovery of any other killed operation: back to the bytes from before it started.
     *
     * A write that is attempted and fails must never take the snapshot down with it — it is
     * the only remaining copy of the original bytes — so a failed restore falls back to
     * strip_managed_block(), the same last resort rollback() uses, and reports failure so the
     * caller (recover()) keeps the snapshot on disk instead of deleting it.
     *
     * @param string $target  'content' or 'uploads'.
     * @param bool   $existed pending.existed.
     * @return bool True when the file is verified back to a safe state (the snapshot was
     *              restored, the strip for a file that did not exist committed, or there was
     *              nothing to do); false when a write was attempted and failed.
     */
    private function restore_from_snapshot($target, $existed) {
        $snapshot = dirname($this->target_file($target)) . '/' . self::SNAPSHOT_FILE;

        if (is_file($snapshot)) {
            $original = @file_get_contents($snapshot);
            if ($original !== false && $this->restore_target($target, $original, true)) {
                return true;
            }
            $this->strip_managed_block($target);
            return false;
        }

        if (!$existed) {
            // No snapshot because there was no file: take our block out, delete the file if nothing else is in it.
            $current  = $this->read_target($target);
            $stripped = $this->replace_block($current['content'], '');
            if ($stripped === null || $stripped === $current['content']) {
                return true;
            }
            if ($this->commit_target($target, $stripped, $current['content'], false)) {
                return true;
            }
            $this->strip_managed_block($target);
            return false;
        }

        // Existed, no snapshot: nothing was ever written for us to undo.
        return true;
    }

    /**
     * Delete only the probe files in both directories, keeping any snapshot untouched.
     * Used when a crash restore failed and the snapshot is the only remaining copy of the
     * original bytes; cleanup_artifacts() is used on the normal, successful path instead.
     */
    private function cleanup_probes() {
        foreach ([$this->content_dir(), $this->uploads_dir()] as $dir) {
            foreach ((array) @scandir($dir) as $name) {
                if (is_string($name) && $name !== self::SNAPSHOT_FILE && self::is_own_artifact($name) && is_file($dir . '/' . $name)) {
                    @unlink($dir . '/' . $name);
                }
            }
        }
    }

    // =========================================================================
    // DEACTIVATION
    // =========================================================================

    /**
     * Plugin deactivation: a deactivated plugin can neither pause nor undo, so both
     * managed blocks come out. Skips the server preflight (often run from WP-CLI,
     * where SERVER_SOFTWARE is empty) and runs no self-test — removing deny rules
     * cannot take a site down.
     */
    public function deactivate() {
        // Take the lock if we can; deactivation goes ahead either way, there is no later.
        $this->acquire_lock();

        $removed = [];
        foreach (['content', 'uploads'] as $target) {
            $current  = $this->read_target($target);
            $stripped = $this->replace_block($current['content'], '');
            // Unreadable, corrupt markers, or no managed block: leave the file alone.
            if (!empty($current['unreadable']) || $stripped === null || $stripped === $current['content']) {
                continue;
            }
            if (!$this->commit_target($target, $stripped, $current['content'], $current['existed'])) {
                $this->restore_target($target, $current['content'], $current['existed']);
                continue;
            }
            $removed[] = $target;
        }

        $this->cleanup_artifacts();

        $state = $this->get_state();
        foreach (self::RULES as $rule) {
            $state['rules'][$rule] = false;
        }
        $state['pause_until'] = null;
        $state['pending']     = null;
        $state['last_result'] = [
            'at'       => $this->now(),
            'action'   => 'deactivate',
            'rule'     => null,
            'ok'       => true,
            'reason'   => null,
            'warnings' => [],
        ];
        $this->save_state($state);
        $this->release_lock();

        LSM_Logger::log('hardening_deactivated', 'info', ['removed_from' => $removed]);
    }
}

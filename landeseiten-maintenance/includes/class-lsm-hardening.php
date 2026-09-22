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

        $state['pause_until']   = $state['pause_until'] === null ? null : (int) $state['pause_until'];
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
}

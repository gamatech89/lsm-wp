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
}

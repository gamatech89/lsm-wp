<?php
/**
 * Security Scanner for Landeseiten Maintenance.
 *
 * Collection-only helpers used by the security collector:
 * - Suspicious file metadata enumeration (PHP in uploads, double extensions,
 *   hidden files, recently modified core files, PHP embedded in images)
 * - File permission audits
 * - Scan progress tracking
 *
 * All malware detection (signature matching, database anomaly checks,
 * core integrity comparisons) has moved server-side to the platform.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Security_Scanner {

    /**
     * Known-safe plugin directories that legitimately place PHP files in uploads.
     * Files from these directories are reported as 'info' severity instead of 'high'.
     */
    private static $safe_upload_paths = [
        'smush',           // WP Smush image optimization logs
        'sucuri',          // Sucuri security scanner files
        'borlabs-cookie',  // Borlabs Cookie GDPR cache
        'wpo-cache',       // WP-Optimize cache
        'wp-rocket',       // WP Rocket cache
        'cache',           // Generic cache directories
        'elementor',       // Elementor CSS/data files
        'wc-logs',         // WooCommerce log files
        'wp-file-manager', // WP File Manager plugin
        'updraftplus',     // UpdraftPlus backup plugin
        'backwpup',        // BackWPup backup plugin
        'w3tc',            // W3 Total Cache
        'breeze',          // Breeze cache plugin
        'litespeed',       // LiteSpeed cache plugin
        'sg-cachepress',   // SiteGround cache
        'hummingbird-cache', // Hummingbird cache
    ];

    /**
     * Scan tier configurations.
     * Each tier defines timeout, modules, directories to scan, and PHP time limit.
     */
    const SCAN_TIERS = [
        'quick' => [
            'timeout' => 30,
            'modules' => ['core_integrity', 'suspicious_files', 'permissions'],
            'malware_dirs' => [],
            'php_time_limit' => 60,
        ],
        'standard' => [
            'timeout' => 120,
            'modules' => ['core_integrity', 'malware_signatures', 'suspicious_files', 'htaccess', 'database', 'permissions'],
            'malware_dirs' => ['wp-content'],
            'php_time_limit' => 180,
        ],
        'full' => [
            'timeout' => 300,
            'modules' => ['core_integrity', 'malware_signatures', 'suspicious_files', 'htaccess', 'database', 'entropy_analysis', 'permissions'],
            'malware_dirs' => ['wp-content', 'wp-admin', 'wp-includes', '.'],
            'php_time_limit' => 600,
        ],
    ];

    /**
     * Maximum file size to scan (2 MB).
     */
    const MAX_FILE_SIZE = 2097152;

    /**
     * Batch size for file processing.
     */
    const BATCH_SIZE = 500;

    /**
     * File extensions to scan for malware patterns.
     */
    const SCANNABLE_EXTENSIONS = ['php', 'js', 'html', 'htm', 'svg', 'htaccess', 'phtml', 'php5', 'php7', 'phps', 'inc'];

    /**
     * File extensions to skip entirely (binary/media).
     */
    const SKIP_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'ico', 'bmp', 'webp', 'avif', 'tiff',
        'mp4', 'mp3', 'avi', 'mov', 'wmv', 'flv', 'webm', 'ogg',
        'zip', 'tar', 'gz', 'rar', '7z', 'bz2',
        'woff', 'woff2', 'ttf', 'eot', 'otf',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'sql', 'log', 'csv', 'xml', 'json',
        'map', 'lock', 'md', 'txt',
    ];

    private $start_time;
    private $timed_out = false;
    private $files_scanned = 0;
    private $scan_type = 'full';
    private $scan_id = null;

    // =========================================================================
    // MODULE 3: Suspicious File Detection
    // =========================================================================

    /**
     * Detect suspicious files in unusual locations.
     *
     * @return array
     */
    private function detect_suspicious_files() {
        $result = [
            'status' => 'pass',
            'findings' => [],
        ];

        // 1. PHP files in uploads directory
        $uploads_dir = wp_upload_dir()['basedir'];
        if (is_dir($uploads_dir)) {
            $php_in_uploads = $this->find_files_by_extension($uploads_dir, ['php', 'phtml', 'php5', 'php7']);
            foreach ($php_in_uploads as $file) {
                $relative_path = str_replace(ABSPATH, '', $file);

                // Check if this file is from a known-safe plugin
                $is_safe = false;
                $safe_plugin = '';
                foreach (self::$safe_upload_paths as $safe_path) {
                    if (stripos($relative_path, '/uploads/' . $safe_path . '/') !== false ||
                        stripos($relative_path, '/uploads/' . $safe_path . '-') !== false) {
                        $is_safe = true;
                        $safe_plugin = $safe_path;
                        break;
                    }
                }

                $result['findings'][] = [
                    'file' => $relative_path,
                    'reason' => $is_safe
                        ? sprintf('PHP file in uploads directory (known plugin: %s)', $safe_plugin)
                        : 'PHP file in uploads directory',
                    'severity' => $is_safe ? 'info' : 'high',
                    'modified_at' => gmdate('c', filemtime($file)),
                    'size' => filesize($file),
                ];
            }
        }

        // 2. Double extensions
        $content_dir = WP_CONTENT_DIR;
        $this->find_double_extensions($content_dir, $result);

        // 3. Hidden files in unusual locations (not in .git, .svn, etc.)
        $this->find_hidden_files($content_dir, $result);

        // 4. Recently modified core files (suspicious if no update was done)
        $this->find_recently_modified_core_files($result);

        // 5. ⭐ NEW: PHP code embedded in image files
        $this->find_php_in_images($uploads_dir, $result);

        // 6. ⭐ NEW: Fake plugin directories
        $this->detect_fake_plugins($result);

        if (!empty($result['findings'])) {
            $has_high = false;
            foreach ($result['findings'] as $f) {
                if (in_array($f['severity'], ['critical', 'high'])) {
                    $has_high = true;
                    break;
                }
            }
            $result['status'] = $has_high ? 'fail' : 'warning';
        }

        return $result;
    }

    /**
     * Detect PHP code embedded in image files.
     * Catches attacks like baucubmedia.de where PHP was hidden inside .ico/.jpg files.
     * Note: SVG files are excluded because they legitimately contain XML declarations (<?xml).
     */
    private function find_php_in_images($dir, &$result) {
        if (!is_dir($dir)) return;

        // Exclude SVG — they legitimately contain <?xml which triggers false positives
        $image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'ico', 'bmp', 'webp'];
        $image_files = $this->find_files_by_extension($dir, $image_extensions);

        foreach ($image_files as $file) {
            if ($this->is_timed_out()) break;
            if (filesize($file) > 1048576) continue; // Skip files > 1MB

            $content = @file_get_contents($file);
            if ($content === false) continue;

            // Only match actual PHP tags, not <?xml or other processing instructions
            if (preg_match('/<\?php\b|<\?=/i', $content)) {
                $result['findings'][] = [
                    'file' => str_replace(ABSPATH, '', $file),
                    'reason' => 'PHP code found inside image file — likely webshell',
                    'severity' => 'critical',
                    'modified_at' => gmdate('c', filemtime($file)),
                    'size' => filesize($file),
                ];
            }
        }
    }

    /**
     * Detect fake plugin directories.
     * Catches rogue plugins like the "developer-toolkit" found in baucubmedia.de.
     */
    private function detect_fake_plugins(&$result) {
        return;
    }

    // =========================================================================
    // MODULE 5: File Permission Audit
    // =========================================================================

    /**
     * Audit file permissions for security issues.
     *
     * @return array
     */
    private function audit_permissions() {
        $result = [
            'status' => 'pass',
            'findings' => [],
        ];

        // 1. wp-config.php permissions
        $wp_config = ABSPATH . 'wp-config.php';
        if (file_exists($wp_config)) {
            $perms = fileperms($wp_config) & 0777;
            if ($perms > 0440) {
                $result['findings'][] = [
                    'file' => 'wp-config.php',
                    'severity' => $perms >= 0666 ? 'high' : 'medium',
                    'reason' => sprintf('wp-config.php has permissions %s (recommended: 440 or 400)', decoct($perms)),
                    'current_permissions' => decoct($perms),
                    'recommended' => '440',
                ];
            }
        }

        // 2. .htaccess permissions
        $htaccess = ABSPATH . '.htaccess';
        if (file_exists($htaccess)) {
            $perms = fileperms($htaccess) & 0777;
            if ($perms > 0644) {
                $result['findings'][] = [
                    'file' => '.htaccess',
                    'severity' => 'medium',
                    'reason' => sprintf('.htaccess has permissions %s (recommended: 644 or less)', decoct($perms)),
                    'current_permissions' => decoct($perms),
                    'recommended' => '644',
                ];
            }
        }

        // 3. Check for world-writable directories in wp-content
        $this->check_writable_dirs(WP_CONTENT_DIR, $result, 0);

        // 4. Check wp-includes for write permissions
        $wp_includes = ABSPATH . 'wp-includes';
        if (is_dir($wp_includes) && is_writable($wp_includes)) {
            $result['findings'][] = [
                'file' => 'wp-includes/',
                'severity' => 'medium',
                'reason' => 'wp-includes directory is writable (should be read-only)',
                'current_permissions' => decoct(fileperms($wp_includes) & 0777),
                'recommended' => '755',
            ];
        }

        // 5. Check wp-admin for write permissions
        $wp_admin = ABSPATH . 'wp-admin';
        if (is_dir($wp_admin) && is_writable($wp_admin)) {
            $result['findings'][] = [
                'file' => 'wp-admin/',
                'severity' => 'low',
                'reason' => 'wp-admin directory is writable (should be read-only in production)',
                'current_permissions' => decoct(fileperms($wp_admin) & 0777),
                'recommended' => '755',
            ];
        }

        if (!empty($result['findings'])) {
            $has_high = false;
            foreach ($result['findings'] as $f) {
                if (in_array($f['severity'], ['critical', 'high'])) {
                    $has_high = true;
                    break;
                }
            }
            $result['status'] = $has_high ? 'fail' : 'warning';
        }

        return $result;
    }

    // =========================================================================
    // SCAN PROGRESS TRACKING
    // =========================================================================

    /**
     * Update scan progress via WordPress transient.
     * Called after each module completes so the frontend can poll for status.
     *
     * @param string     $module_name   Current module name.
     * @param string     $status        'running' or 'completed'.
     * @param int        $findings      Number of findings in this module.
     * @param array|null $all_modules   Full list of modules (only on init).
     */
    private function update_progress($module_name, $status, $findings = 0, $all_modules = null) {
        $progress = get_transient('lsm_scan_progress') ?: [
            'scan_id' => $this->scan_id,
            'scan_type' => $this->scan_type,
            'started_at' => $this->start_time,
            'modules' => [],
            'modules_list' => [],
            'current_module' => null,
            'files_scanned' => 0,
            'total_findings' => 0,
        ];

        // On initialization, pre-populate ALL modules as 'waiting' so the
        // frontend can display every step from the very start.
        if ($all_modules !== null) {
            $progress['modules_list'] = $all_modules;
            foreach ($all_modules as $mod) {
                if (!isset($progress['modules'][$mod])) {
                    $progress['modules'][$mod] = [
                        'status' => 'waiting',
                    ];
                }
            }
        }

        $progress['current_module'] = $module_name;
        $progress['files_scanned'] = $this->files_scanned;
        $progress['elapsed_seconds'] = round(microtime(true) - $this->start_time, 1);

        if ($status === 'completed') {
            $progress['modules'][$module_name] = [
                'status' => 'completed',
                'findings' => $findings,
                'completed_at' => microtime(true),
            ];
            $progress['total_findings'] += $findings;
        } else if ($status === 'running') {
            $progress['modules'][$module_name] = [
                'status' => 'running',
                'started_at' => microtime(true),
            ];
        }

        set_transient('lsm_scan_progress', $progress, 600); // 10 min TTL
    }

    /**
     * Get current scan progress (static, for API endpoint).
     *
     * @return array|null Progress data or null if no scan running.
     */
    public static function get_scan_progress() {
        $progress = get_transient('lsm_scan_progress');
        if (empty($progress)) {
            return null;
        }
        return $progress;
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /**
     * Check if scan has exceeded time limit.
     */
    private function is_timed_out() {
        if ($this->timed_out) return true;

        $tier = self::SCAN_TIERS[$this->scan_type] ?? self::SCAN_TIERS['full'];
        $elapsed = microtime(true) - $this->start_time;
        if ($elapsed >= $tier['timeout']) {
            $this->timed_out = true;
            return true;
        }
        return false;
    }

    /**
     * Get all scannable files in a directory, recursively.
     */
    private function get_scannable_files($dir) {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($this->is_timed_out()) break;
            if (!$file->isFile()) continue;

            $ext = strtolower($file->getExtension());

            // Skip binary files
            if (in_array($ext, self::SKIP_EXTENSIONS)) continue;

            // Only scan known scannable types, plus extensionless files
            if (!in_array($ext, self::SCANNABLE_EXTENSIONS) && !empty($ext)) continue;

            $files[] = $file->getPathname();
        }

        return $files;
    }

    /**
     * Find files with specific extensions in a directory.
     */
    private function find_files_by_extension($dir, $extensions) {
        $found = [];

        if (!is_dir($dir)) return $found;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($this->is_timed_out()) break;
            if (!$file->isFile()) continue;

            $ext = strtolower($file->getExtension());
            if (in_array($ext, $extensions)) {
                $found[] = $file->getPathname();
            }
        }

        return $found;
    }

    /**
     * Find files with double extensions (e.g. image.php.jpg).
     */
    private function find_double_extensions($dir, &$result) {
        $dangerous_inner_exts = ['php', 'phtml', 'php5', 'php7', 'exe', 'sh', 'bat'];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        $count = 0;
        foreach ($iterator as $file) {
            if ($this->is_timed_out() || $count > 5000) break;
            if (!$file->isFile()) continue;
            $count++;

            $name = $file->getFilename();
            // Check for patterns like "something.php.jpg"
            if (preg_match('/\.(' . implode('|', $dangerous_inner_exts) . ')\.\w+$/i', $name)) {
                $result['findings'][] = [
                    'file' => str_replace(ABSPATH, '', $file->getPathname()),
                    'reason' => 'Double extension — may attempt to bypass upload restrictions',
                    'severity' => 'high',
                    'modified_at' => gmdate('c', $file->getMTime()),
                    'size' => $file->getSize(),
                ];
            }
        }
    }

    /**
     * Find hidden files in unusual locations.
     */
    private function find_hidden_files($dir, &$result) {
        $skip_hidden = ['.htaccess', '.htpasswd', '.user.ini', '.well-known'];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        $count = 0;
        foreach ($iterator as $file) {
            if ($this->is_timed_out() || $count > 5000) break;
            if (!$file->isFile()) continue;
            $count++;

            $name = $file->getFilename();
            if ($name[0] === '.' && !in_array($name, $skip_hidden)) {
                // Check if it's a PHP file hidden with a dot prefix
                $ext = strtolower($file->getExtension());
                if (in_array($ext, ['php', 'phtml', 'php5'])) {
                    $result['findings'][] = [
                        'file' => str_replace(ABSPATH, '', $file->getPathname()),
                        'reason' => 'Hidden PHP file (dot-prefixed)',
                        'severity' => 'high',
                        'modified_at' => gmdate('c', $file->getMTime()),
                        'size' => $file->getSize(),
                    ];
                }
            }
        }
    }

    /**
     * Find recently modified core files that shouldn't have changed.
     */
    private function find_recently_modified_core_files(&$result) {
        $core_dirs = [ABSPATH . 'wp-admin/', ABSPATH . 'wp-includes/'];
        $two_days_ago = time() - 2 * DAY_IN_SECONDS;

        foreach ($core_dirs as $dir) {
            if (!is_dir($dir)) continue;

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );

            $count = 0;
            foreach ($iterator as $file) {
                if ($this->is_timed_out() || $count > 3000) break;
                if (!$file->isFile()) continue;
                $count++;

                if ($file->getMTime() > $two_days_ago) {
                    $result['findings'][] = [
                        'file' => str_replace(ABSPATH, '', $file->getPathname()),
                        'reason' => 'Core file modified within last 48 hours',
                        'severity' => 'medium',
                        'modified_at' => gmdate('c', $file->getMTime()),
                        'size' => $file->getSize(),
                    ];
                }
            }
        }
    }

    /**
     * Check for world-writable directories.
     */
    private function check_writable_dirs($dir, &$result, $depth) {
        if ($depth > 3 || $this->is_timed_out()) return; // Don't recurse too deep

        $perms = fileperms($dir) & 0777;
        if ($perms >= 0777) {
            $result['findings'][] = [
                'file' => str_replace(ABSPATH, '', $dir) . '/',
                'severity' => 'high',
                'reason' => sprintf('World-writable directory (permissions: %s)', decoct($perms)),
                'current_permissions' => decoct($perms),
                'recommended' => '755',
            ];
        }

        // Check subdirectories
        $subdirs = glob($dir . '/*', GLOB_ONLYDIR);
        if ($subdirs) {
            foreach ($subdirs as $subdir) {
                if ($this->is_timed_out()) break;
                $this->check_writable_dirs($subdir, $result, $depth + 1);
            }
        }
    }
}

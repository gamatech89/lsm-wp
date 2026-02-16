<?php
/**
 * Security Scanner for Landeseiten Maintenance.
 *
 * Performs filesystem-level malware scanning including:
 * - WordPress core integrity checks (against official checksums)
 * - Malware signature pattern matching
 * - Suspicious file detection (PHP in uploads, double extensions)
 * - Database anomaly detection (rogue admins, suspicious options)
 * - File permission audits
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Security_Scanner {

    /**
     * Maximum scan duration in seconds before bailing out.
     */
    const MAX_SCAN_TIME = 60;

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

    /**
     * Malware signature patterns organized by category.
     */
    private static $malware_patterns = [
        'backdoor' => [
            'eval(base64_decode(' => 'Base64 eval execution',
            'eval(gzinflate(' => 'Compressed eval execution',
            'eval(str_rot13(' => 'ROT13 eval execution',
            'eval(gzuncompress(' => 'Compressed eval execution',
            'eval(gzdecode(' => 'Compressed eval execution',
            'assert(base64_decode(' => 'Base64 assert execution',
            'assert(gzinflate(' => 'Compressed assert execution',
            'create_function(' => 'Dynamic function creation (deprecated)',
        ],
        'shell' => [
            'shell_exec($_' => 'Shell execution from user input',
            'system($_' => 'System call from user input',
            'passthru($_' => 'Passthrough from user input',
            'exec($_' => 'Exec from user input',
            'popen($_' => 'Process open from user input',
            'proc_open($_' => 'Process open from user input',
            'pcntl_exec(' => 'Process execution',
        ],
        'file_operation' => [
            'file_put_contents($_' => 'File write from user input',
            'fwrite($fp, base64_decode' => 'Base64 decoded file write',
            'fputs($fp, base64_decode' => 'Base64 decoded file write',
        ],
        'obfuscation' => [
            'chr(ord(' => 'Character ordinal obfuscation',
            '\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53' => 'Hex-encoded GLOBALS access',
            'preg_replace(\'/.*/' => 'Regex eval (potential code execution)',
        ],
        'known_malware' => [
            'wp_cd_code' => 'Known WP malware variant',
            'IconicState' => 'Known backdoor pattern',
            'wso_version' => 'Web Shell by oRb',
            'FilesMan' => 'FilesMan web shell',
            'b374k' => 'b374k web shell',
            'r57shell' => 'r57 shell',
            'c99shell' => 'c99 shell',
            'safe0ver' => 'Safe0ver shell',
            'GIF89a<?php' => 'PHP hidden in GIF header',
        ],
        'injection' => [
            'document.write(unescape' => 'JavaScript injection (unescape)',
            'String.fromCharCode(' => 'Obfuscated JavaScript (only in PHP files)',
            'window.location.href=\'http' => 'Redirect injection',
        ],
        'data_theft' => [
            '$_REQUEST[\'cmd\']' => 'Command parameter access',
            '$_GET[\'cmd\']' => 'Command parameter access',
            '$_POST[\'cmd\']' => 'Command parameter access',
            '$_REQUEST[\'eval\']' => 'Eval parameter access',
            'curl_exec' => 'Outbound data exfiltration (review context)',
        ],
    ];

    /**
     * Regex-based patterns for more complex detection.
     */
    private static $regex_patterns = [
        '/eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i' => [
            'description' => 'Direct eval of user input',
            'severity' => 'critical',
            'category' => 'backdoor',
        ],
        '/base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i' => [
            'description' => 'Base64 decode of user input',
            'severity' => 'critical',
            'category' => 'backdoor',
        ],
        '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){50,}/i' => [
            'description' => 'Long hex-encoded string (obfuscation)',
            'severity' => 'high',
            'category' => 'obfuscation',
        ],
        '/\$[a-z]{1,2}\s*\.\s*\$[a-z]{1,2}\s*\.\s*\$[a-z]{1,2}\s*\.\s*\$[a-z]{1,2}\s*\.\s*\$[a-z]{1,2}\s*\.\s*\$[a-z]{1,2}/i' => [
            'description' => 'Concatenated single-char variables (obfuscation)',
            'severity' => 'medium',
            'category' => 'obfuscation',
        ],
        '/preg_replace\s*\(\s*[\'"]\/.*\/[a-z]*e[a-z]*[\'"]\s*,/i' => [
            'description' => 'preg_replace with /e modifier (code execution)',
            'severity' => 'critical',
            'category' => 'backdoor',
        ],
        '/<\s*iframe\s+[^>]*src\s*=\s*[\'"]https?:\/\/(?!.*(?:youtube|vimeo|google|facebook))/i' => [
            'description' => 'Suspicious iframe injection',
            'severity' => 'high',
            'category' => 'injection',
        ],
    ];

    /**
     * Scan start time for timeout tracking.
     */
    private $start_time;

    /**
     * Whether the scan was cut short due to timeout.
     */
    private $timed_out = false;

    /**
     * Files scanned counter.
     */
    private $files_scanned = 0;

    /**
     * Run a full security scan.
     *
     * @param array $modules Which scan modules to run.
     * @param bool  $quick   Quick scan (core + uploads only).
     * @return array Scan results.
     */
    public function run($modules = null, $quick = false) {
        $this->start_time = microtime(true);
        $this->timed_out = false;
        $this->files_scanned = 0;

        $scan_id = wp_generate_uuid4();

        if ($modules === null) {
            $modules = ['core_integrity', 'malware_signatures', 'suspicious_files', 'database', 'permissions'];
        }

        if ($quick) {
            $modules = ['core_integrity', 'suspicious_files', 'permissions'];
        }

        $results = [];

        // Run each module
        foreach ($modules as $module) {
            if ($this->is_timed_out()) {
                break;
            }

            switch ($module) {
                case 'core_integrity':
                    $results['core_integrity'] = $this->check_core_integrity();
                    break;
                case 'malware_signatures':
                    $results['malware_signatures'] = $this->scan_malware_signatures();
                    break;
                case 'suspicious_files':
                    $results['suspicious_files'] = $this->detect_suspicious_files();
                    break;
                case 'database':
                    $results['database'] = $this->check_database_anomalies();
                    break;
                case 'permissions':
                    $results['permissions'] = $this->audit_permissions();
                    break;
            }
        }

        // Calculate summary
        $threats = 0;
        $warnings = 0;
        $worst_status = 'pass';

        foreach ($results as $module_result) {
            if (!empty($module_result['findings'])) {
                foreach ($module_result['findings'] as $finding) {
                    $severity = $finding['severity'] ?? 'low';
                    if (in_array($severity, ['critical', 'high'])) {
                        $threats++;
                    } else {
                        $warnings++;
                    }
                }
            }
            if ($module_result['status'] === 'fail') {
                $worst_status = 'fail';
            } elseif ($module_result['status'] === 'warning' && $worst_status !== 'fail') {
                $worst_status = 'warning';
            }
        }

        // Also count modified/unknown core files as threats
        if (!empty($results['core_integrity']['modified_files'])) {
            $threats += count($results['core_integrity']['modified_files']);
        }
        if (!empty($results['core_integrity']['unknown_files'])) {
            $warnings += count($results['core_integrity']['unknown_files']);
        }

        $risk_level = $this->calculate_risk_level($threats, $warnings);

        $duration = round(microtime(true) - $this->start_time, 2);

        return [
            'scan_id' => $scan_id,
            'started_at' => gmdate('c', (int) $this->start_time),
            'completed_at' => gmdate('c'),
            'duration_seconds' => $duration,
            'status' => $this->timed_out ? 'partial' : 'completed',
            'summary' => [
                'total_files_scanned' => $this->files_scanned,
                'threats_found' => $threats,
                'warnings_found' => $warnings,
                'clean' => $threats === 0,
                'risk_level' => $risk_level,
            ],
            'results' => $results,
        ];
    }

    // =========================================================================
    // MODULE 1: WordPress Core Integrity
    // =========================================================================

    /**
     * Check WordPress core file integrity against official checksums.
     *
     * @return array
     */
    private function check_core_integrity() {
        global $wp_version;

        $result = [
            'status' => 'pass',
            'wordpress_version' => $wp_version,
            'modified_files' => [],
            'unknown_files' => [],
            'missing_files' => [],
            'checked_files' => 0,
        ];

        // Fetch official checksums
        $checksums = $this->get_core_checksums($wp_version);
        if (empty($checksums)) {
            $result['status'] = 'warning';
            $result['error'] = 'Could not fetch official checksums from WordPress.org';
            return $result;
        }

        // Files/dirs to skip (expected to be different)
        $skip_files = [
            'wp-config.php',
            'wp-config-sample.php',
            '.htaccess',
            'robots.txt',
            'favicon.ico',
            'license.txt',
            'readme.html',
        ];

        $skip_dirs = [
            'wp-content/',
        ];

        foreach ($checksums as $file => $checksum) {
            if ($this->is_timed_out()) break;

            // Skip expected-to-differ files
            if (in_array($file, $skip_files)) continue;

            // Skip wp-content (has its own scanner)
            $skip = false;
            foreach ($skip_dirs as $dir) {
                if (strpos($file, $dir) === 0) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;

            $full_path = ABSPATH . $file;
            $result['checked_files']++;

            if (!file_exists($full_path)) {
                $result['missing_files'][] = $file;
                continue;
            }

            $file_hash = md5_file($full_path);
            if ($file_hash !== $checksum) {
                $result['modified_files'][] = [
                    'file' => $file,
                    'expected_hash' => $checksum,
                    'actual_hash' => $file_hash,
                    'severity' => 'high',
                    'modified_at' => gmdate('c', filemtime($full_path)),
                ];
            }
        }

        // Check for unknown files in WP root (not in checksums)
        $root_files = glob(ABSPATH . '*.php');
        $known_root_files = ['wp-config.php', 'wp-config-sample.php', 'wp-settings.php',
            'wp-blog-header.php', 'wp-load.php', 'wp-login.php', 'wp-signup.php',
            'wp-activate.php', 'wp-comments-post.php', 'wp-cron.php', 'wp-links-opml.php',
            'wp-mail.php', 'wp-trackback.php', 'xmlrpc.php', 'index.php',
            'wp-config.php', 'wp-config-sample.php',
        ];

        if ($root_files) {
            foreach ($root_files as $file) {
                $basename = basename($file);
                if (!in_array($basename, $known_root_files) && !isset($checksums[$basename])) {
                    $result['unknown_files'][] = [
                        'file' => $basename,
                        'severity' => 'medium',
                        'size' => filesize($file),
                        'modified_at' => gmdate('c', filemtime($file)),
                    ];
                }
            }
        }

        if (!empty($result['modified_files'])) {
            $result['status'] = 'fail';
        } elseif (!empty($result['unknown_files']) || !empty($result['missing_files'])) {
            $result['status'] = 'warning';
        }

        $this->files_scanned += $result['checked_files'];

        return $result;
    }

    /**
     * Fetch official WP core checksums.
     *
     * @param string $version WordPress version.
     * @return array|null
     */
    private function get_core_checksums($version) {
        $locale = get_locale();
        $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";

        $response = wp_remote_get($url, ['timeout' => 10]);
        if (is_wp_error($response)) {
            // Fallback to en_US
            $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US";
            $response = wp_remote_get($url, ['timeout' => 10]);
            if (is_wp_error($response)) {
                return null;
            }
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        return $body['checksums'] ?? null;
    }

    // =========================================================================
    // MODULE 2: Malware Signature Scanner
    // =========================================================================

    /**
     * Scan wp-content for malware signatures.
     *
     * @return array
     */
    private function scan_malware_signatures() {
        $result = [
            'status' => 'pass',
            'findings' => [],
            'files_scanned' => 0,
            'skipped_files' => 0,
        ];

        $scan_dir = WP_CONTENT_DIR;
        $files = $this->get_scannable_files($scan_dir);

        foreach (array_chunk($files, self::BATCH_SIZE) as $batch) {
            if ($this->is_timed_out()) break;

            foreach ($batch as $file) {
                if ($this->is_timed_out()) break;

                $result['files_scanned']++;
                $this->files_scanned++;

                // Skip large files
                $size = @filesize($file);
                if ($size > self::MAX_FILE_SIZE) {
                    $result['skipped_files']++;
                    continue;
                }

                $content = @file_get_contents($file);
                if ($content === false) continue;

                $relative_path = str_replace(ABSPATH, '', $file);

                // Check string patterns
                foreach (self::$malware_patterns as $category => $patterns) {
                    foreach ($patterns as $pattern => $description) {
                        if (stripos($content, $pattern) !== false) {
                            // Find the line number
                            $line = $this->find_line_number($content, $pattern);
                            $snippet = $this->get_snippet($content, $pattern);

                            $result['findings'][] = [
                                'file' => $relative_path,
                                'line' => $line,
                                'pattern' => $pattern,
                                'description' => $description,
                                'severity' => $this->get_pattern_severity($category),
                                'category' => $category,
                                'snippet' => $snippet,
                            ];
                        }
                    }
                }

                // Check regex patterns
                foreach (self::$regex_patterns as $regex => $info) {
                    if (preg_match($regex, $content, $matches, PREG_OFFSET_CAPTURE)) {
                        $line = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                        $snippet = $this->get_snippet_at_offset($content, $matches[0][1]);

                        $result['findings'][] = [
                            'file' => $relative_path,
                            'line' => $line,
                            'pattern' => substr($matches[0][0], 0, 100),
                            'description' => $info['description'],
                            'severity' => $info['severity'],
                            'category' => $info['category'],
                            'snippet' => $snippet,
                        ];
                    }
                }
            }
        }

        if (!empty($result['findings'])) {
            $has_critical = false;
            foreach ($result['findings'] as $f) {
                if (in_array($f['severity'], ['critical', 'high'])) {
                    $has_critical = true;
                    break;
                }
            }
            $result['status'] = $has_critical ? 'fail' : 'warning';
        }

        return $result;
    }

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
                $result['findings'][] = [
                    'file' => str_replace(ABSPATH, '', $file),
                    'reason' => 'PHP file in uploads directory',
                    'severity' => 'high',
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
    // MODULE 4: Database Anomaly Check
    // =========================================================================

    /**
     * Check database for security anomalies.
     *
     * @return array
     */
    private function check_database_anomalies() {
        global $wpdb;

        $result = [
            'status' => 'pass',
            'findings' => [],
        ];

        // 1. Check for recently added admin users (last 7 days)
        $seven_days_ago = gmdate('Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS);
        $recent_users = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered
             FROM {$wpdb->users} u
             INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
             WHERE um.meta_key = %s
             AND um.meta_value LIKE %s
             AND u.user_registered > %s",
            $wpdb->prefix . 'capabilities',
            '%administrator%',
            $seven_days_ago
        ));

        foreach ($recent_users as $user) {
            $result['findings'][] = [
                'type' => 'new_admin',
                'severity' => 'high',
                'description' => sprintf(
                    'New administrator account created: %s (%s) on %s',
                    $user->user_login,
                    $user->user_email,
                    $user->user_registered
                ),
                'details' => [
                    'user_id' => $user->ID,
                    'username' => $user->user_login,
                    'email' => $user->user_email,
                    'registered' => $user->user_registered,
                ],
            ];
        }

        // 2. Check for siteurl/home changes (compare with wp-config if defined)
        if (defined('WP_SITEURL')) {
            $db_siteurl = get_option('siteurl');
            if ($db_siteurl !== WP_SITEURL) {
                $result['findings'][] = [
                    'type' => 'siteurl_mismatch',
                    'severity' => 'critical',
                    'description' => sprintf(
                        'Site URL mismatch: DB has "%s" but wp-config defines "%s"',
                        $db_siteurl,
                        WP_SITEURL
                    ),
                ];
            }
        }

        // 3. Check for suspicious cron jobs
        $crons = _get_cron_array();
        if ($crons) {
            foreach ($crons as $timestamp => $cron_hooks) {
                foreach ($cron_hooks as $hook => $cron_events) {
                    // Flag cron hooks that look suspicious
                    if (preg_match('/^[a-f0-9]{8,}$/', $hook) || // Random hex names
                        preg_match('/^wp_[a-f0-9]{6,}$/', $hook) || // Fake WP hooks
                        strpos($hook, 'eval') !== false ||
                        strpos($hook, 'exec') !== false ||
                        strpos($hook, 'base64') !== false
                    ) {
                        $result['findings'][] = [
                            'type' => 'suspicious_cron',
                            'severity' => 'high',
                            'description' => sprintf('Suspicious cron job: "%s" scheduled for %s',
                                $hook,
                                gmdate('c', $timestamp)
                            ),
                            'details' => [
                                'hook' => $hook,
                                'next_run' => gmdate('c', $timestamp),
                            ],
                        ];
                    }
                }
            }
        }

        // 4. Check for base64 content in widget_text
        $widget_text = get_option('widget_text');
        if ($widget_text && is_array($widget_text)) {
            foreach ($widget_text as $key => $widget) {
                if (is_array($widget) && isset($widget['text'])) {
                    if (preg_match('/base64_decode|eval\(|<\s*script/i', $widget['text'])) {
                        $result['findings'][] = [
                            'type' => 'suspicious_widget',
                            'severity' => 'high',
                            'description' => sprintf('Suspicious code in text widget #%s', $key),
                            'details' => [
                                'widget_key' => $key,
                                'snippet' => substr($widget['text'], 0, 200),
                            ],
                        ];
                    }
                }
            }
        }

        // 5. Check for unknown users with admin capabilities
        $admin_count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->usermeta} 
             WHERE meta_key = %s AND meta_value LIKE %s",
            $wpdb->prefix . 'capabilities',
            '%administrator%'
        ));

        $result['admin_count'] = (int) $admin_count;

        if (!empty($result['findings'])) {
            $result['status'] = 'warning';
            foreach ($result['findings'] as $f) {
                if ($f['severity'] === 'critical') {
                    $result['status'] = 'fail';
                    break;
                }
            }
        }

        return $result;
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
    // HELPER METHODS
    // =========================================================================

    /**
     * Check if scan has exceeded time limit.
     */
    private function is_timed_out() {
        if ($this->timed_out) return true;

        $elapsed = microtime(true) - $this->start_time;
        if ($elapsed >= self::MAX_SCAN_TIME) {
            $this->timed_out = true;
            return true;
        }
        return false;
    }

    /**
     * Calculate risk level from threat and warning counts.
     */
    private function calculate_risk_level($threats, $warnings) {
        if ($threats >= 5) return 'critical';
        if ($threats >= 2) return 'high';
        if ($threats >= 1) return 'medium';
        if ($warnings >= 5) return 'low';
        return 'clean';
    }

    /**
     * Get severity level for a pattern category.
     */
    private function get_pattern_severity($category) {
        switch ($category) {
            case 'backdoor':
            case 'shell':
            case 'known_malware':
                return 'critical';
            case 'file_operation':
            case 'injection':
            case 'data_theft':
                return 'high';
            case 'obfuscation':
                return 'medium';
            default:
                return 'low';
        }
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
     * Find line number of a pattern in content.
     */
    private function find_line_number($content, $pattern) {
        $pos = stripos($content, $pattern);
        if ($pos === false) return 0;
        return substr_count(substr($content, 0, $pos), "\n") + 1;
    }

    /**
     * Get a code snippet around a pattern match.
     */
    private function get_snippet($content, $pattern) {
        $pos = stripos($content, $pattern);
        if ($pos === false) return '';

        return $this->get_snippet_at_offset($content, $pos);
    }

    /**
     * Get a code snippet around an offset position.
     */
    private function get_snippet_at_offset($content, $pos) {
        $start = max(0, $pos - 50);
        $length = min(strlen($content) - $start, 200);
        $snippet = substr($content, $start, $length);

        // Clean up for display
        $snippet = preg_replace('/\s+/', ' ', $snippet);
        $snippet = trim($snippet);

        if ($start > 0) $snippet = '...' . $snippet;
        if ($start + $length < strlen($content)) $snippet .= '...';

        return $snippet;
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

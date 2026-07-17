<?php
// landeseiten-maintenance/includes/class-lsm-scan-collector.php
if (!defined('ABSPATH')) { exit; }

class LSM_Scan_Collector {

    private $scan_type;
    private $token;
    private $start_time;
    private $files_scanned = 0;

    public function run($modules, $scan_type = 'full') {
        if (!isset(LSM_Security_Scanner::SCAN_TIERS[$scan_type])) {
            $scan_type = 'full';
        }
        $this->scan_type = $scan_type;
        $this->start_time = microtime(true);

        global $wp_version;

        // 1. Open a session on the platform.
        $session = $this->post('/scanner/session', [
            'scan_id'    => (int) ($modules['__scan_id'] ?? 0),
            'scan_type'  => $scan_type,
            'wp_version' => $wp_version,
            'locale'     => get_locale(),
        ]);
        if (!$session || empty($session['token'])) {
            return $this->partial('Could not open scan session with the platform');
        }
        $this->token = $session['token'];
        $spam_keywords = $session['spam_keywords'] ?? [];

        // 2. Build the file manifest and ask which contents are needed.
        $manifest = $this->build_manifest($scan_type);
        $needed = [];
        foreach (array_chunk($manifest, 1000) as $chunk) {
            $resp = $this->post('/scanner/manifest', [
                'token'      => $this->token,
                'wp_version' => $wp_version,
                'locale'     => get_locale(),
                'manifest'   => $chunk,
            ]);
            if ($resp && !empty($resp['needed_paths'])) {
                $needed = array_merge($needed, $resp['needed_paths']);
            }
        }

        // 3. Upload needed file contents in ~2MB batches (skip for quick tier).
        if ($scan_type !== 'quick') {
            $this->upload_files($needed);
        }

        // 4. Collect DB + metadata and finalize.
        $collector_db = new LSM_Scan_Data_Collector($spam_keywords);
        $finalize = $this->post('/scanner/finalize', [
            'token'            => $this->token,
            'home_host'        => parse_url(home_url(), PHP_URL_HOST) ?: '',
            'htaccess_files'   => $this->collect_htaccess(),
            'database'         => in_array('database', LSM_Security_Scanner::SCAN_TIERS[$scan_type]['modules'], true)
                                    ? $collector_db->collect() : [],
            'suspicious_files' => $this->collect_suspicious_files(),
            'permissions'      => $this->collect_permissions(),
        ]);

        if (!$finalize || empty($finalize['results'])) {
            return $this->partial('Finalize step failed');
        }
        return $finalize['results'];
    }

    private function upload_files($needed) {
        $batch = [];
        $bytes = 0;
        foreach ($needed as $rel) {
            $full = ABSPATH . $rel;
            $size = @filesize($full);
            if ($size === false || $size > LSM_Security_Scanner::MAX_FILE_SIZE) continue;
            $content = @file_get_contents($full);
            if ($content === false) continue;

            $batch[] = ['path' => $rel, 'content_b64' => base64_encode($content), 'ext' => strtolower(pathinfo($rel, PATHINFO_EXTENSION))];
            $bytes += $size;
            $this->files_scanned++;

            if ($bytes >= 1572864) { // ~1.5MB raw -> ~2MB b64
                $this->flush_batch($batch);
                $batch = []; $bytes = 0;
            }
        }
        if ($batch) $this->flush_batch($batch);
    }

    private function flush_batch($batch) {
        $this->post('/scanner/files', ['token' => $this->token, 'files' => $batch]);
    }

    private function build_manifest($scan_type) {
        $scanner = new LSM_Security_Scanner();
        $dirs = [WP_CONTENT_DIR];
        if ($scan_type === 'full') {
            $dirs[] = ABSPATH . 'wp-admin';
            $dirs[] = ABSPATH . 'wp-includes';
        }
        $manifest = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) continue;
            foreach ($scanner->public_scannable_files($dir) as $file) {
                $size = @filesize($file);
                if ($size === false) continue;
                $manifest[] = [
                    'path' => str_replace(ABSPATH, '', $file),
                    'md5'  => md5_file($file),
                    'size' => $size,
                ];
            }
        }
        foreach (glob(ABSPATH . '*.php') ?: [] as $file) {
            $manifest[] = ['path' => basename($file), 'md5' => md5_file($file), 'size' => filesize($file)];
        }
        return $manifest;
    }

    private function post($path, $body) {
        $settings = Landeseiten_Maintenance::get_setting();
        $api_key = $settings['api_key'] ?? '';
        if (empty($api_key)) return null;

        $response = wp_remote_post(LSM_Ticket_Client::base_url() . $path, [
            'timeout' => 60,
            'headers' => ['X-LSM-Key' => $api_key, 'Content-Type' => 'application/json', 'Accept' => 'application/json'],
            'body'    => wp_json_encode($body),
        ]);
        if (is_wp_error($response)) return null;
        if (wp_remote_retrieve_response_code($response) >= 300) return null;
        return json_decode(wp_remote_retrieve_body($response), true);
    }

    private function partial($message) {
        return [
            'scan_id' => '', 'status' => 'partial',
            'started_at' => gmdate('c', (int) $this->start_time), 'completed_at' => gmdate('c'),
            'duration_seconds' => round(microtime(true) - $this->start_time, 2),
            'summary' => ['total_files_scanned' => $this->files_scanned, 'threats_found' => 0, 'warnings_found' => 0, 'clean' => true, 'risk_level' => 'clean'],
            'results' => [], 'error' => $message,
        ];
    }

    /**
     * Collect .htaccess file contents for tampering checks.
     */
    private function collect_htaccess() {
        $files = [];
        $found = [];
        $search = [ABSPATH, WP_CONTENT_DIR];
        foreach ($search as $dir) {
            $this->find_htaccess($dir, $found, 5, 0);
        }
        $out = [];
        foreach (array_unique($found) as $file) {
            if (@filesize($file) > 65536) continue;
            $content = @file_get_contents($file);
            if ($content === false) continue;
            $out[] = ['path' => str_replace(ABSPATH, '', $file), 'content_b64' => base64_encode($content)];
        }
        return $out;
    }

    /**
     * Recursively locate .htaccess files up to $max_depth, skipping VCS/vendor dirs.
     */
    private function find_htaccess($dir, &$files, $max_depth, $depth) {
        if ($depth > $max_depth || !is_dir($dir)) return;
        $ht = $dir . '/.htaccess';
        if (file_exists($ht)) $files[] = $ht;
        foreach (@glob($dir . '/*', GLOB_ONLYDIR | GLOB_NOSORT) ?: [] as $sub) {
            $base = basename($sub);
            if (in_array($base, ['.git', '.svn', 'node_modules', '.hg'], true)) continue;
            $this->find_htaccess($sub, $files, $max_depth, $depth + 1);
        }
    }

    /**
     * Collect suspicious file metadata (PHP in uploads, double extensions, hidden PHP,
     * recently-modified core, PHP-in-images, plugin dir listing). Classification of
     * ambiguous findings (e.g. fake plugins) is deferred to the server.
     */
    private function collect_suspicious_files() {
        $scanner = new LSM_Security_Scanner();
        $result = $scanner->public_detect_suspicious_files();
        return $result['findings'] ?? [];
    }

    /**
     * Collect file/directory permission info for hardening checks.
     */
    private function collect_permissions() {
        $scanner = new LSM_Security_Scanner();
        $result = $scanner->public_audit_permissions();
        return $result['findings'] ?? [];
    }
}

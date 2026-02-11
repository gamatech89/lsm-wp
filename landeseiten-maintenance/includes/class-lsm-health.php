<?php
/**
 * Health monitoring class for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Health class.
 */
class LSM_Health {

    /**
     * Get comprehensive health data.
     *
     * @return array
     */
    public function get_health_data() {
        return [
            'status'           => $this->get_overall_status(),
            'timestamp'        => current_time('mysql'),
            'site_url'   => get_site_url(),
            'wordpress'  => $this->get_wordpress_info(),
            'php'        => $this->get_php_info(),
            'server'     => $this->get_server_info(),
            'plugins'    => $this->get_plugins_info(),
            'themes'     => $this->get_themes_info(),
            'ssl'        => $this->get_ssl_info(),
            'database'   => $this->get_database_info(),
            'disk'       => $this->get_disk_info(),
        ];
    }

    /**
     * Get overall health status.
     *
     * @return string healthy|warning|critical
     */
    private function get_overall_status() {
        $issues = 0;
        $critical = 0;

        // Ensure update functions are available
        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        // Check for outdated plugins
        $plugin_updates = get_plugin_updates();
        if (count($plugin_updates) > 5) {
            $issues++;
        }
        if (count($plugin_updates) > 10) {
            $critical++;
        }

        // Check for core updates
        $core_updates = get_core_updates();
        if (!empty($core_updates) && isset($core_updates[0]->response) && $core_updates[0]->response === 'upgrade') {
            $issues++;
        }

        // Check SSL
        if (!is_ssl()) {
            $issues++;
        }

        if ($critical > 0) {
            return 'critical';
        }
        if ($issues > 0) {
            return 'warning';
        }
        return 'healthy';
    }

    /**
     * Get WordPress information.
     *
     * @return array
     */
    private function get_wordpress_info() {
        global $wp_version;

        return [
            'version'     => $wp_version,
            'multisite'   => is_multisite(),
            'locale'      => get_locale(),
            'timezone'    => wp_timezone_string(),
            'home_url'    => home_url(),
            'site_url'    => site_url(),
            'debug_mode'  => defined('WP_DEBUG') && WP_DEBUG,
        ];
    }

    /**
     * Get PHP information.
     *
     * @return array
     */
    private function get_php_info() {
        return [
            'version'          => phpversion(),
            'memory_limit'     => ini_get('memory_limit'),
            'max_execution'    => ini_get('max_execution_time'),
            'upload_max'       => ini_get('upload_max_filesize'),
            'post_max'         => ini_get('post_max_size'),
            'extensions'       => get_loaded_extensions(),
        ];
    }

    /**
     * Get server information.
     *
     * @return array
     */
    private function get_server_info() {
        return [
            'software'     => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'protocol'     => isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'Unknown',
            'document_root'=> isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : 'Unknown',
        ];
    }

    /**
     * Get plugins information.
     *
     * @return array
     */
    private function get_plugins_info() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', []);
        $plugin_updates = get_plugin_updates();

        $plugins = [];
        foreach ($all_plugins as $file => $data) {
            $plugins[] = [
                'name'        => $data['Name'],
                'version'     => $data['Version'],
                'active'      => in_array($file, $active_plugins),
                'update'      => isset($plugin_updates[$file]),
                'new_version' => isset($plugin_updates[$file]) ? $plugin_updates[$file]->update->new_version : null,
            ];
        }

        return [
            'total'          => count($all_plugins),
            'active'         => count($active_plugins),
            'outdated_count' => count($plugin_updates),
            'list'           => $plugins,
        ];
    }

    /**
     * Get themes information.
     *
     * @return array
     */
    private function get_themes_info() {
        if (!function_exists('get_theme_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $current_theme = wp_get_theme();
        $all_themes = wp_get_themes();
        $theme_updates = get_theme_updates();

        return [
            'current' => [
                'name'    => $current_theme->get('Name'),
                'version' => $current_theme->get('Version'),
                'parent'  => $current_theme->parent() ? $current_theme->parent()->get('Name') : null,
            ],
            'total'          => count($all_themes),
            'outdated_count' => count($theme_updates),
        ];
    }

    /**
     * Get SSL information.
     *
     * @return array
     */
    private function get_ssl_info() {
        $ssl_enabled = is_ssl();
        $ssl_info = [
            'enabled' => $ssl_enabled,
            'status'  => $ssl_enabled ? 'valid' : 'none',
        ];

        // Try to get SSL certificate info
        if ($ssl_enabled) {
            $url = get_site_url();
            $parsed = parse_url($url);
            $host = $parsed['host'] ?? '';

            $context = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
            $stream = @stream_socket_client(
                "ssl://{$host}:443",
                $errno,
                $errstr,
                30,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if ($stream) {
                $params = stream_context_get_params($stream);
                if (isset($params['options']['ssl']['peer_certificate'])) {
                    $cert_info = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
                    if ($cert_info) {
                        $ssl_info['issuer'] = $cert_info['issuer']['O'] ?? 'Unknown';
                        $ssl_info['expires'] = date('Y-m-d', $cert_info['validTo_time_t']);
                        $ssl_info['expires_at'] = date('Y-m-d H:i:s', $cert_info['validTo_time_t']);
                    }
                }
                fclose($stream);
            }
        }

        return $ssl_info;
    }

    /**
     * Get database information.
     *
     * @return array
     */
    private function get_database_info() {
        global $wpdb;

        $tables = $wpdb->get_results("SHOW TABLE STATUS LIKE '{$wpdb->prefix}%'");
        $total_size = 0;
        $table_count = 0;

        foreach ($tables as $table) {
            $total_size += $table->Data_length + $table->Index_length;
            $table_count++;
        }

        return [
            'version'     => $wpdb->db_version(),
            'prefix'      => $wpdb->prefix,
            'tables'      => $table_count,
            'size'        => size_format($total_size),
            'size_bytes'  => $total_size,
        ];
    }

    /**
     * Get disk information.
     *
     * @return array
     */
    private function get_disk_info() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        $wp_path = ABSPATH;

        // Use disk_free_space which is fast, instead of recursive size calculation
        $disk_free = @disk_free_space($wp_path);
        $disk_total = @disk_total_space($wp_path);
        
        return [
            'uploads_path' => $uploads_path,
            'wp_path'      => $wp_path,
            'disk_free'    => $disk_free !== false ? size_format($disk_free) : 'Unknown',
            'disk_total'   => $disk_total !== false ? size_format($disk_total) : 'Unknown',
            'disk_used_percent' => ($disk_free !== false && $disk_total !== false && $disk_total > 0) 
                ? round(100 - ($disk_free / $disk_total * 100), 1) 
                : null,
        ];
    }
}

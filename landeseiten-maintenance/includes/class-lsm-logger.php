<?php
/**
 * Logger class for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Logger class.
 * 
 * Captures WordPress activity for remote monitoring.
 */
class LSM_Logger {

    /**
     * Maximum log entries to keep.
     */
    const MAX_ENTRIES = 200;

    /**
     * Initialize activity logging hooks.
     */
    public static function init() {
        // Plugin events
        add_action('activated_plugin', [__CLASS__, 'on_plugin_activated'], 10, 2);
        add_action('deactivated_plugin', [__CLASS__, 'on_plugin_deactivated'], 10, 2);
        add_action('upgrader_process_complete', [__CLASS__, 'on_upgrade_complete'], 10, 2);
        add_action('deleted_plugin', [__CLASS__, 'on_plugin_deleted'], 10, 2);
        
        // Theme events
        add_action('switch_theme', [__CLASS__, 'on_theme_switch'], 10, 3);
        
        // Core update
        add_action('_core_updated_successfully', [__CLASS__, 'on_core_updated']);
        
        // User events
        add_action('wp_login', [__CLASS__, 'on_user_login'], 10, 2);
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed']);
        add_action('user_register', [__CLASS__, 'on_user_registered']);
        add_action('delete_user', [__CLASS__, 'on_user_deleted']);
        
        // Options/Settings changes (useful for security)
        add_action('update_option_blogname', [__CLASS__, 'on_site_name_changed'], 10, 2);
        add_action('update_option_siteurl', [__CLASS__, 'on_site_url_changed'], 10, 2);
        add_action('update_option_home', [__CLASS__, 'on_home_url_changed'], 10, 2);
        
        // Post events (only significant ones)
        add_action('transition_post_status', [__CLASS__, 'on_post_status_change'], 10, 3);
    }

    // =========================================================================
    // EVENT HANDLERS
    // =========================================================================

    /**
     * Plugin activated.
     */
    public static function on_plugin_activated($plugin, $network_wide = false) {
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
        self::log('plugin_activated', 'success', [
            'plugin' => $plugin,
            'name' => $plugin_data['Name'] ?? $plugin,
            'version' => $plugin_data['Version'] ?? 'unknown',
            'network_wide' => $network_wide,
        ]);
    }

    /**
     * Plugin deactivated.
     */
    public static function on_plugin_deactivated($plugin, $network_wide = false) {
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
        self::log('plugin_deactivated', 'info', [
            'plugin' => $plugin,
            'name' => $plugin_data['Name'] ?? $plugin,
            'network_wide' => $network_wide,
        ]);
    }

    /**
     * Plugin deleted.
     */
    public static function on_plugin_deleted($plugin, $deleted) {
        if ($deleted) {
            self::log('plugin_deleted', 'warning', [
                'plugin' => $plugin,
            ]);
        }
    }

    /**
     * Upgrade complete (plugin, theme, or core).
     */
    public static function on_upgrade_complete($upgrader, $options) {
        if (!isset($options['type'])) {
            return;
        }

        switch ($options['type']) {
            case 'plugin':
                if (isset($options['plugins'])) {
                    foreach ($options['plugins'] as $plugin) {
                        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
                        self::log('plugin_updated', 'success', [
                            'plugin' => $plugin,
                            'name' => $plugin_data['Name'] ?? $plugin,
                            'new_version' => $plugin_data['Version'] ?? 'unknown',
                        ]);
                    }
                }
                break;
            case 'theme':
                if (isset($options['themes'])) {
                    foreach ($options['themes'] as $theme) {
                        self::log('theme_updated', 'success', [
                            'theme' => $theme,
                        ]);
                    }
                }
                break;
            case 'core':
                global $wp_version;
                self::log('core_updated', 'success', [
                    'version' => $wp_version,
                ]);
                break;
        }
    }

    /**
     * Theme switched.
     */
    public static function on_theme_switch($new_name, $new_theme, $old_theme = null) {
        self::log('theme_switched', 'info', [
            'new_theme' => $new_name,
            'new_stylesheet' => $new_theme->get_stylesheet(),
            'old_theme' => $old_theme ? $old_theme->get('Name') : null,
        ]);
    }

    /**
     * WordPress core updated.
     */
    public static function on_core_updated($version = null) {
        global $wp_version;
        self::log('core_updated', 'success', [
            'version' => $version ?? $wp_version,
        ]);
    }

    /**
     * User logged in.
     */
    public static function on_user_login($user_login, $user) {
        self::log('user_login', 'info', [
            'user_id' => $user->ID,
            'username' => $user_login,
            'roles' => $user->roles,
        ]);
    }

    /**
     * Login failed.
     */
    public static function on_login_failed($username) {
        self::log('login_failed', 'warning', [
            'username' => $username,
        ]);
    }

    /**
     * User registered.
     */
    public static function on_user_registered($user_id) {
        $user = get_userdata($user_id);
        self::log('user_registered', 'info', [
            'user_id' => $user_id,
            'username' => $user ? $user->user_login : 'unknown',
            'email' => $user ? $user->user_email : 'unknown',
        ]);
    }

    /**
     * User deleted.
     */
    public static function on_user_deleted($user_id) {
        self::log('user_deleted', 'warning', [
            'user_id' => $user_id,
        ]);
    }

    /**
     * Site name changed.
     */
    public static function on_site_name_changed($old_value, $new_value) {
        self::log('setting_changed', 'info', [
            'setting' => 'blogname',
            'old_value' => $old_value,
            'new_value' => $new_value,
        ]);
    }

    /**
     * Site URL changed.
     */
    public static function on_site_url_changed($old_value, $new_value) {
        self::log('setting_changed', 'warning', [
            'setting' => 'siteurl',
            'old_value' => $old_value,
            'new_value' => $new_value,
        ]);
    }

    /**
     * Home URL changed.
     */
    public static function on_home_url_changed($old_value, $new_value) {
        self::log('setting_changed', 'warning', [
            'setting' => 'home',
            'old_value' => $old_value,
            'new_value' => $new_value,
        ]);
    }

    /**
     * Post status changed (only for publish/trash).
     */
    public static function on_post_status_change($new_status, $old_status, $post) {
        // Only log significant transitions
        if ($new_status === $old_status) {
            return;
        }

        // Only log page and post types
        if (!in_array($post->post_type, ['post', 'page'])) {
            return;
        }

        // Only log publish and trash events
        if ($new_status === 'publish' && $old_status !== 'publish') {
            self::log('content_published', 'info', [
                'post_id' => $post->ID,
                'post_type' => $post->post_type,
                'title' => $post->post_title,
            ]);
        } elseif ($new_status === 'trash') {
            self::log('content_trashed', 'warning', [
                'post_id' => $post->ID,
                'post_type' => $post->post_type,
                'title' => $post->post_title,
            ]);
        }
    }

    // =========================================================================
    // CORE LOGGING METHODS
    // =========================================================================

    /**
     * Log an event.
     *
     * @param string $action Event action.
     * @param string $status Event status (success, failure, warning, info).
     * @param array  $context Additional context.
     */
    public static function log($action, $status = 'info', $context = []) {
        $logs = get_option('lsm_activity_log', []);

        // Get current user if available
        $current_user = wp_get_current_user();
        
        $entry = [
            'action'    => $action,
            'status'    => $status,
            'context'   => $context,
            'timestamp' => current_time('mysql'),
            'user_ip'   => self::get_client_ip(),
            'user_id'   => $current_user->ID ?? 0,
            'username'  => $current_user->user_login ?? null,
        ];

        array_unshift($logs, $entry);

        // Keep only last N entries
        $logs = array_slice($logs, 0, self::MAX_ENTRIES);

        update_option('lsm_activity_log', $logs, false);
    }

    /**
     * Get activity log.
     *
     * @param int $limit Number of entries to return.
     * @param string|null $action_filter Filter by action type.
     * @return array
     */
    public static function get_log($limit = 50, $action_filter = null) {
        $logs = get_option('lsm_activity_log', []);
        
        if ($action_filter) {
            $logs = array_filter($logs, function($log) use ($action_filter) {
                return $log['action'] === $action_filter;
            });
        }
        
        return array_values(array_slice($logs, 0, $limit));
    }

    /**
     * Get activity statistics.
     *
     * @return array
     */
    public static function get_stats() {
        $logs = get_option('lsm_activity_log', []);
        
        $stats = [
            'total' => count($logs),
            'by_action' => [],
            'by_status' => [
                'success' => 0,
                'info' => 0,
                'warning' => 0,
                'error' => 0,
            ],
            'last_activity' => null,
        ];
        
        foreach ($logs as $log) {
            // Count by action
            $action = $log['action'];
            if (!isset($stats['by_action'][$action])) {
                $stats['by_action'][$action] = 0;
            }
            $stats['by_action'][$action]++;
            
            // Count by status
            $status = $log['status'];
            if (isset($stats['by_status'][$status])) {
                $stats['by_status'][$status]++;
            }
        }
        
        if (!empty($logs)) {
            $stats['last_activity'] = $logs[0]['timestamp'];
        }
        
        return $stats;
    }

    /**
     * Clear activity log.
     */
    public static function clear_log() {
        update_option('lsm_activity_log', []);
    }

    /**
     * Get client IP address.
     *
     * @return string
     */
    private static function get_client_ip() {
        $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Handle comma-separated IPs
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                return sanitize_text_field($ip);
            }
        }
        
        return 'unknown';
    }
}

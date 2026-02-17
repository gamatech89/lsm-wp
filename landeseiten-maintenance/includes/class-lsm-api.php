<?php
/**
 * REST API endpoints for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM API class.
 */
class LSM_API {

    /**
     * API namespace.
     */
    const NAMESPACE = 'lsm/v1';

    /**
     * Register routes.
     */
    public function register_routes() {
        // Public info endpoint
        register_rest_route(self::NAMESPACE, '/info', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_info'],
            'permission_callback' => '__return_true',
        ]);

        // Authenticated endpoints
        register_rest_route(self::NAMESPACE, '/health', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_health'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/sso/token', [
            'methods'             => 'POST',
            'callback'            => [$this, 'generate_sso_token'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/cache/clear', [
            'methods'             => 'POST',
            'callback'            => [$this, 'clear_cache'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/database/optimize', [
            'methods'             => 'POST',
            'callback'            => [$this, 'optimize_database'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/database/cleanup', [
            'methods'             => 'POST',
            'callback'            => [$this, 'cleanup_database'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/database/stats', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_database_stats'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/rewrite/flush', [
            'methods'             => 'POST',
            'callback'            => [$this, 'flush_rewrite'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/updates', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_updates'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/plugins', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_plugins'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/themes', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_themes'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Theme activation
        register_rest_route(self::NAMESPACE, '/themes/activate', [
            'methods'             => 'POST',
            'callback'            => [$this, 'activate_theme'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/transients/clear', [
            'methods'             => 'POST',
            'callback'            => [$this, 'clear_transients'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/updates/plugins', [
            'methods'             => 'POST',
            'callback'            => [$this, 'update_plugins'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Single plugin update
        register_rest_route(self::NAMESPACE, '/plugins/update', [
            'methods'             => 'POST',
            'callback'            => [$this, 'update_single_plugin'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Plugin activation
        register_rest_route(self::NAMESPACE, '/plugins/activate', [
            'methods'             => 'POST',
            'callback'            => [$this, 'activate_plugin'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Plugin deactivation
        register_rest_route(self::NAMESPACE, '/plugins/deactivate', [
            'methods'             => 'POST',
            'callback'            => [$this, 'deactivate_plugin'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Plugin deletion
        register_rest_route(self::NAMESPACE, '/plugins/delete', [
            'methods'             => 'POST',
            'callback'            => [$this, 'delete_plugin'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/updates/core', [
            'methods'             => 'POST',
            'callback'            => [$this, 'update_core'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/maintenance/enable', [
            'methods'             => 'POST',
            'callback'            => [$this, 'enable_maintenance'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/maintenance/disable', [
            'methods'             => 'POST',
            'callback'            => [$this, 'disable_maintenance'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/recovery/disable-plugins', [
            'methods'             => 'POST',
            'callback'            => [$this, 'disable_plugins'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/recovery/restore-plugins', [
            'methods'             => 'POST',
            'callback'            => [$this, 'restore_plugins'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/recovery/emergency', [
            'methods'             => 'POST',
            'callback'            => [$this, 'emergency_recovery'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Backup endpoints
        register_rest_route(self::NAMESPACE, '/backup/create', [
            'methods'             => 'POST',
            'callback'            => [$this, 'create_backup'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/backup/list', [
            'methods'             => 'GET',
            'callback'            => [$this, 'list_backups'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [$this, 'download_backup'],
            'permission_callback' => '__return_true', // Uses token auth
        ]);

        register_rest_route(self::NAMESPACE, '/backup/restore', [
            'methods'             => 'POST',
            'callback'            => [$this, 'restore_backup'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/backup/delete', [
            'methods'             => 'POST',
            'callback'            => [$this, 'delete_backup'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // PHP Error endpoints
        register_rest_route(self::NAMESPACE, '/errors/list', [
            'methods'             => 'GET',
            'callback'            => [$this, 'list_errors'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/errors/stats', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_error_stats'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/errors/resolve', [
            'methods'             => 'POST',
            'callback'            => [$this, 'resolve_error'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/errors/delete', [
            'methods'             => 'POST',
            'callback'            => [$this, 'delete_error'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/errors/clear', [
            'methods'             => 'POST',
            'callback'            => [$this, 'clear_errors'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // =================================================================
        // Activity Log Endpoints
        // =================================================================
        register_rest_route(self::NAMESPACE, '/activity/list', [
            'methods'             => 'GET',
            'callback'            => [$this, 'list_activity'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/activity/stats', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_activity_stats'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/activity/clear', [
            'methods'             => 'POST',
            'callback'            => [$this, 'clear_activity'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Site Info & Stats
        register_rest_route(self::NAMESPACE, '/site/info', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_site_info'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Users Management
        register_rest_route(self::NAMESPACE, '/users/list', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_users'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Security Settings
        register_rest_route(self::NAMESPACE, '/security/settings', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_security_settings'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        register_rest_route(self::NAMESPACE, '/security/settings', [
            'methods'             => 'POST',
            'callback'            => [$this, 'update_security_settings'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Security Headers Check
        register_rest_route(self::NAMESPACE, '/security/headers', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_security_headers'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Security Header Snippets Generator
        register_rest_route(self::NAMESPACE, '/security/headers/snippets', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_security_header_snippets'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Security Scan - Full scan
        register_rest_route(self::NAMESPACE, '/security/scan', [
            'methods'             => 'POST',
            'callback'            => [$this, 'run_security_scan'],
            'permission_callback' => [$this, 'authenticate'],
        ]);

        // Security Scan - Quick scan (lightweight)
        register_rest_route(self::NAMESPACE, '/security/scan/quick', [
            'methods'             => 'GET',
            'callback'            => [$this, 'run_quick_scan'],
            'permission_callback' => [$this, 'authenticate'],
        ]);
    }


    /**
     * Authenticate API request.
     *
     * @param WP_REST_Request $request Request object.
     * @return bool
     */
    public function authenticate($request) {
        $api_key = Landeseiten_Maintenance::get_setting('api_key');
        if (empty($api_key)) {
            return false;
        }

        // Check query param
        $key = $request->get_param('key');
        if ($key === $api_key) {
            return true;
        }

        // Check header
        $auth_header = $request->get_header('X-LSM-Key');
        if ($auth_header === $api_key) {
            return true;
        }

        // Check Authorization header
        $auth = $request->get_header('Authorization');
        if ($auth && preg_match('/^Bearer\s+(.+)$/i', $auth, $matches)) {
            if ($matches[1] === $api_key) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get plugin info.
     */
    public function get_info() {
        return rest_ensure_response([
            'success' => true,
            'data'    => [
                'plugin'  => 'Landeseiten Maintenance',
                'version' => LSM_VERSION,
                'status'  => 'active',
            ],
        ]);
    }

    /**
     * Get health data.
     */
    public function get_health() {
        $health = new LSM_Health();
        return rest_ensure_response([
            'success' => true,
            'data'    => $health->get_health_data(),
        ]);
    }

    /**
     * Generate SSO token.
     *
     * @param WP_REST_Request $request Request.
     */
    public function generate_sso_token($request) {
        $auth = new LSM_Auth();
        $token_data = $auth->generate_login_token(
            $request->get_param('role') ?? 'administrator',
            $request->get_param('expires_in') ?? 300,
            $request->get_param('bind_ip'),
            $request->get_param('dashboard_user')
        );

        return rest_ensure_response([
            'success'   => true,
            'login_url' => $token_data['login_url'],
            'expires'   => $token_data['expires'],
        ]);
    }

    /**
     * Clear cache.
     */
    public function clear_cache() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::clear_cache(),
        ]);
    }

    /**
     * Optimize database.
     */
    public function optimize_database() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::optimize_database(),
        ]);
    }

    /**
     * Cleanup database - removes revisions, transients, drafts, spam, etc.
     *
     * @param WP_REST_Request $request Request with cleanup options.
     */
    public function cleanup_database($request) {
        $options = [
            'revisions'   => $request->get_param('revisions') ?? true,
            'transients'  => $request->get_param('transients') ?? true,
            'drafts'      => $request->get_param('drafts') ?? true,
            'spam'        => $request->get_param('spam') ?? true,
            'trash'       => $request->get_param('trash') ?? true,
            'orphan_meta' => $request->get_param('orphan_meta') ?? true,
        ];

        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::cleanup_database($options),
        ]);
    }

    /**
     * Get database statistics for cleanup preview.
     */
    public function get_database_stats() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::get_database_stats(),
        ]);
    }

    /**
     * Flush rewrite rules.
     */
    public function flush_rewrite() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::flush_rewrite(),
        ]);
    }

    /**
     * Get updates.
     */
    public function get_updates() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::get_updates(),
        ]);
    }

    /**
     * Get all installed plugins with enhanced details.
     */
    public function get_plugins() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        // Refresh update cache so update_available is accurate
        wp_set_current_user(1);
        wp_update_plugins();

        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', []);
        $auto_update_plugins = get_option('auto_update_plugins', []);
        $plugin_updates = get_plugin_updates();
        
        // Get cached plugin info from WordPress.org
        $plugin_info_cache = get_transient('lsm_plugin_info_cache') ?: [];
        
        $plugins = [];
        
        foreach ($all_plugins as $plugin_file => $plugin_data) {
            // Extract slug from plugin file path
            $slug = dirname($plugin_file);
            if ($slug === '.') {
                $slug = basename($plugin_file, '.php');
            }
            
            // Get update info
            $update_available = isset($plugin_updates[$plugin_file]);
            $new_version = $update_available ? $plugin_updates[$plugin_file]->update->new_version : null;
            
            // Get icon from WordPress.org (cached)
            $icon = null;
            if (!isset($plugin_info_cache[$slug])) {
                $api_response = wp_remote_get(
                    "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug={$slug}",
                    ['timeout' => 5]
                );
                if (!is_wp_error($api_response)) {
                    $body = json_decode(wp_remote_retrieve_body($api_response), true);
                    if (!empty($body) && !isset($body['error'])) {
                        $plugin_info_cache[$slug] = [
                            'icon' => $body['icons']['1x'] ?? $body['icons']['svg'] ?? $body['icons']['default'] ?? null,
                            'rating' => $body['rating'] ?? null,
                            'num_ratings' => $body['num_ratings'] ?? 0,
                            'active_installs' => $body['active_installs'] ?? null,
                            'last_updated' => $body['last_updated'] ?? null,
                        ];
                    }
                }
            }
            
            $cached_info = $plugin_info_cache[$slug] ?? [];
            
            $plugins[] = [
                'slug'             => $slug,
                'plugin'           => $plugin_file,
                'name'             => $plugin_data['Name'],
                'version'          => $plugin_data['Version'],
                'new_version'      => $new_version,
                'update_available' => $update_available,
                'author'           => strip_tags($plugin_data['Author']),
                'author_url'       => $plugin_data['AuthorURI'] ?? '',
                'description'      => $plugin_data['Description'],
                'active'           => in_array($plugin_file, $active_plugins, true),
                'auto_update'      => in_array($plugin_file, $auto_update_plugins, true),
                'url'              => $plugin_data['PluginURI'] ?? '',
                'requires_wp'      => $plugin_data['RequiresWP'] ?? null,
                'requires_php'     => $plugin_data['RequiresPHP'] ?? null,
                'icon'             => $cached_info['icon'] ?? null,
                'rating'           => $cached_info['rating'] ?? null,
                'active_installs'  => $cached_info['active_installs'] ?? null,
                'last_updated'     => $cached_info['last_updated'] ?? null,
            ];
        }
        
        // Cache plugin info for 1 hour
        set_transient('lsm_plugin_info_cache', $plugin_info_cache, HOUR_IN_SECONDS);
        
        return rest_ensure_response([
            'success' => true,
            'data'    => $plugins,
        ]);
    }

    /**
     * Get all installed themes with details.
     */
    public function get_themes() {
        if (!function_exists('wp_get_themes')) {
            require_once ABSPATH . 'wp-includes/theme.php';
        }
        if (!function_exists('get_theme_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $all_themes = wp_get_themes();
        $active_theme = wp_get_theme();
        $theme_updates = get_theme_updates();
        
        $themes = [];
        
        foreach ($all_themes as $stylesheet => $theme) {
            $update_available = isset($theme_updates[$stylesheet]);
            $new_version = $update_available ? $theme_updates[$stylesheet]->update['new_version'] : null;
            
            $themes[] = [
                'slug'             => $stylesheet,
                'name'             => $theme->get('Name'),
                'version'          => $theme->get('Version'),
                'new_version'      => $new_version,
                'update_available' => $update_available,
                'author'           => $theme->get('Author'),
                'author_url'       => $theme->get('AuthorURI'),
                'description'      => $theme->get('Description'),
                'active'           => ($active_theme->get_stylesheet() === $stylesheet),
                'template'         => $theme->get('Template'),
                'screenshot'       => $theme->get_screenshot(),
                'requires_wp'      => $theme->get('RequiresWP'),
                'requires_php'     => $theme->get('RequiresPHP'),
            ];
        }
        
        return rest_ensure_response([
            'success' => true,
            'data'    => $themes,
        ]);
    }

    /**
     * Activate a specific theme.
     *
     * @param WP_REST_Request $request Request.
     */
    public function activate_theme($request) {
        $slug = $request->get_param('slug');
        
        if (empty($slug)) {
            return new WP_Error('missing_slug', 'Theme slug is required', ['status' => 400]);
        }

        if (!function_exists('wp_get_themes')) {
            require_once ABSPATH . 'wp-includes/theme.php';
        }

        // Check if theme exists
        $theme = wp_get_theme($slug);
        if (!$theme->exists()) {
            return new WP_Error('theme_not_found', 'Theme not found', ['status' => 404]);
        }

        // Activate the theme
        switch_theme($slug);

        // Clear any caches
        wp_cache_flush();

        return rest_ensure_response([
            'success' => true,
            'message' => 'Theme activated successfully',
            'theme'   => $slug,
        ]);
    }

    /**
     * Clear transients from the database.
     */
    public function clear_transients(WP_REST_Request $request) {
        global $wpdb;
        
        $all = $request->get_param('all') === true || $request->get_param('all') === 'true';
        
        if ($all) {
            // Clear all transients
            $count = $wpdb->query(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' OR option_name LIKE '_site_transient_%'"
            );
        } else {
            // Clear only expired transients
            $time = time();
            $expired_transients = $wpdb->get_col(
                $wpdb->prepare(
                    "SELECT option_name FROM {$wpdb->options} 
                     WHERE option_name LIKE '_transient_timeout_%' 
                     AND option_value < %d",
                    $time
                )
            );
            
            $count = 0;
            foreach ($expired_transients as $transient) {
                $transient_name = str_replace('_transient_timeout_', '', $transient);
                delete_transient($transient_name);
                $count++;
            }
        }
        
        LSM_Logger::log('transients_cleared', 'success', [
            'count' => $count,
            'all'   => $all,
        ]);
        
        return rest_ensure_response([
            'success' => true,
            'data'    => [
                'cleared' => $count,
                'all'     => $all,
                'message' => sprintf(__('Cleared %d transient(s).', 'landeseiten-maintenance'), $count),
            ],
        ]);
    }

    /**
     * Update plugins.
     */
    public function update_plugins() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::update_all_plugins(),
        ]);
    }

    /**
     * Update a single plugin.
     *
     * @param WP_REST_Request $request Request.
     */
    public function update_single_plugin($request) {
        $plugin = $request->get_param('plugin');
        $slug = $request->get_param('slug');
        
        if (empty($plugin) && empty($slug)) {
            return new WP_Error('missing_plugin', 'Plugin file path or slug is required', ['status' => 400]);
        }

        // Set admin user context — required for Plugin_Upgrader filesystem operations
        wp_set_current_user(1);

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        // Find plugin by slug if only slug provided
        if (empty($plugin) && !empty($slug)) {
            $all_plugins = get_plugins();
            foreach ($all_plugins as $file => $data) {
                $plugin_slug = dirname($file);
                if ($plugin_slug === '.' ) {
                    $plugin_slug = basename($file, '.php');
                }
                if ($plugin_slug === $slug) {
                    $plugin = $file;
                    break;
                }
            }
        }

        if (empty($plugin)) {
            return new WP_Error('plugin_not_found', 'Plugin not found', ['status' => 404]);
        }

        // Check if update is available
        wp_update_plugins(); // Refresh update cache first
        $updates = get_plugin_updates();
        
        if (!isset($updates[$plugin])) {
            return rest_ensure_response([
                'success' => false,
                'message' => 'No update available for this plugin',
                'plugin'  => $plugin,
            ]);
        }

        // Get the update info
        $update_info = $updates[$plugin];
        $new_version = $update_info->update->new_version ?? 'unknown';

        // Perform the update — use upgrade() for single plugin (not bulk_upgrade which can trigger auto-updates on other plugins)
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/file.php';
        
        // Disable auto-updates during this operation to prevent WordPress from updating other plugins
        add_filter('auto_update_plugin', '__return_false', 999);
        add_filter('auto_update_theme', '__return_false', 999);
        add_filter('auto_update_core', '__return_false', 999);
        
        $skin = new Automatic_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader($skin);
        
        $result = $upgrader->upgrade($plugin);
        
        // Re-enable auto-updates after the operation
        remove_filter('auto_update_plugin', '__return_false', 999);
        remove_filter('auto_update_theme', '__return_false', 999);
        remove_filter('auto_update_core', '__return_false', 999);

        if (is_wp_error($result)) {
            return new WP_Error('update_failed', $result->get_error_message(), ['status' => 500]);
        }

        if ($result === false) {
            $error_msg = 'Update failed';
            // Include skin errors for better debugging
            $skin_errors = $skin->get_errors();
            if ($skin_errors && $skin_errors->has_errors()) {
                $error_msg .= ' — ' . implode('; ', $skin_errors->get_error_messages());
            }
            return new WP_Error('update_failed', $error_msg, ['status' => 500]);
        }


        // Clear update cache
        wp_clean_plugins_cache();

        return rest_ensure_response([
            'success' => true,
            'message' => "Plugin updated to version {$new_version}",
            'plugin'  => $plugin,
            'new_version' => $new_version,
        ]);
    }


    /**
     * Activate a plugin.
     *
     * @param WP_REST_Request $request Request.
     */
    public function activate_plugin($request) {
        $plugin = $request->get_param('plugin');
        $slug = $request->get_param('slug');
        
        if (empty($plugin) && empty($slug)) {
            return new WP_Error('missing_plugin', 'Plugin file path or slug is required', ['status' => 400]);
        }

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        // Find plugin by slug if only slug provided
        if (empty($plugin) && !empty($slug)) {
            $all_plugins = get_plugins();
            foreach ($all_plugins as $file => $data) {
                $plugin_slug = dirname($file);
                if ($plugin_slug === '.' ) {
                    $plugin_slug = basename($file, '.php');
                }
                if ($plugin_slug === $slug) {
                    $plugin = $file;
                    break;
                }
            }
        }

        if (empty($plugin)) {
            return new WP_Error('plugin_not_found', 'Plugin not found', ['status' => 404]);
        }

        // Check if already active
        if (is_plugin_active($plugin)) {
            return rest_ensure_response([
                'success' => true,
                'message' => 'Plugin is already active',
                'plugin'  => $plugin,
            ]);
        }

        // Activate
        $result = activate_plugin($plugin);

        if (is_wp_error($result)) {
            return new WP_Error('activation_failed', $result->get_error_message(), ['status' => 500]);
        }

        return rest_ensure_response([
            'success' => true,
            'message' => 'Plugin activated successfully',
            'plugin'  => $plugin,
        ]);
    }

    /**
     * Deactivate a plugin.
     *
     * @param WP_REST_Request $request Request.
     */
    public function deactivate_plugin($request) {
        $plugin = $request->get_param('plugin');
        $slug = $request->get_param('slug');
        
        if (empty($plugin) && empty($slug)) {
            return new WP_Error('missing_plugin', 'Plugin file path or slug is required', ['status' => 400]);
        }

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        // Find plugin by slug if only slug provided
        if (empty($plugin) && !empty($slug)) {
            $all_plugins = get_plugins();
            foreach ($all_plugins as $file => $data) {
                $plugin_slug = dirname($file);
                if ($plugin_slug === '.' ) {
                    $plugin_slug = basename($file, '.php');
                }
                if ($plugin_slug === $slug) {
                    $plugin = $file;
                    break;
                }
            }
        }

        if (empty($plugin)) {
            return new WP_Error('plugin_not_found', 'Plugin not found', ['status' => 404]);
        }

        // PROTECT: Cannot deactivate Landeseiten Maintenance plugin
        if (strpos($plugin, 'landeseiten-maintenance') !== false) {
            return new WP_Error(
                'protected_plugin', 
                'Cannot deactivate Landeseiten Maintenance - this would break the remote connection',
                ['status' => 403]
            );
        }

        // Check if already inactive
        if (!is_plugin_active($plugin)) {
            return rest_ensure_response([
                'success' => true,
                'message' => 'Plugin is already inactive',
                'plugin'  => $plugin,
            ]);
        }

        // Deactivate
        deactivate_plugins($plugin);

        return rest_ensure_response([
            'success' => true,
            'message' => 'Plugin deactivated successfully',
            'plugin'  => $plugin,
        ]);
    }

    /**
     * Delete a plugin.
     *
     * @param WP_REST_Request $request Request.
     */
    public function delete_plugin($request) {
        $plugin = $request->get_param('plugin');
        $slug = $request->get_param('slug');
        
        if (empty($plugin) && empty($slug)) {
            return new WP_Error('missing_plugin', 'Plugin file path or slug is required', ['status' => 400]);
        }

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('delete_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        // Find plugin by slug if only slug provided
        if (empty($plugin) && !empty($slug)) {
            $all_plugins = get_plugins();
            foreach ($all_plugins as $file => $data) {
                $plugin_slug = dirname($file);
                if ($plugin_slug === '.' ) {
                    $plugin_slug = basename($file, '.php');
                }
                if ($plugin_slug === $slug) {
                    $plugin = $file;
                    break;
                }
            }
        }

        if (empty($plugin)) {
            return new WP_Error('plugin_not_found', 'Plugin not found', ['status' => 404]);
        }

        // PROTECT: Cannot delete Landeseiten Maintenance plugin
        if (strpos($plugin, 'landeseiten-maintenance') !== false) {
            return new WP_Error(
                'protected_plugin', 
                'Cannot delete Landeseiten Maintenance - this would break the remote connection',
                ['status' => 403]
            );
        }

        // Plugin must be deactivated first
        if (is_plugin_active($plugin)) {
            deactivate_plugins($plugin);
        }

        // Delete the plugin
        $deleted = delete_plugins([$plugin]);

        if (is_wp_error($deleted)) {
            return new WP_Error(
                'delete_failed',
                $deleted->get_error_message(),
                ['status' => 500]
            );
        }

        return rest_ensure_response([
            'success' => true,
            'message' => 'Plugin deleted successfully',
            'plugin'  => $plugin,
        ]);
    }

    /**
     * Update core.
     */
    public function update_core() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Actions::update_core(),
        ]);
    }

    /**
     * Enable maintenance mode.
     */
    public function enable_maintenance() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Maintenance_Mode::enable(),
        ]);
    }

    /**
     * Disable maintenance mode.
     */
    public function disable_maintenance() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Maintenance_Mode::disable(),
        ]);
    }

    /**
     * Disable all plugins.
     */
    public function disable_plugins() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Recovery::disable_all_plugins(),
        ]);
    }

    /**
     * Restore plugins.
     */
    public function restore_plugins() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Recovery::restore_plugins(),
        ]);
    }

    /**
     * Emergency recovery.
     */
    public function emergency_recovery() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Recovery::emergency_recovery(),
        ]);
    }

    // =========================================================================
    // BACKUP METHODS
    // =========================================================================

    /**
     * Create a backup.
     *
     * @param WP_REST_Request $request Request.
     */
    public function create_backup($request) {
        $options = [
            'includes_database' => $request->get_param('includes_database') ?? true,
            'includes_files'    => $request->get_param('includes_files') ?? true,
            'includes_uploads'  => $request->get_param('includes_uploads') ?? true,
        ];

        $result = LSM_Backup::create_backup($options);

        return rest_ensure_response([
            'success' => $result['success'],
            'data'    => $result,
        ]);
    }

    /**
     * List available backups.
     */
    public function list_backups() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Backup::list_backups(),
        ]);
    }

    /**
     * Download a backup.
     *
     * @param WP_REST_Request $request Request.
     */
    public function download_backup($request) {
        $token = $request->get_param('token');
        
        if (empty($token)) {
            return new WP_Error('missing_token', 'Download token is required', ['status' => 400]);
        }

        $backup_path = LSM_Backup::get_backup_by_token($token);
        
        if (!$backup_path) {
            return new WP_Error('invalid_token', 'Invalid or expired download token', ['status' => 403]);
        }

        // Serve the file
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . basename($backup_path) . '"');
        header('Content-Length: ' . filesize($backup_path));
        header('Cache-Control: no-cache, must-revalidate');

        readfile($backup_path);
        exit;
    }

    /**
     * Restore a backup.
     *
     * @param WP_REST_Request $request Request.
     */
    public function restore_backup($request) {
        $filename = $request->get_param('backup_file');
        
        if (empty($filename)) {
            return new WP_Error('missing_filename', 'Backup filename is required', ['status' => 400]);
        }

        $result = LSM_Backup::restore_backup($filename);

        return rest_ensure_response([
            'success' => $result['success'],
            'data'    => $result,
        ]);
    }

    /**
     * Delete a backup.
     *
     * @param WP_REST_Request $request Request.
     */
    public function delete_backup($request) {
        $filename = $request->get_param('backup_file');
        
        if (empty($filename)) {
            return new WP_Error('missing_filename', 'Backup filename is required', ['status' => 400]);
        }

        $success = LSM_Backup::delete_backup($filename);

        return rest_ensure_response([
            'success' => $success,
            'message' => $success ? 'Backup deleted' : 'Failed to delete backup',
        ]);
    }

    // =========================================================================
    // PHP ERROR METHODS
    // =========================================================================

    /**
     * List PHP errors.
     *
     * @param WP_REST_Request $request Request.
     */
    public function list_errors($request) {
        $filters = [
            'type'       => $request->get_param('type'),
            'unresolved' => $request->get_param('unresolved'),
            'search'     => $request->get_param('search'),
        ];

        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Php_Errors::get_errors($filters),
        ]);
    }

    /**
     * Get error statistics.
     */
    public function get_error_stats() {
        return rest_ensure_response([
            'success' => true,
            'data'    => LSM_Php_Errors::get_stats(),
        ]);
    }

    /**
     * Resolve an error.
     *
     * @param WP_REST_Request $request Request.
     */
    public function resolve_error($request) {
        $hash = $request->get_param('hash');
        
        if (empty($hash)) {
            return new WP_Error('missing_hash', 'Error hash is required', ['status' => 400]);
        }

        $success = LSM_Php_Errors::resolve_error($hash);

        return rest_ensure_response([
            'success' => $success,
            'message' => $success ? 'Error resolved' : 'Error not found',
        ]);
    }

    /**
     * Delete an error.
     *
     * @param WP_REST_Request $request Request.
     */
    public function delete_error($request) {
        $hash = $request->get_param('hash');
        
        if (empty($hash)) {
            return new WP_Error('missing_hash', 'Error hash is required', ['status' => 400]);
        }

        $success = LSM_Php_Errors::delete_error($hash);

        return rest_ensure_response([
            'success' => $success,
            'message' => $success ? 'Error deleted' : 'Error not found',
        ]);
    }

    /**
     * Clear all errors.
     */
    public function clear_errors() {
        LSM_Php_Errors::clear_errors();

        return rest_ensure_response([
            'success' => true,
            'message' => 'All errors cleared',
        ]);
    }

    // =========================================================================
    // Activity Log Callbacks
    // =========================================================================

    /**
     * List activity log entries.
     *
     * @param WP_REST_Request $request Request object.
     * @return WP_REST_Response
     */
    public function list_activity($request) {
        $limit = $request->get_param('limit') ?? 50;
        $action = $request->get_param('action');

        $activity = LSM_Logger::get_log((int) $limit, $action);

        return rest_ensure_response([
            'success' => true,
            'activity' => $activity,
            'total' => count($activity),
        ]);
    }

    /**
     * Get activity statistics.
     *
     * @return WP_REST_Response
     */
    public function get_activity_stats() {
        return rest_ensure_response([
            'success' => true,
            'stats' => LSM_Logger::get_stats(),
        ]);
    }

    /**
     * Clear activity log.
     *
     * @return WP_REST_Response
     */
    public function clear_activity() {
        LSM_Logger::clear_log();

        return rest_ensure_response([
            'success' => true,
            'message' => 'Activity log cleared',
        ]);
    }

    // =========================================================================
    // SITE INFO & STATS
    // =========================================================================

    /**
     * Get comprehensive site information.
     *
     * @return WP_REST_Response
     */
    public function get_site_info() {
        global $wpdb;

        // User counts by role
        $user_counts = count_users();
        
        // Content counts
        $post_counts = wp_count_posts('post');
        $page_counts = wp_count_posts('page');
        $media_count = wp_count_attachments();
        
        // Comment counts
        $comment_counts = wp_count_comments();
        
        // Get settings related to security
        $comments_enabled = get_option('default_comment_status') === 'open';
        $registration_enabled = get_option('users_can_register') == 1;
        
        // Check for XML-RPC status (if our filter is active)
        $xmlrpc_enabled = get_option('lsm_xmlrpc_enabled', true);
        
        // Check for REST API guest access
        $rest_api_public = get_option('lsm_rest_api_public', true);

        return rest_ensure_response([
            'success' => true,
            'data' => [
                'users' => [
                    'total' => $user_counts['total_users'],
                    'by_role' => $user_counts['avail_roles'],
                ],
                'content' => [
                    'posts' => [
                        'published' => (int)$post_counts->publish,
                        'draft' => (int)$post_counts->draft,
                        'trash' => (int)$post_counts->trash,
                        'total' => array_sum((array)$post_counts),
                    ],
                    'pages' => [
                        'published' => (int)$page_counts->publish,
                        'draft' => (int)$page_counts->draft,
                        'total' => array_sum((array)$page_counts),
                    ],
                    'media' => array_sum((array)$media_count),
                ],
                'comments' => [
                    'total' => (int)$comment_counts->total_comments,
                    'approved' => (int)$comment_counts->approved,
                    'pending' => (int)$comment_counts->moderated,
                    'spam' => (int)$comment_counts->spam,
                    'trash' => (int)$comment_counts->trash,
                ],
                'settings' => [
                    'comments_enabled' => $comments_enabled,
                    'registration_enabled' => $registration_enabled,
                    'xmlrpc_enabled' => $xmlrpc_enabled,
                    'rest_api_public' => $rest_api_public,
                ],
            ],
        ]);
    }

    /**
     * Get all users with their roles.
     *
     * @return WP_REST_Response
     */
    public function get_users() {
        $users = get_users([
            'orderby' => 'registered',
            'order' => 'DESC',
        ]);

        $user_list = [];
        foreach ($users as $user) {
            $user_list[] = [
                'id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'display_name' => $user->display_name,
                'roles' => $user->roles,
                'registered' => $user->user_registered,
                'last_login' => get_user_meta($user->ID, 'last_login', true) ?: null,
            ];
        }

        return rest_ensure_response([
            'success' => true,
            'data' => $user_list,
        ]);
    }

    // =========================================================================
    // SECURITY SETTINGS
    // =========================================================================

    /**
     * Get current security settings.
     *
     * @return WP_REST_Response
     */
    public function get_security_settings() {
        // Check if file editing is disabled either by constant OR our plugin option
        $file_editing_disabled = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
        if (!$file_editing_disabled) {
            $file_editing_disabled = get_option('lsm_file_editing_disabled', false);
        }

        // Check if debug mode is enabled
        $debug_enabled = defined('WP_DEBUG') && WP_DEBUG;

        return rest_ensure_response([
            'success' => true,
            'data' => [
                'comments_enabled' => get_option('default_comment_status') === 'open',
                'registration_enabled' => get_option('users_can_register') == 1,
                'xmlrpc_enabled' => (bool) get_option('lsm_xmlrpc_enabled', true),
                'rest_api_public' => (bool) get_option('lsm_rest_api_public', true),
                'file_editing_disabled' => (bool) $file_editing_disabled,
                'debug_enabled' => (bool) $debug_enabled,
                'security_headers_enabled' => (bool) get_option('lsm_security_headers_enabled', false),
            ],
        ]);
    }

    /**
     * Update security settings.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function update_security_settings($request) {
        $changes = [];

        // Comments
        if ($request->has_param('comments_enabled')) {
            $enabled = $request->get_param('comments_enabled');
            update_option('default_comment_status', $enabled ? 'open' : 'closed');
            $changes['comments_enabled'] = $enabled;
        }

        // User Registration
        if ($request->has_param('registration_enabled')) {
            $enabled = $request->get_param('registration_enabled');
            update_option('users_can_register', $enabled ? 1 : 0);
            $changes['registration_enabled'] = $enabled;
        }

        // XML-RPC (we store our own option and apply filter)
        if ($request->has_param('xmlrpc_enabled')) {
            $enabled = (bool) $request->get_param('xmlrpc_enabled');
            update_option('lsm_xmlrpc_enabled', $enabled);
            $changes['xmlrpc_enabled'] = $enabled;
        }

        // REST API Public Access
        if ($request->has_param('rest_api_public')) {
            $enabled = (bool) $request->get_param('rest_api_public');
            update_option('lsm_rest_api_public', $enabled);
            $changes['rest_api_public'] = $enabled;
        }

        // File Editing Disabled
        if ($request->has_param('file_editing_disabled')) {
            $disabled = (bool) $request->get_param('file_editing_disabled');
            update_option('lsm_file_editing_disabled', $disabled);
            $changes['file_editing_disabled'] = $disabled;
        }

        // Debug Mode (note: this requires wp-config.php modification which we can't do automatically)
        // We'll store the preference and show a notice to the user
        if ($request->has_param('debug_enabled')) {
            $enabled = (bool) $request->get_param('debug_enabled');
            update_option('lsm_debug_preference', $enabled);
            $changes['debug_enabled'] = $enabled;
            // Note: Actual WP_DEBUG constant can only be changed in wp-config.php
        }

        // Security Headers Enabled
        if ($request->has_param('security_headers_enabled')) {
            $enabled = (bool) $request->get_param('security_headers_enabled');
            update_option('lsm_security_headers_enabled', $enabled);
            $changes['security_headers_enabled'] = $enabled;
        }

        // Log the action
        if (!empty($changes)) {
            LSM_Logger::log('security_settings_changed', 'info', [
                'changes' => $changes,
            ]);
        }

        return rest_ensure_response([
            'success' => true,
            'message' => 'Security settings updated',
            'changes' => $changes,
        ]);
    }

    /**
     * Get security headers status.
     * 
     * Makes a request to the site's homepage and checks which security headers are present.
     *
     * @return WP_REST_Response
     */
    public function get_security_headers() {
        $site_url = get_site_url();
        
        // Make a HEAD request to the homepage to get headers
        $response = wp_remote_head($site_url, [
            'timeout' => 10,
            'sslverify' => false,
        ]);

        if (is_wp_error($response)) {
            return rest_ensure_response([
                'success' => false,
                'message' => 'Could not fetch headers: ' . $response->get_error_message(),
                'data' => null,
            ]);
        }

        $headers = wp_remote_retrieve_headers($response);
        $headers_array = $headers->getAll();
        
        // Normalize header names to lowercase for easier checking
        $headers_lower = [];
        foreach ($headers_array as $key => $value) {
            $headers_lower[strtolower($key)] = $value;
        }

        // Check for important security headers
        $security_headers = [
            'x-frame-options' => [
                'name' => 'X-Frame-Options',
                'description' => 'Prevents clickjacking attacks by blocking framing',
                'recommendation' => 'DENY or SAMEORIGIN',
                'present' => isset($headers_lower['x-frame-options']),
                'value' => $headers_lower['x-frame-options'] ?? null,
            ],
            'x-content-type-options' => [
                'name' => 'X-Content-Type-Options',
                'description' => 'Prevents MIME type sniffing attacks',
                'recommendation' => 'nosniff',
                'present' => isset($headers_lower['x-content-type-options']),
                'value' => $headers_lower['x-content-type-options'] ?? null,
            ],
            'x-xss-protection' => [
                'name' => 'X-XSS-Protection',
                'description' => 'Enables browser XSS filtering (legacy)',
                'recommendation' => '1; mode=block',
                'present' => isset($headers_lower['x-xss-protection']),
                'value' => $headers_lower['x-xss-protection'] ?? null,
            ],
            'strict-transport-security' => [
                'name' => 'Strict-Transport-Security',
                'description' => 'Enforces HTTPS connections (HSTS)',
                'recommendation' => 'max-age=31536000; includeSubDomains',
                'present' => isset($headers_lower['strict-transport-security']),
                'value' => $headers_lower['strict-transport-security'] ?? null,
            ],
            // Note: Content-Security-Policy removed - too complex to automate per site
            'referrer-policy' => [
                'name' => 'Referrer-Policy',
                'description' => 'Controls referrer information sent',
                'recommendation' => 'strict-origin-when-cross-origin',
                'present' => isset($headers_lower['referrer-policy']),
                'value' => $headers_lower['referrer-policy'] ?? null,
            ],
            'permissions-policy' => [
                'name' => 'Permissions-Policy',
                'description' => 'Controls browser features and APIs',
                'recommendation' => 'Depends on site needs',
                'present' => isset($headers_lower['permissions-policy']),
                'value' => $headers_lower['permissions-policy'] ?? null,
            ],
        ];

        // Calculate score
        $total = count($security_headers);
        $present = 0;
        foreach ($security_headers as $header) {
            if ($header['present']) {
                $present++;
            }
        }
        $score = round(($present / $total) * 100);

        return rest_ensure_response([
            'success' => true,
            'data' => [
                'headers' => $security_headers,
                'score' => $score,
                'present_count' => $present,
                'total_count' => $total,
            ],
        ]);
    }

    /**
     * Generate security header configuration snippets for Apache and Nginx.
     *
     * @return WP_REST_Response
     */
    public function get_security_header_snippets() {
        $site_url = get_site_url();
        $domain = parse_url($site_url, PHP_URL_HOST);
        
        // Apache .htaccess snippet
        $htaccess = <<<HTACCESS
# ===== SECURITY HEADERS =====
# Add to your .htaccess file in the WordPress root directory
# Generated for: {$domain}

<IfModule mod_headers.c>
    # Prevent clickjacking attacks
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # Prevent MIME type sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # Enable XSS filter (legacy browsers)
    Header always set X-XSS-Protection "1; mode=block"
    
    # Force HTTPS (uncomment if using SSL)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Control referrer information
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Restrict browser features
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    
    # Content Security Policy (customize based on your needs)
    # Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:;"
</IfModule>

# ===== END SECURITY HEADERS =====
HTACCESS;

        // Nginx snippet
        $nginx = <<<NGINX
# ===== SECURITY HEADERS =====
# Add to your nginx server block
# Generated for: {$domain}

# Prevent clickjacking attacks
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Enable XSS filter (legacy browsers)
add_header X-XSS-Protection "1; mode=block" always;

# Force HTTPS (uncomment if using SSL)
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Control referrer information
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Restrict browser features
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Content Security Policy (customize based on your needs)
# add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:;" always;

# ===== END SECURITY HEADERS =====
NGINX;

        // WordPress PHP snippet (for wp-config.php or plugin)
        $php = <<<'PHP'
<?php
/**
 * Security Headers via PHP
 * Add this code to your theme's functions.php or a custom plugin
 */
add_action('send_headers', function() {
    // Prevent clickjacking attacks
    header('X-Frame-Options: SAMEORIGIN');
    
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Enable XSS filter (legacy browsers)
    header('X-XSS-Protection: 1; mode=block');
    
    // Force HTTPS (uncomment if using SSL)
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    
    // Control referrer information
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Restrict browser features
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
});
PHP;

         return rest_ensure_response([
            'success' => true,
            'data' => [
                'apache' => $htaccess,
                'nginx' => $nginx,
                'php' => $php,
            ],
        ]);
    }

    /**
     * Run a full security scan.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function run_security_scan($request) {
        $scan_type = $request->get_param('scan_type') ?: 'full';
        $valid_types = ['quick', 'standard', 'full'];
        if (!in_array($scan_type, $valid_types)) {
            $scan_type = 'full';
        }

        // Set time limits based on scan tier
        $time_limits = ['quick' => 60, 'standard' => 180, 'full' => 600];
        if (function_exists('set_time_limit')) {
            @set_time_limit($time_limits[$scan_type]);
        }
        @ini_set('memory_limit', '256M');

        $modules = $request->get_param('modules');
        if ($modules && is_string($modules)) {
            $modules = explode(',', $modules);
            $modules = array_map('trim', $modules);
        }

        $scanner = new LSM_Security_Scanner();
        $results = $scanner->run($modules, $scan_type);

        LSM_Logger::log('security_scan_completed', $results['summary']['clean'] ? 'success' : 'warning', [
            'scan_type' => $scan_type,
            'status'   => $results['status'],
            'threats'  => $results['summary']['threats_found'],
            'warnings' => $results['summary']['warnings_found'],
            'duration' => $results['duration_seconds'],
        ]);

        return rest_ensure_response([
            'success' => true,
            'data'    => $results,
        ]);
    }

    /**
     * Run a quick security scan (lightweight).
     * Legacy endpoint — delegates to run_security_scan with scan_type=quick.
     *
     * @param WP_REST_Request $request Request.
     * @return WP_REST_Response
     */
    public function run_quick_scan($request) {
        if (function_exists('set_time_limit')) {
            @set_time_limit(60);
        }

        $scanner = new LSM_Security_Scanner();
        $results = $scanner->run(null, 'quick');

        return rest_ensure_response([
            'success' => true,
            'data'    => $results,
        ]);
    }
}


<?php
/**
 * Site actions for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Actions class.
 */
class LSM_Actions {

    /**
     * Clear all caches - Ultimate cache clearing for all layers.
     *
     * @return array Result with cleared caches.
     */
    public static function clear_cache() {
        $cleared = [];

        // WP Super Cache
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
            $cleared[] = 'wp_super_cache';
        }

        // W3 Total Cache
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
            $cleared[] = 'w3_total_cache';
        }

        // WP Fastest Cache
        if (class_exists('WpFastestCache')) {
            $wpfc = new WpFastestCache();
            if (method_exists($wpfc, 'deleteCache')) {
                $wpfc->deleteCache();
                $cleared[] = 'wp_fastest_cache';
            }
        }

        // LiteSpeed Cache
        if (class_exists('LiteSpeed_Cache_API')) {
            LiteSpeed_Cache_API::purge_all();
            $cleared[] = 'litespeed_cache';
        }

        // WP Rocket - Full purge
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
            $cleared[] = 'wp_rocket';
        }
        // WP Rocket - Also clean minified CSS/JS
        if (function_exists('rocket_clean_minify')) {
            rocket_clean_minify();
            $cleared[] = 'wp_rocket_minify';
        }

        // Autoptimize
        if (class_exists('autoptimizeCache')) {
            autoptimizeCache::clearall();
            $cleared[] = 'autoptimize';
        }

        // SG Optimizer (SiteGround SuperCacher)
        if (function_exists('sg_cachepress_purge_cache')) {
            sg_cachepress_purge_cache();
            $cleared[] = 'sg_optimizer';
        }

        // Breeze (Cloudways)
        if (class_exists('Breeze_PurgeCache')) {
            Breeze_PurgeCache::breeze_cache_flush();
            $cleared[] = 'breeze';
        }

        // Elementor - Regenerate CSS files
        if (class_exists('\Elementor\Plugin')) {
            // Clear Elementor CSS cache
            \Elementor\Plugin::$instance->files_manager->clear_cache();
            $cleared[] = 'elementor_css';
        }

        // Elementor Pro - Clear dynamic CSS if available
        if (class_exists('\ElementorPro\Plugin')) {
            if (method_exists('\ElementorPro\Plugin', 'instance')) {
                $elementor_pro = \ElementorPro\Plugin::instance();
                if (isset($elementor_pro->assets_manager)) {
                    $elementor_pro->assets_manager->clear_assets_cache();
                    $cleared[] = 'elementor_pro_assets';
                }
            }
        }

        // Object cache (Redis, Memcached, etc.)
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
            $cleared[] = 'object_cache';
        }

        // OPcache - Clear PHP opcode cache
        if (function_exists('opcache_reset') && ini_get('opcache.enable')) {
            @opcache_reset();
            $cleared[] = 'opcache';
        }

        // WP transients - Clear expired transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%' AND option_value < UNIX_TIMESTAMP()");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%' AND option_name NOT IN (SELECT CONCAT('_transient_', SUBSTRING(option_name, 20)) FROM (SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%') AS t)");
        $cleared[] = 'expired_transients';

        LSM_Logger::log('cache_cleared', 'success', [
            'cleared' => $cleared,
        ]);

        return [
            'success' => true,
            'cleared' => $cleared,
            'count'   => count($cleared),
            'message' => sprintf(__('%d cache layers cleared', 'landeseiten-maintenance'), count($cleared)),
        ];
    }

    /**
     * Flush rewrite rules.
     *
     * @return array Result.
     */
    public static function flush_rewrite() {
        flush_rewrite_rules();

        LSM_Logger::log('rewrite_flushed', 'success', []);

        return [
            'success' => true,
            'message' => __('Rewrite rules flushed.', 'landeseiten-maintenance'),
        ];
    }

    /**
     * Optimize database.
     *
     * @return array Result with optimization details.
     */
    public static function optimize_database() {
        global $wpdb;

        $tables = $wpdb->get_results("SHOW TABLES LIKE '{$wpdb->prefix}%'", ARRAY_N);
        $optimized = 0;
        $size_before = 0;
        $size_after = 0;

        foreach ($tables as $table) {
            $table_name = $table[0];

            // Get size before
            $status = $wpdb->get_row("SHOW TABLE STATUS LIKE '$table_name'");
            if ($status) {
                $size_before += $status->Data_length + $status->Index_length;
            }

            // Optimize
            $wpdb->query("OPTIMIZE TABLE `$table_name`");
            $optimized++;

            // Get size after
            $status = $wpdb->get_row("SHOW TABLE STATUS LIKE '$table_name'");
            if ($status) {
                $size_after += $status->Data_length + $status->Index_length;
            }
        }

        $saved = $size_before - $size_after;

        LSM_Logger::log('database_optimized', 'success', [
            'tables'      => $optimized,
            'saved_bytes' => $saved,
        ]);

        return [
            'success'      => true,
            'tables_count' => $optimized,
            'size_before'  => size_format($size_before),
            'size_after'   => size_format($size_after),
            'saved'        => size_format($saved),
        ];
    }

    /**
     * Cleanup database - removes revisions, transients, drafts, spam, etc.
     *
     * @param array $options Cleanup options (revisions, transients, drafts, spam, orphan_meta).
     * @return array Result with cleanup details.
     */
    public static function cleanup_database($options = []) {
        global $wpdb;

        // Default: clean everything
        $defaults = [
            'revisions'    => true,
            'transients'   => true,
            'drafts'       => true,
            'spam'         => true,
            'trash'        => true,
            'orphan_meta'  => true,
        ];
        $options = wp_parse_args($options, $defaults);

        $results = [];
        $total_deleted = 0;

        // 1. Delete all post revisions (like WP Rocket does)
        if (!empty($options['revisions'])) {
            $revisions = $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_type = 'revision'");
            $results['revisions'] = (int) $revisions;
            $total_deleted += (int) $revisions;
        }

        // 2. Delete expired transients
        if (!empty($options['transients'])) {
            $time = time();
            
            // Get expired transient names first
            $expired_names = $wpdb->get_col($wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} 
                WHERE option_name LIKE %s 
                AND option_value < %d",
                '_transient_timeout_%',
                $time
            ));
            
            $deleted_count = 0;
            
            if (!empty($expired_names)) {
                // Delete the timeout entries
                $deleted_timeouts = $wpdb->query(
                    "DELETE FROM {$wpdb->options} 
                    WHERE option_name LIKE '_transient_timeout_%' 
                    AND option_value < {$time}"
                );
                $deleted_count += (int) $deleted_timeouts;
                
                // Delete matching transient values
                foreach ($expired_names as $timeout_name) {
                    $transient_name = str_replace('_transient_timeout_', '_transient_', $timeout_name);
                    $wpdb->delete($wpdb->options, ['option_name' => $transient_name]);
                    $deleted_count++;
                }
            }
            
            // Also clean expired site transients
            $expired_site = $wpdb->get_col($wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} 
                WHERE option_name LIKE %s 
                AND option_value < %d",
                '_site_transient_timeout_%',
                $time
            ));
            
            if (!empty($expired_site)) {
                $wpdb->query(
                    "DELETE FROM {$wpdb->options} 
                    WHERE option_name LIKE '_site_transient_timeout_%' 
                    AND option_value < {$time}"
                );
                foreach ($expired_site as $timeout_name) {
                    $transient_name = str_replace('_site_transient_timeout_', '_site_transient_', $timeout_name);
                    $wpdb->delete($wpdb->options, ['option_name' => $transient_name]);
                    $deleted_count++;
                }
            }
            
            $results['transients'] = $deleted_count;
            $total_deleted += $deleted_count;
        }

        // 3. Delete auto-drafts
        if (!empty($options['drafts'])) {
            $drafts = $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_status = 'auto-draft'");
            $results['drafts'] = (int) $drafts;
            $total_deleted += (int) $drafts;
        }

        // 4. Delete spam comments
        if (!empty($options['spam'])) {
            $spam = $wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam'");
            $results['spam'] = (int) $spam;
            $total_deleted += (int) $spam;
        }

        // 5. Delete trashed comments
        if (!empty($options['trash'])) {
            $trash = $wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_approved = 'trash'");
            // Also delete trashed posts
            $trash_posts = $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_status = 'trash'");
            $results['trash'] = (int) $trash + (int) $trash_posts;
            $total_deleted += $results['trash'];
        }

        // 6. Delete orphaned postmeta
        if (!empty($options['orphan_meta'])) {
            $orphan_postmeta = $wpdb->query(
                "DELETE pm FROM {$wpdb->postmeta} pm 
                LEFT JOIN {$wpdb->posts} p ON pm.post_id = p.ID 
                WHERE p.ID IS NULL"
            );
            $orphan_commentmeta = $wpdb->query(
                "DELETE cm FROM {$wpdb->commentmeta} cm 
                LEFT JOIN {$wpdb->comments} c ON cm.comment_id = c.comment_ID 
                WHERE c.comment_ID IS NULL"
            );
            $results['orphan_meta'] = (int) $orphan_postmeta + (int) $orphan_commentmeta;
            $total_deleted += $results['orphan_meta'];
        }

        LSM_Logger::log('database_cleanup', 'success', [
            'results' => $results,
            'total'   => $total_deleted,
        ]);

        // Build detailed message
        $details = [];
        if (!empty($results['revisions'])) {
            $details[] = $results['revisions'] . ' revisions';
        }
        if (!empty($results['transients'])) {
            $details[] = $results['transients'] . ' transients';
        }
        if (!empty($results['drafts'])) {
            $details[] = $results['drafts'] . ' auto-drafts';
        }
        if (!empty($results['spam'])) {
            $details[] = $results['spam'] . ' spam comments';
        }
        if (!empty($results['trash'])) {
            $details[] = $results['trash'] . ' trashed items';
        }
        if (!empty($results['orphan_meta'])) {
            $details[] = $results['orphan_meta'] . ' orphaned meta';
        }
        
        $detailed_message = !empty($details) 
            ? implode(', ', $details)
            : 'No items to clean';

        return [
            'success'       => true,
            'results'       => $results,
            'total_deleted' => $total_deleted,
            'message'       => $detailed_message,
        ];
    }

    /**
     * Get database statistics for cleanup preview.
     *
     * @return array Counts for each cleanup category.
     */
    public static function get_database_stats() {
        global $wpdb;

        // Count revisions
        $revisions = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'"
        );

        // Count auto-drafts
        $drafts = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'auto-draft'"
        );

        // Count trashed posts
        $trashed_posts = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status = 'trash'"
        );

        // Count spam comments
        $spam_comments = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam'"
        );

        // Count trashed comments
        $trashed_comments = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'trash'"
        );

        // Count expired transients
        $time = time();
        $expired_transients = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%' AND option_value < {$time}"
        );

        // Count all transients (for display)
        $all_transients = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%'"
        );

        // Count orphaned postmeta
        $orphan_postmeta = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->postmeta} pm 
            LEFT JOIN {$wpdb->posts} p ON pm.post_id = p.ID 
            WHERE p.ID IS NULL"
        );

        // Count orphaned commentmeta
        $orphan_commentmeta = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->commentmeta} cm 
            LEFT JOIN {$wpdb->comments} c ON cm.comment_id = c.comment_ID 
            WHERE c.comment_ID IS NULL"
        );

        // Get tables that can be optimized
        $tables = $wpdb->get_results("SHOW TABLE STATUS LIKE '{$wpdb->prefix}%'", ARRAY_A);
        $tables_to_optimize = 0;
        $potential_savings = 0;
        foreach ($tables as $table) {
            if (isset($table['Data_free']) && $table['Data_free'] > 0) {
                $tables_to_optimize++;
                $potential_savings += (int) $table['Data_free'];
            }
        }

        return [
            'success' => true,
            'stats' => [
                'revisions' => [
                    'count' => $revisions,
                    'label' => 'Post Revisions',
                ],
                'drafts' => [
                    'count' => $drafts,
                    'label' => 'Auto-Drafts',
                ],
                'trashed_posts' => [
                    'count' => $trashed_posts,
                    'label' => 'Trashed Posts',
                ],
                'spam_comments' => [
                    'count' => $spam_comments,
                    'label' => 'Spam Comments',
                ],
                'trashed_comments' => [
                    'count' => $trashed_comments,
                    'label' => 'Trashed Comments',
                ],
                'transients' => [
                    'count' => $expired_transients,
                    'total' => $all_transients,
                    'label' => 'Expired Transients',
                ],
                'orphan_meta' => [
                    'count' => $orphan_postmeta + $orphan_commentmeta,
                    'label' => 'Orphaned Meta',
                ],
                'optimize' => [
                    'tables' => $tables_to_optimize,
                    'potential_savings' => size_format($potential_savings),
                    'label' => 'Tables to Optimize',
                ],
            ],
        ];
    }

    /**
     * Get available updates.
     *
     * @return array Updates info.
     */
    public static function get_updates() {
        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        // Force update check
        wp_update_plugins();
        wp_update_themes();

        $plugin_updates = get_plugin_updates();
        $theme_updates = get_theme_updates();
        $core_updates = get_core_updates();

        $plugins = [];
        foreach ($plugin_updates as $file => $data) {
            $plugins[] = [
                'file'        => $file,
                'name'        => $data->Name,
                'current'     => $data->Version,
                'new_version' => $data->update->new_version,
            ];
        }

        $themes = [];
        foreach ($theme_updates as $slug => $data) {
            $themes[] = [
                'slug'        => $slug,
                'name'        => $data->get('Name'),
                'current'     => $data->get('Version'),
                'new_version' => $data->update['new_version'],
            ];
        }

        $core = null;
        if (!empty($core_updates) && $core_updates[0]->response === 'upgrade') {
            $core = [
                'current'     => get_bloginfo('version'),
                'new_version' => $core_updates[0]->version,
            ];
        }

        return [
            'plugins' => $plugins,
            'themes'  => $themes,
            'core'    => $core,
            'total'   => count($plugins) + count($themes) + ($core ? 1 : 0),
        ];
    }

    /**
     * Update all plugins.
     *
     * @return array Result.
     */
    public static function update_all_plugins() {
        // Set admin user context — required for Plugin_Upgrader filesystem operations
        wp_set_current_user(1);

        if (!function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

        // Refresh update cache before checking for available updates
        wp_update_plugins();

        $plugin_updates = get_plugin_updates();
        $updated = [];
        $failed = [];

        $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin());

        foreach ($plugin_updates as $file => $data) {
            $result = $upgrader->upgrade($file);
            if ($result && !is_wp_error($result)) {
                $updated[] = $data->Name;
            } else {
                $failed[] = $data->Name;
            }
        }


        LSM_Logger::log('plugins_updated', 'success', [
            'updated' => count($updated),
            'failed'  => count($failed),
        ]);

        return [
            'success'       => true,
            'updated'       => $updated,
            'failed'        => $failed,
            'updated_count' => count($updated),
        ];
    }

    /**
     * Update WordPress core.
     *
     * @return array Result.
     */
    public static function update_core() {
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/update.php';

        $core_updates = get_core_updates();
        if (empty($core_updates) || $core_updates[0]->response !== 'upgrade') {
            return [
                'success' => false,
                'message' => __('No core update available.', 'landeseiten-maintenance'),
            ];
        }

        $upgrader = new Core_Upgrader(new Automatic_Upgrader_Skin());
        $result = $upgrader->upgrade($core_updates[0]);

        if (is_wp_error($result)) {
            return [
                'success' => false,
                'message' => $result->get_error_message(),
            ];
        }

        LSM_Logger::log('core_updated', 'success', [
            'version' => $core_updates[0]->version,
        ]);

        return [
            'success'     => true,
            'new_version' => $core_updates[0]->version,
        ];
    }
}

<?php
/**
 * Recovery tools for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Recovery class.
 */
class LSM_Recovery {

    /**
     * Disable all plugins except this one.
     *
     * @return array Result with disabled plugins list.
     */
    public static function disable_all_plugins() {
        $active_plugins = get_option('active_plugins', []);
        $our_plugin = 'landeseiten-maintenance/landeseiten-maintenance.php';

        // Store current plugins for later restoration
        update_option('lsm_disabled_plugins', $active_plugins);

        // Deactivate all except ours
        $disabled = [];
        foreach ($active_plugins as $plugin) {
            if ($plugin !== $our_plugin) {
                deactivate_plugins($plugin);
                $disabled[] = $plugin;
            }
        }

        LSM_Logger::log('plugins_disabled', 'warning', [
            'count' => count($disabled),
        ]);

        return [
            'success'        => true,
            'disabled_count' => count($disabled),
            'disabled'       => $disabled,
        ];
    }

    /**
     * Restore previously disabled plugins.
     *
     * @return array Result with restored plugins list.
     */
    public static function restore_plugins() {
        $disabled_plugins = get_option('lsm_disabled_plugins', []);

        if (empty($disabled_plugins)) {
            return [
                'success'        => false,
                'message'        => __('No plugins to restore.', 'landeseiten-maintenance'),
                'restored_count' => 0,
            ];
        }

        $restored = [];
        foreach ($disabled_plugins as $plugin) {
            if (file_exists(WP_PLUGIN_DIR . '/' . $plugin)) {
                activate_plugin($plugin);
                $restored[] = $plugin;
            }
        }

        // Clear the stored list
        update_option('lsm_disabled_plugins', []);

        LSM_Logger::log('plugins_restored', 'success', [
            'count' => count($restored),
        ]);

        return [
            'success'        => true,
            'restored_count' => count($restored),
            'restored'       => $restored,
        ];
    }

    /**
     * Switch to default theme.
     *
     * @return array Result.
     */
    public static function switch_to_default_theme() {
        $current_theme = get_stylesheet();
        
        // Store current theme for restoration
        update_option('lsm_previous_theme', $current_theme);

        // Try default themes in order of preference
        $default_themes = ['twentytwentyfour', 'twentytwentythree', 'twentytwentytwo', 'twentytwentyone', 'twentytwenty'];

        foreach ($default_themes as $theme) {
            if (wp_get_theme($theme)->exists()) {
                switch_theme($theme);
                
                LSM_Logger::log('theme_switched', 'warning', [
                    'from' => $current_theme,
                    'to'   => $theme,
                ]);

                return [
                    'success'        => true,
                    'previous_theme' => $current_theme,
                    'current_theme'  => $theme,
                ];
            }
        }

        return [
            'success' => false,
            'message' => __('No default theme available.', 'landeseiten-maintenance'),
        ];
    }

    /**
     * Restore previous theme.
     *
     * @return array Result.
     */
    public static function restore_theme() {
        $previous_theme = get_option('lsm_previous_theme');

        if (!$previous_theme) {
            return [
                'success' => false,
                'message' => __('No previous theme stored.', 'landeseiten-maintenance'),
            ];
        }

        if (wp_get_theme($previous_theme)->exists()) {
            $current = get_stylesheet();
            switch_theme($previous_theme);
            delete_option('lsm_previous_theme');

            LSM_Logger::log('theme_restored', 'success', [
                'from' => $current,
                'to'   => $previous_theme,
            ]);

            return [
                'success'       => true,
                'current_theme' => $previous_theme,
            ];
        }

        return [
            'success' => false,
            'message' => __('Previous theme no longer exists.', 'landeseiten-maintenance'),
        ];
    }

    /**
     * Full emergency recovery.
     *
     * @return array Result of all recovery actions.
     */
    public static function emergency_recovery() {
        LSM_Logger::log('emergency_recovery_started', 'warning', []);

        $results = [
            'maintenance' => LSM_Maintenance_Mode::enable(),
            'plugins'     => self::disable_all_plugins(),
            'theme'       => self::switch_to_default_theme(),
        ];

        LSM_Logger::log('emergency_recovery_completed', 'warning', $results);

        return [
            'success' => true,
            'actions' => $results,
        ];
    }
}

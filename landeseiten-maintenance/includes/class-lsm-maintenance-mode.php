<?php
/**
 * Maintenance Mode for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Maintenance Mode class.
 */
class LSM_Maintenance_Mode {

    /**
     * Constructor.
     */
    public function __construct() {
        add_action('template_redirect', [$this, 'check_maintenance_mode'], 10);
    }

    /**
     * Check and display maintenance mode.
     */
    public function check_maintenance_mode() {
        if (!self::is_enabled()) {
            return;
        }

        // Allow logged in admins
        if (current_user_can('manage_options')) {
            return;
        }

        // Allow admin, login, and cron
        if (
            is_admin() ||
            wp_doing_cron() ||
            wp_doing_ajax() ||
            (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) ||
            strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false
        ) {
            return;
        }

        // Allow API requests with valid key
        if (strpos($_SERVER['REQUEST_URI'], '/wp-json/lsm/') !== false) {
            return;
        }

        // Show maintenance page
        self::display_maintenance_page();
        exit;
    }

    /**
     * Enable maintenance mode.
     *
     * @return array Result.
     */
    public static function enable() {
        Landeseiten_Maintenance::update_setting('maintenance_mode', true);
        Landeseiten_Maintenance::update_setting('maintenance_enabled_at', current_time('mysql'));

        LSM_Logger::log('maintenance_enabled', 'warning', []);

        return [
            'success' => true,
            'enabled' => true,
            'message' => __('Maintenance mode enabled.', 'landeseiten-maintenance'),
        ];
    }

    /**
     * Disable maintenance mode.
     *
     * @return array Result.
     */
    public static function disable() {
        Landeseiten_Maintenance::update_setting('maintenance_mode', false);

        LSM_Logger::log('maintenance_disabled', 'success', []);

        return [
            'success' => true,
            'enabled' => false,
            'message' => __('Maintenance mode disabled.', 'landeseiten-maintenance'),
        ];
    }

    /**
     * Check if maintenance mode is enabled.
     *
     * @return bool
     */
    public static function is_enabled() {
        return (bool) Landeseiten_Maintenance::get_setting('maintenance_mode');
    }

    /**
     * Display custom maintenance page.
     */
    public static function display_maintenance_page() {
        $settings = Landeseiten_Maintenance::get_setting();
        if (!is_array($settings)) {
            $settings = [];
        }

        $title = $settings['maintenance_title'] ?? __('Site Under Maintenance', 'landeseiten-maintenance');
        $message = $settings['maintenance_message'] ?? __('We are performing scheduled maintenance. Please check back soon.', 'landeseiten-maintenance');
        $logo_url = $settings['maintenance_logo'] ?? '';
        $bg_color = $settings['maintenance_bg_color'] ?? '#0f172a';
        $text_color = $settings['maintenance_text_color'] ?? '#ffffff';
        $accent_color = $settings['maintenance_accent_color'] ?? '#667eea';

        // Set proper HTTP status if headers not sent
        if (!headers_sent()) {
            status_header(503);
            header('Retry-After: 3600');
            header('Content-Type: text/html; charset=utf-8');
        }

        ?>
<!DOCTYPE html>
<html lang="<?php echo get_locale(); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html($title); ?> - <?php echo esc_html(get_bloginfo('name')); ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: <?php echo esc_attr($bg_color); ?>;
            color: <?php echo esc_attr($text_color); ?>;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        /* Animated background */
        .bg-animation {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            overflow: hidden;
            z-index: 0;
        }

        .bg-animation::before {
            content: '';
            position: absolute;
            width: 150%;
            height: 150%;
            top: -25%;
            left: -25%;
            background: radial-gradient(ellipse at center, <?php echo esc_attr($accent_color); ?>20 0%, transparent 70%);
            animation: pulse 8s ease-in-out infinite;
        }

        .bg-animation::after {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(2px 2px at 20% 30%, rgba(255,255,255,0.1) 1px, transparent 0),
                radial-gradient(2px 2px at 40% 70%, rgba(255,255,255,0.05) 1px, transparent 0),
                radial-gradient(1px 1px at 90% 40%, rgba(255,255,255,0.1) 1px, transparent 0);
            background-size: 200px 200px;
            animation: stars 20s linear infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 0.5; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.1); }
        }

        @keyframes stars {
            0% { transform: translateY(0); }
            100% { transform: translateY(-200px); }
        }

        .container {
            position: relative;
            z-index: 1;
            max-width: 600px;
            text-align: center;
            padding: 60px 40px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            backdrop-filter: blur(20px);
        }

        .logo {
            margin-bottom: 40px;
        }

        .logo img {
            max-height: 60px;
            width: auto;
        }

        .logo-placeholder {
            width: 80px;
            height: 80px;
            margin: 0 auto;
            background: linear-gradient(135deg, <?php echo esc_attr($accent_color); ?>, #764ba2);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            animation: float 3s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }

        .icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: linear-gradient(135deg, <?php echo esc_attr($accent_color); ?>, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: float 3s ease-in-out infinite;
        }

        .icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }

        h1 {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 16px;
            background: linear-gradient(135deg, <?php echo esc_attr($text_color); ?>, <?php echo esc_attr($accent_color); ?>);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .message {
            font-size: 18px;
            line-height: 1.7;
            opacity: 0.8;
            margin-bottom: 40px;
        }

        .progress-bar {
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 30px;
        }

        .progress-bar::after {
            content: '';
            display: block;
            width: 30%;
            height: 100%;
            background: linear-gradient(90deg, <?php echo esc_attr($accent_color); ?>, #764ba2);
            animation: loading 2s ease-in-out infinite;
        }

        @keyframes loading {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(400%); }
        }

        .info {
            display: flex;
            justify-content: center;
            gap: 30px;
            font-size: 14px;
            opacity: 0.6;
        }

        .info-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .powered-by {
            position: absolute;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 12px;
            opacity: 0.4;
            z-index: 1;
        }

        .powered-by a {
            color: inherit;
            text-decoration: none;
        }

        @media (max-width: 640px) {
            .container {
                padding: 40px 24px;
            }
            h1 {
                font-size: 24px;
            }
            .message {
                font-size: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="bg-animation"></div>
    
    <div class="container">
        <div class="logo">
            <?php if ($logo_url) : ?>
                <img src="<?php echo esc_url($logo_url); ?>" alt="<?php echo esc_attr(get_bloginfo('name')); ?>">
            <?php else : ?>
                <div class="logo-placeholder">
                    <svg viewBox="0 0 24 24" width="40" height="40" fill="white">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                    </svg>
                </div>
            <?php endif; ?>
        </div>
        
        <h1><?php echo esc_html($title); ?></h1>
        
        <p class="message"><?php echo nl2br(esc_html($message)); ?></p>
        
        <div class="progress-bar"></div>
        
        <div class="info">
            <div class="info-item">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                    <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/>
                    <polyline points="12,6 12,12 16,14" fill="none" stroke="currentColor" stroke-width="2"/>
                </svg>
                <span><?php _e('Back soon', 'landeseiten-maintenance'); ?></span>
            </div>
            <div class="info-item">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="2"/>
                </svg>
                <span><?php _e('Secure', 'landeseiten-maintenance'); ?></span>
            </div>
        </div>
    </div>
    
    <div class="powered-by">
        <?php _e('Managed by', 'landeseiten-maintenance'); ?> <a href="https://landeseiten.at" target="_blank">Landeseiten</a>
    </div>
</body>
</html>
        <?php
    }
}

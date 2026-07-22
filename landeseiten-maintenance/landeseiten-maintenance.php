<?php
/**
 * Plugin Name: Landeseiten Maintenance
 * Description: Remote site management, SSO login, health monitoring, security scanning, and client support for Landeseiten managed WordPress sites.
 * Version: 2.9.3
 * Author: Landeseiten GmbH
 * Author URI: https://landeseiten.at
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: landeseiten-maintenance
 * Domain Path: /languages
 *
 * @package Landeseiten_Maintenance
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('LSM_VERSION', '2.9.3');
define('LSM_PLUGIN_FILE', __FILE__);
define('LSM_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('LSM_PLUGIN_URL', plugin_dir_url(__FILE__));
define('LSM_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Main plugin class.
 *
 * @since 1.0.0
 */
final class Landeseiten_Maintenance {

    /**
     * Plugin instance.
     *
     * @var Landeseiten_Maintenance
     */
    private static $instance = null;

    /**
     * Get plugin instance.
     *
     * @return Landeseiten_Maintenance
     */
    public static function instance() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor.
     */
    private function __construct() {
        $this->includes();
        $this->init_hooks();

        // Self-updater via GitHub releases
        LSM_Updater::init();
    }

    /**
     * Include required files.
     */
    private function includes() {
        // Core classes
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-logger.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-health.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-auth.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-recovery.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-actions.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-api.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-support.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-ticket-types.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-ticket-client.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-maintenance-mode.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-backup.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-php-errors.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-security-scanner.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-scan-collector.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-scan-data-collector.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-media.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-updater.php';

        // Admin
        if (is_admin()) {
            require_once LSM_PLUGIN_DIR . 'admin/class-lsm-admin.php';
        }
    }

    /**
     * Initialize hooks.
     */
    private function init_hooks() {
        // Activation/Deactivation
        register_activation_hook(LSM_PLUGIN_FILE, [$this, 'activate']);
        register_deactivation_hook(LSM_PLUGIN_FILE, [$this, 'deactivate']);

        // Initialize components
        add_action('init', [$this, 'init'], 0);
        add_action('rest_api_init', [$this, 'init_rest_api']);
        
        // Enqueue scripts
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

        // Front-end flying ticket widget (admins only)
        add_action('wp_enqueue_scripts', [$this, 'enqueue_ticket_widget']);
        add_action('wp_footer', [$this, 'render_ticket_widget_root']);
        add_action('admin_footer', [$this, 'render_ticket_widget_root_admin']);

        // Security filters
        $this->init_security_filters();
    }

    /**
     * Initialize security filters based on settings.
     */
    private function init_security_filters() {
        // XML-RPC blocking
        if (!get_option('lsm_xmlrpc_enabled', true)) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', '__return_empty_array');
        }

        // REST API: Block user enumeration + ensure LSM endpoints always work
        add_filter('rest_authentication_errors', function($result) {
            // If there's already an error, check if it's an LSM request before passing it through
            if (is_wp_error($result) || $result === false) {
                $is_lsm_request = $this->is_lsm_rest_request();
                return $is_lsm_request ? null : $result;
            }

            // Block user enumeration via REST API when setting is enabled
            if (!get_option('lsm_rest_api_public', true) && !is_user_logged_in()) {
                $uri = isset($_SERVER['REQUEST_URI']) ? urldecode($_SERVER['REQUEST_URI']) : '';
                $route = isset($_GET['rest_route']) ? urldecode($_GET['rest_route']) : '';

                $is_users_endpoint = strpos($uri, '/wp/v2/users') !== false
                    || strpos($route, '/wp/v2/users') !== false;

                if ($is_users_endpoint) {
                    return new \WP_Error(
                        'rest_user_enumeration_blocked',
                        'User enumeration is disabled.',
                        ['status' => 403]
                    );
                }
            }

            return $result;
        }, 999);

        // Block ?author= query string user enumeration
        if (!get_option('lsm_rest_api_public', true)) {
            add_action('template_redirect', function() {
                if (!is_user_logged_in() && isset($_GET['author'])) {
                    wp_die('User enumeration is disabled.', 'Forbidden', ['response' => 403]);
                }
            });
        }

        // File editing disabled - remove capabilities for editing plugins/themes
        if (get_option('lsm_file_editing_disabled', false)) {
            // Use map_meta_cap to block file editing capabilities (most reliable method)
            add_filter('map_meta_cap', function($caps, $cap, $user_id, $args) {
                // Block these specific capabilities
                $blocked_caps = ['edit_plugins', 'edit_themes', 'edit_files'];
                if (in_array($cap, $blocked_caps)) {
                    // Return do_not_allow to prevent this capability
                    return ['do_not_allow'];
                }
                return $caps;
            }, 10, 4);
            
            // Also define the constant for good measure if not already defined
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        // Security headers - inject via PHP when enabled
        if (get_option('lsm_security_headers_enabled', false)) {
            add_action('send_headers', function() {
                // Prevent clickjacking
                header('X-Frame-Options: SAMEORIGIN');
                // Prevent MIME type sniffing
                header('X-Content-Type-Options: nosniff');
                // XSS protection for legacy browsers
                header('X-XSS-Protection: 1; mode=block');
                // Control referrer information
                header('Referrer-Policy: strict-origin-when-cross-origin');
                // Restrict browser features
                header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
                // HSTS - only on HTTPS
                if (is_ssl()) {
                    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
                }
            });
        }
    }

    /**
     * Initialize plugin.
     */
    public function init() {
        // Load textdomain
        load_plugin_textdomain('landeseiten-maintenance', false, dirname(LSM_PLUGIN_BASENAME) . '/languages');

        // Initialize components
        LSM_Logger::init();
        new LSM_Health();
        new LSM_Auth();
        new LSM_Recovery();
        new LSM_Actions();
        new LSM_Support();
        new LSM_Maintenance_Mode();

        // Initialize PHP error handling
        LSM_Php_Errors::init();

        if (is_admin()) {
            new LSM_Admin();
        }
    }

    private function is_lsm_rest_request(): bool {
        $checks = [
            $_SERVER['REQUEST_URI'] ?? '',
            $_GET['rest_route'] ?? '',
            $_SERVER['PATH_INFO'] ?? '',
            $_SERVER['REDIRECT_URL'] ?? '',
        ];
        foreach ($checks as $value) {
            if (strpos(urldecode($value), '/lsm/v1') !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Initialize REST API.
     */
    public function init_rest_api() {
        $api = new LSM_API();
        $api->register_routes();
    }

    /**
     * Enqueue admin assets.
     */
    public function enqueue_admin_assets($hook) {
        // Admin page styles
        if (strpos($hook, 'landeseiten') !== false) {
            wp_enqueue_style(
                'lsm-admin',
                LSM_PLUGIN_URL . 'admin/css/admin.css',
                [],
                LSM_VERSION
            );

            wp_enqueue_style('lsm-ticket-ui', LSM_PLUGIN_URL . 'assets/css/ticket-ui.css', [], LSM_VERSION);

            wp_enqueue_script(
                'lsm-admin',
                LSM_PLUGIN_URL . 'admin/js/admin.js',
                ['jquery'],
                LSM_VERSION,
                true
            );
        }
    }

    /**
     * Whether the flying ticket widget should load for the current user.
     */
    private function ticket_widget_allowed() {
        $settings = self::get_setting();

        return !empty($settings['ticket_widget_enabled'] ?? true)
            && is_user_logged_in()
            && current_user_can('manage_options');
    }

    /**
     * Enqueue the ticket widget assets (front-end).
     */
    public function enqueue_ticket_widget() {
        if (!$this->ticket_widget_allowed()) {
            return;
        }

        wp_enqueue_style('lsm-ticket-ui', LSM_PLUGIN_URL . 'assets/css/ticket-ui.css', [], LSM_VERSION);
        wp_enqueue_style('lsm-ticket-widget', LSM_PLUGIN_URL . 'assets/css/ticket-widget.css', [], LSM_VERSION);
        wp_enqueue_script('lsm-html2canvas', LSM_PLUGIN_URL . 'assets/js/vendor/html2canvas.min.js', [], '1.4.1', true);
        wp_enqueue_script('lsm-ticket-widget', LSM_PLUGIN_URL . 'assets/js/ticket-widget.js', ['lsm-html2canvas'], LSM_VERSION, true);

        $user = wp_get_current_user();
        wp_localize_script('lsm-ticket-widget', 'lsmTicketWidget', [
            'ajaxUrl'      => admin_url('admin-ajax.php'),
            'ticketNonce'  => wp_create_nonce('lsm_ticket_nonce'),
            'supportNonce' => wp_create_nonce('lsm_support_nonce'),
            'userEmail'    => $user->user_email,
            'userName'     => $user->display_name,
            'siteUrl'      => get_site_url(),
            'pageUrl'      => home_url(add_query_arg([])),
            'types' => array_map(
                function ($code, $t) {
                    return ['code' => $code, 'label' => $t['label'], 'icon' => LSM_Ticket_Types::icon($t['icon'])];
                },
                array_keys(LSM_Ticket_Types::types()),
                array_values(LSM_Ticket_Types::types())
            ),
            'priorities' => array_map(
                function ($code, $p) { return ['code' => $code, 'label' => $p['label']]; },
                array_keys(LSM_Ticket_Types::priorities()),
                array_values(LSM_Ticket_Types::priorities())
            ),
            'defaultPriority' => LSM_Ticket_Types::default_priority(),
            'i18n'         => [
                'title'           => __('Support', 'landeseiten-maintenance'),
                'newTicket'       => __('New Ticket', 'landeseiten-maintenance'),
                'myTickets'       => __('My Tickets', 'landeseiten-maintenance'),
                'type'            => __('Type', 'landeseiten-maintenance'),
                'priority'        => __('Priority', 'landeseiten-maintenance'),
                'subject'         => __('Subject', 'landeseiten-maintenance'),
                'message'         => __('Message', 'landeseiten-maintenance'),
                'attachments'     => __('Attachments (max 5, images/PDF)', 'landeseiten-maintenance'),
                'screenshot'      => __('Screenshot', 'landeseiten-maintenance'),
                'captureShot'     => __('Capture', 'landeseiten-maintenance'),
                'modeView'        => __('Current view', 'landeseiten-maintenance'),
                'modeDesktop'     => __('Full page — Desktop (1920px)', 'landeseiten-maintenance'),
                'modeLaptop'      => __('Full page — Laptop (1366px)', 'landeseiten-maintenance'),
                'modeTablet'      => __('Full page — Tablet (768px)', 'landeseiten-maintenance'),
                'modePhone'       => __('Full page — Phone (390px)', 'landeseiten-maintenance'),
                'attachShot'      => __('Attach screenshot', 'landeseiten-maintenance'),
                'removeShot'      => __('Remove screenshot', 'landeseiten-maintenance'),
                'annotateHint'    => __('Highlight the problem: draw, circle or add text, then attach.', 'landeseiten-maintenance'),
                'toolCrop'        => __('Crop', 'landeseiten-maintenance'),
                'toolRect'        => __('Rectangle', 'landeseiten-maintenance'),
                'toolPen'         => __('Pen', 'landeseiten-maintenance'),
                'toolText'        => __('Text', 'landeseiten-maintenance'),
                'undo'            => __('Undo', 'landeseiten-maintenance'),
                'textPrompt'      => __('Enter text:', 'landeseiten-maintenance'),
                'screenshotFailed'=> __('Screenshot failed on this page.', 'landeseiten-maintenance'),
                'send'            => __('Send ticket', 'landeseiten-maintenance'),
                'sent'            => __('Ticket sent!', 'landeseiten-maintenance'),
                'sendReply'       => __('Send reply', 'landeseiten-maintenance'),
                'yourReply'       => __('Your reply', 'landeseiten-maintenance'),
                'replyPlaceholder'=> __('Write a reply…', 'landeseiten-maintenance'),
                'back'            => __('Back', 'landeseiten-maintenance'),
                'cancel'          => __('Cancel', 'landeseiten-maintenance'),
                'noTickets'       => __('No tickets yet.', 'landeseiten-maintenance'),
                'originalMessage' => __('Original request', 'landeseiten-maintenance'),
                'fillRequired'    => __('Please fill in subject and message.', 'landeseiten-maintenance'),
                'genericError'    => __('Something went wrong. Please try again.', 'landeseiten-maintenance'),
            ],
        ]);
    }

    /**
     * Widget mount point (front-end footer).
     */
    public function render_ticket_widget_root() {
        if (!$this->ticket_widget_allowed()) {
            return;
        }
        echo '<div id="lsm-ticket-widget-root"></div>';
    }

    /**
     * Widget on the plugin admin page only.
     */
    public function render_ticket_widget_root_admin() {
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if (!$screen || strpos((string) $screen->id, 'landeseiten-maintenance') === false) {
            return;
        }
        if (!$this->ticket_widget_allowed()) {
            return;
        }
        // Admin page: assets aren't enqueued by wp_enqueue_scripts, do it inline.
        $this->enqueue_ticket_widget();
        wp_print_styles(['lsm-ticket-ui', 'lsm-ticket-widget']);
        wp_print_scripts(['lsm-html2canvas', 'lsm-ticket-widget']);
        echo '<div id="lsm-ticket-widget-root"></div>';
    }

    /**
     * Plugin activation.
     */
    public function activate() {
        // Create options
        $default_settings = [
            'api_key'           => wp_generate_password(32, false),
            'token_lifetime'    => 300,
            'enable_support'    => true,
            'support_email'     => get_option('admin_email'),
            'maintenance_mode'  => false,
            'maintenance_title' => __('Site Under Maintenance', 'landeseiten-maintenance'),
            'maintenance_message' => __('We are performing scheduled maintenance. Please check back soon.', 'landeseiten-maintenance'),
        ];

        if (!get_option('lsm_settings')) {
            add_option('lsm_settings', $default_settings);
        }

        // Store disabled plugins state
        if (!get_option('lsm_disabled_plugins')) {
            add_option('lsm_disabled_plugins', []);
        }

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation.
     */
    public function deactivate() {
        // Disable maintenance mode on deactivation
        $settings = get_option('lsm_settings', []);
        $settings['maintenance_mode'] = false;
        update_option('lsm_settings', $settings);

        flush_rewrite_rules();
    }

    /**
     * Get plugin settings.
     *
     * @param string|null $key Setting key.
     * @return mixed
     */
    public static function get_setting($key = null) {
        $settings = get_option('lsm_settings', []);
        
        if ($key) {
            return $settings[$key] ?? null;
        }
        
        return $settings;
    }

    /**
     * Update plugin setting.
     *
     * @param string $key Setting key.
     * @param mixed $value Setting value.
     */
    public static function update_setting($key, $value) {
        $settings = get_option('lsm_settings', []);
        $settings[$key] = $value;
        update_option('lsm_settings', $settings);
    }
}

/**
 * Get plugin instance.
 *
 * @return Landeseiten_Maintenance
 */
function lsm() {
    return Landeseiten_Maintenance::instance();
}

// Initialize plugin
lsm();

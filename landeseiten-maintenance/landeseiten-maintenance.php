<?php
/**
 * Plugin Name: Landeseiten Maintenance
 * Description: Remote site management, SSO login, health monitoring, security scanning, and client support for Landeseiten managed WordPress sites.
 * Version: 2.3.0
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
define('LSM_VERSION', '2.3.0');
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
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-maintenance-mode.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-backup.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-php-errors.php';
        require_once LSM_PLUGIN_DIR . 'includes/class-lsm-security-scanner.php';
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
        
        // Admin bar support button - using priority 999 to place at end
        add_action('admin_bar_menu', [$this, 'add_support_button'], 999);
        add_action('wp_footer', [$this, 'render_support_modal']);
        add_action('admin_footer', [$this, 'render_support_modal']);
        
        // Enqueue scripts
        add_action('wp_enqueue_scripts', [$this, 'enqueue_frontend_assets']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);

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

        // REST API: Ensure LSM endpoints always work regardless of other security plugins
        // Note: We do NOT block the REST API globally anymore - our endpoints have their own auth.
        // This filter ONLY clears blocks from other plugins for our namespace.
        add_filter('rest_authentication_errors', function($result) {
            // If no error, nothing to do
            if (!is_wp_error($result) && $result !== false) {
                return $result;
            }

            // Check if this is an LSM request - if so, clear any errors from other plugins
            $is_lsm_request = false;

            if (isset($_SERVER['REQUEST_URI'])) {
                $uri = urldecode($_SERVER['REQUEST_URI']);
                if (strpos($uri, '/lsm/v1') !== false || strpos($uri, 'wp-json/lsm/') !== false) {
                    $is_lsm_request = true;
                }
            }

            if (!$is_lsm_request && isset($_GET['rest_route'])) {
                if (strpos(urldecode($_GET['rest_route']), '/lsm/v1') !== false) {
                    $is_lsm_request = true;
                }
            }

            if (!$is_lsm_request && isset($_SERVER['PATH_INFO'])) {
                if (strpos($_SERVER['PATH_INFO'], '/lsm/v1') !== false) {
                    $is_lsm_request = true;
                }
            }

            if (!$is_lsm_request && isset($_SERVER['REDIRECT_URL'])) {
                if (strpos($_SERVER['REDIRECT_URL'], '/lsm/v1') !== false) {
                    $is_lsm_request = true;
                }
            }

            // For LSM requests: clear any authentication errors
            if ($is_lsm_request) {
                return null;
            }

            return $result;
        }, 999);

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

    /**
     * Initialize REST API.
     */
    public function init_rest_api() {
        $api = new LSM_API();
        $api->register_routes();
    }

    /**
     * Add support button to admin bar.
     *
     * @param WP_Admin_Bar $wp_admin_bar Admin bar instance.
     */
    public function add_support_button($wp_admin_bar) {
        // Only show for logged-in users
        if (!is_user_logged_in()) {
            return;
        }

        $wp_admin_bar->add_node([
            'id'    => 'lsm-support',
            'title' => '<span class="ab-label">' . __('Landeseiten Support', 'landeseiten-maintenance') . '</span>',
            'href'  => admin_url('admin.php?page=landeseiten-maintenance#support-form'),
            'meta'  => [
                'class'  => 'lsm-support-link',
                'title'  => __('Open support form', 'landeseiten-maintenance'),
                'target' => '_blank',
            ],
        ]);
    }

    /**
     * Render support modal.
     */
    public function render_support_modal() {
        if (!is_user_logged_in()) {
            return;
        }

        $current_user = wp_get_current_user();
        $site_url = get_site_url();
        $current_url = isset($_SERVER['REQUEST_URI']) ? $site_url . $_SERVER['REQUEST_URI'] : $site_url;
        
        ?>
        <div id="lsm-support-modal" class="lsm-modal" style="display:none;">
            <div class="lsm-modal-overlay"></div>
            <div class="lsm-modal-container">
                <div class="lsm-modal-header">
                    <div class="lsm-modal-logo">
                        <img src="<?php echo LSM_PLUGIN_URL; ?>assets/images/logo-light.png" alt="Landeseiten" height="40">
                    </div>
                    <h2><?php _e('Landeseiten Support', 'landeseiten-maintenance'); ?></h2>
                    <button class="lsm-modal-close" aria-label="<?php esc_attr_e('Close', 'landeseiten-maintenance'); ?>">&times;</button>
                </div>
                <div class="lsm-modal-body">
                    <p class="lsm-modal-intro"><?php _e('Describe your issue or request below. Our team will get back to you as soon as possible.', 'landeseiten-maintenance'); ?></p>
                    
                    <form id="lsm-support-form">
                        <div class="lsm-form-group">
                            <label for="lsm-issue-type"><?php _e('Issue Type', 'landeseiten-maintenance'); ?></label>
                            <select id="lsm-issue-type" name="issue_type" required>
                                <option value=""><?php _e('Select type...', 'landeseiten-maintenance'); ?></option>
                                <option value="bug"><?php _e('Bug / Error', 'landeseiten-maintenance'); ?></option>
                                <option value="content"><?php _e('Content Change Request', 'landeseiten-maintenance'); ?></option>
                                <option value="design"><?php _e('Design Change Request', 'landeseiten-maintenance'); ?></option>
                                <option value="feature"><?php _e('New Feature Request', 'landeseiten-maintenance'); ?></option>
                                <option value="question"><?php _e('Question', 'landeseiten-maintenance'); ?></option>
                                <option value="urgent"><?php _e('Urgent Issue', 'landeseiten-maintenance'); ?></option>
                            </select>
                        </div>
                        
                        <div class="lsm-form-group">
                            <label for="lsm-subject"><?php _e('Subject', 'landeseiten-maintenance'); ?></label>
                            <input type="text" id="lsm-subject" name="subject" placeholder="<?php esc_attr_e('Brief description of your issue...', 'landeseiten-maintenance'); ?>" required>
                        </div>
                        
                        <div class="lsm-form-group">
                            <label for="lsm-message"><?php _e('Description', 'landeseiten-maintenance'); ?></label>
                            <textarea id="lsm-message" name="message" rows="5" placeholder="<?php esc_attr_e('Please describe your issue in detail. Include steps to reproduce if applicable...', 'landeseiten-maintenance'); ?>" required></textarea>
                        </div>
                        
                        <div class="lsm-form-group">
                            <label for="lsm-problem-page"><?php _e('Problematic Page', 'landeseiten-maintenance'); ?></label>
                            <select id="lsm-problem-page" name="problem_page">
                                <option value=""><?php _e('Select a page...', 'landeseiten-maintenance'); ?></option>
                                <option value="<?php echo esc_attr(home_url('/')); ?>"><?php _e('Homepage', 'landeseiten-maintenance'); ?></option>
                                <?php
                                // Get pages - limit to 20 for performance
                                $pages = get_pages(['number' => 20, 'sort_column' => 'menu_order']);
                                if (!empty($pages)) {
                                    foreach ($pages as $page) {
                                        echo '<option value="' . esc_attr(get_permalink($page->ID)) . '">' . esc_html($page->post_title) . '</option>';
                                    }
                                }
                                ?>
                                <option value="other"><?php _e('Other (specify in description)', 'landeseiten-maintenance'); ?></option>
                            </select>
                        </div>
                        
                        <div class="lsm-form-group">
                            <label><?php _e('Your Email', 'landeseiten-maintenance'); ?></label>
                            <input type="email" value="<?php echo esc_attr($current_user->user_email); ?>" readonly class="lsm-input-readonly">
                        </div>
                        
                        <input type="hidden" name="user_email" value="<?php echo esc_attr($current_user->user_email); ?>">
                        <input type="hidden" name="user_name" value="<?php echo esc_attr($current_user->display_name); ?>">
                        <input type="hidden" name="page_url" value="<?php echo esc_attr($current_url); ?>">
                        <input type="hidden" name="site_url" value="<?php echo esc_attr($site_url); ?>">
                        <?php wp_nonce_field('lsm_support_nonce', 'lsm_nonce'); ?>
                        
                        <div class="lsm-form-actions">
                            <button type="button" class="lsm-btn lsm-btn-secondary lsm-modal-cancel"><?php _e('Cancel', 'landeseiten-maintenance'); ?></button>
                            <button type="submit" class="lsm-btn lsm-btn-primary">
                                <span class="lsm-btn-text"><?php _e('Send Request', 'landeseiten-maintenance'); ?></span>
                                <span class="lsm-btn-loading" style="display:none;"><?php _e('Sending...', 'landeseiten-maintenance'); ?></span>
                            </button>
                        </div>
                    </form>
                    
                    <div id="lsm-support-success" style="display:none;">
                        <div class="lsm-success-message">
                            <div class="lsm-success-icon">✓</div>
                            <h3><?php _e('Request Sent!', 'landeseiten-maintenance'); ?></h3>
                            <p><?php _e('We\'ve received your support request and will get back to you shortly.', 'landeseiten-maintenance'); ?></p>
                            <button class="lsm-btn lsm-btn-primary lsm-modal-close-success"><?php _e('Close', 'landeseiten-maintenance'); ?></button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Enqueue frontend assets.
     */
    public function enqueue_frontend_assets() {
        if (!is_user_logged_in()) {
            return;
        }

        wp_enqueue_style(
            'lsm-support',
            LSM_PLUGIN_URL . 'assets/css/support.css',
            [],
            LSM_VERSION
        );

        wp_enqueue_script(
            'lsm-support',
            LSM_PLUGIN_URL . 'assets/js/support.js',
            ['jquery'],
            LSM_VERSION,
            true
        );

        wp_localize_script('lsm-support', 'lsmSupport', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('lsm_support_nonce'),
            'strings' => [
                'error'   => __('An error occurred. Please try again.', 'landeseiten-maintenance'),
                'success' => __('Request sent successfully!', 'landeseiten-maintenance'),
            ],
        ]);
    }

    /**
     * Enqueue admin assets.
     */
    public function enqueue_admin_assets($hook) {
        // Support modal on all admin pages
        if (is_user_logged_in()) {
            wp_enqueue_style(
                'lsm-support',
                LSM_PLUGIN_URL . 'assets/css/support.css',
                [],
                LSM_VERSION
            );

            wp_enqueue_script(
                'lsm-support',
                LSM_PLUGIN_URL . 'assets/js/support.js',
                ['jquery'],
                LSM_VERSION,
                true
            );

            wp_localize_script('lsm-support', 'lsmSupport', [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce('lsm_support_nonce'),
            ]);
        }

        // Admin page styles
        if (strpos($hook, 'landeseiten') !== false) {
            wp_enqueue_style(
                'lsm-admin',
                LSM_PLUGIN_URL . 'admin/css/admin.css',
                [],
                LSM_VERSION
            );

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

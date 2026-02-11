<?php
/**
 * Admin dashboard for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Admin class.
 */
class LSM_Admin {

    /**
     * Constructor.
     */
    public function __construct() {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'handle_api_key_save']);
        add_action('admin_notices', [$this, 'hide_admin_notices'], 1);
        add_action('all_admin_notices', [$this, 'hide_admin_notices'], 1);
    }
    
    /**
     * Hide admin notices on our plugin page.
     */
    public function hide_admin_notices() {
        $screen = get_current_screen();
        if ($screen && strpos($screen->id, 'landeseiten') !== false) {
            remove_all_actions('admin_notices');
            remove_all_actions('all_admin_notices');
        }
    }

    /**
     * Add admin menu.
     */
    public function add_menu() {
        add_menu_page(
            __('Landeseiten Maintenance', 'landeseiten-maintenance'),
            __('Landeseiten', 'landeseiten-maintenance'),
            'manage_options',
            'landeseiten-maintenance',
            [$this, 'render_page'],
            'dashicons-admin-site-alt3',
            25
        );
    }

    /**
     * Register settings.
     */
    public function register_settings() {
        register_setting('lsm_settings', 'lsm_settings', [
            'sanitize_callback' => [$this, 'sanitize_settings'],
        ]);
    }

    /**
     * Sanitize settings.
     *
     * @param array $input Input data.
     * @return array Sanitized data.
     */
    public function sanitize_settings($input) {
        $sanitized = [];

        $sanitized['api_key'] = sanitize_text_field($input['api_key'] ?? '');
        $sanitized['token_lifetime'] = absint($input['token_lifetime'] ?? 300);
        $sanitized['enable_support'] = !empty($input['enable_support']);
        $sanitized['support_email'] = sanitize_email($input['support_email'] ?? '');
        $sanitized['maintenance_mode'] = !empty($input['maintenance_mode']);
        $sanitized['maintenance_title'] = sanitize_text_field($input['maintenance_title'] ?? '');
        $sanitized['maintenance_message'] = sanitize_textarea_field($input['maintenance_message'] ?? '');
        $sanitized['maintenance_logo'] = esc_url_raw($input['maintenance_logo'] ?? '');
        $sanitized['maintenance_bg_color'] = sanitize_hex_color($input['maintenance_bg_color'] ?? '#0f172a');
        $sanitized['maintenance_text_color'] = sanitize_hex_color($input['maintenance_text_color'] ?? '#ffffff');
        $sanitized['maintenance_accent_color'] = sanitize_hex_color($input['maintenance_accent_color'] ?? '#667eea');

        return $sanitized;
    }

    /**
     * Handle API key save from separate form.
     */
    public function handle_api_key_save() {
        if (!isset($_POST['lsm_save_api_key'])) {
            return;
        }
        
        if (!wp_verify_nonce($_POST['lsm_api_key_nonce'] ?? '', 'lsm_save_api_key')) {
            return;
        }
        
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $new_api_key = sanitize_text_field($_POST['lsm_api_key'] ?? '');
        
        if (!empty($new_api_key)) {
            $settings = Landeseiten_Maintenance::get_setting();
            $settings['api_key'] = $new_api_key;
            update_option('lsm_settings', $settings);
            
            // Redirect to avoid resubmission
            wp_redirect(admin_url('admin.php?page=landeseiten-maintenance&api_key_saved=1'));
            exit;
        }
    }

    /**
     * Render admin page.
     */
    public function render_page() {
        $settings = Landeseiten_Maintenance::get_setting();
        $health = new LSM_Health();
        $health_data = $health->get_health_data();
        $activity_log = LSM_Logger::get_log(10);
        ?>
        <div class="wrap lsm-admin">
            <div class="lsm-header">
            <div class="lsm-header-content">
                    <div class="lsm-logo">
                        <img src="<?php echo LSM_PLUGIN_URL; ?>assets/images/logo-light.png" alt="Landeseiten" height="48">
                    </div>
                    <div class="lsm-header-text">
                        <h1><?php _e('Landeseiten Maintenance', 'landeseiten-maintenance'); ?></h1>
                        <p class="lsm-version">v<?php echo LSM_VERSION; ?></p>
                    </div>
                </div>
                <div class="lsm-header-status">
                    <?php if ($settings['maintenance_mode'] ?? false) : ?>
                        <span class="lsm-badge lsm-badge-warning"><?php _e('Maintenance Mode Active', 'landeseiten-maintenance'); ?></span>
                    <?php else : ?>
                        <span class="lsm-badge lsm-badge-success"><?php _e('Site Online', 'landeseiten-maintenance'); ?></span>
                    <?php endif; ?>
                </div>
            </div>

            <div class="lsm-grid">
                <!-- API Key Card -->
                <div class="lsm-card lsm-card-wide">
                    <div class="lsm-card-header">
                        <h2><span class="dashicons dashicons-admin-network"></span> <?php _e('API Connection', 'landeseiten-maintenance'); ?></h2>
                    </div>
                    <div class="lsm-card-body">
                        <form method="post" action="" id="lsm-api-key-form">
                            <div class="lsm-api-key-display">
                                <label><?php _e('API Key', 'landeseiten-maintenance'); ?></label>
                                <div class="lsm-key-wrapper">
                                    <input type="text" id="lsm-api-key" name="lsm_api_key" value="<?php echo esc_attr($settings['api_key'] ?? ''); ?>" class="lsm-input">
                                    <button type="button" class="lsm-btn lsm-btn-secondary lsm-copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('lsm-api-key').value); this.textContent='<?php echo esc_js(__('Copied!', 'landeseiten-maintenance')); ?>'; setTimeout(() => this.textContent='<?php echo esc_js(__('Copy', 'landeseiten-maintenance')); ?>', 2000);">
                                        <?php _e('Copy', 'landeseiten-maintenance'); ?>
                                    </button>
                                    <button type="button" class="lsm-btn lsm-btn-secondary" id="lsm-regenerate-key">
                                        <?php _e('Regenerate', 'landeseiten-maintenance'); ?>
                                    </button>
                                </div>
                                <p class="lsm-help"><?php _e('Use this key to connect from your Landeseiten Dashboard. You can edit or regenerate the key.', 'landeseiten-maintenance'); ?></p>
                                <div class="lsm-key-actions">
                                    <?php wp_nonce_field('lsm_save_api_key', 'lsm_api_key_nonce'); ?>
                                    <button type="submit" name="lsm_save_api_key" class="lsm-btn lsm-btn-primary lsm-btn-sm"><?php _e('Save API Key', 'landeseiten-maintenance'); ?></button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="lsm-card">
                    <div class="lsm-card-header">
                        <h2><span class="dashicons dashicons-chart-bar"></span> <?php _e('System Status', 'landeseiten-maintenance'); ?></h2>
                    </div>
                    <div class="lsm-card-body">
                        <div class="lsm-stats">
                            <div class="lsm-stat">
                                <span class="lsm-stat-value"><?php echo esc_html($health_data['wordpress']['version']); ?></span>
                                <span class="lsm-stat-label"><?php _e('WordPress', 'landeseiten-maintenance'); ?></span>
                            </div>
                            <div class="lsm-stat">
                                <span class="lsm-stat-value"><?php echo esc_html($health_data['php']['version']); ?></span>
                                <span class="lsm-stat-label"><?php _e('PHP', 'landeseiten-maintenance'); ?></span>
                            </div>
                            <div class="lsm-stat">
                                <span class="lsm-stat-value"><?php echo esc_html($health_data['plugins']['total']); ?></span>
                                <span class="lsm-stat-label"><?php _e('Plugins', 'landeseiten-maintenance'); ?></span>
                            </div>
                            <div class="lsm-stat">
                                <span class="lsm-stat-value lsm-stat-<?php echo $health_data['ssl']['enabled'] ? 'success' : 'warning'; ?>">
                                    <?php echo $health_data['ssl']['enabled'] ? '✓' : '✗'; ?>
                                </span>
                                <span class="lsm-stat-label"><?php _e('SSL', 'landeseiten-maintenance'); ?></span>
                            </div>
                        </div>
                        <?php if ($health_data['plugins']['outdated_count'] > 0) : ?>
                            <div class="lsm-alert lsm-alert-warning">
                                <?php printf(
                                    _n('%d plugin needs updating', '%d plugins need updating', $health_data['plugins']['outdated_count'], 'landeseiten-maintenance'),
                                    $health_data['plugins']['outdated_count']
                                ); ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Settings Card -->
                <div class="lsm-card">
                    <div class="lsm-card-header">
                        <h2><span class="dashicons dashicons-admin-generic"></span> <?php _e('Settings', 'landeseiten-maintenance'); ?></h2>
                    </div>
                    <div class="lsm-card-body">
                        <form method="post" action="options.php">
                            <?php settings_fields('lsm_settings'); ?>

                            <div class="lsm-form-group">
                                <label><?php _e('Token Lifetime (seconds)', 'landeseiten-maintenance'); ?></label>
                                <input type="number" name="lsm_settings[token_lifetime]" value="<?php echo esc_attr($settings['token_lifetime'] ?? 300); ?>" min="60" max="900" class="lsm-input">
                            </div>

                            <div class="lsm-form-group">
                                <label class="lsm-checkbox">
                                    <input type="checkbox" name="lsm_settings[enable_support]" value="1" <?php checked(!empty($settings['enable_support'])); ?>>
                                    <?php _e('Enable Support Button in Admin Bar', 'landeseiten-maintenance'); ?>
                                </label>
                            </div>

                            <!-- Hidden fields to preserve other settings -->
                            <input type="hidden" name="lsm_settings[api_key]" value="<?php echo esc_attr($settings['api_key'] ?? ''); ?>">
                            <input type="hidden" name="lsm_settings[maintenance_mode]" value="<?php echo !empty($settings['maintenance_mode']) ? '1' : '0'; ?>">
                            <input type="hidden" name="lsm_settings[maintenance_title]" value="<?php echo esc_attr($settings['maintenance_title'] ?? ''); ?>">
                            <input type="hidden" name="lsm_settings[maintenance_message]" value="<?php echo esc_attr($settings['maintenance_message'] ?? ''); ?>">

                            <button type="submit" class="lsm-btn lsm-btn-primary"><?php _e('Save Settings', 'landeseiten-maintenance'); ?></button>
                        </form>
                    </div>
                </div>

                <!-- Two-column row for Support and Maintenance -->
                <div class="lsm-row">
                    <!-- Contact Support Card -->
                    <div class="lsm-card" id="support-form">
                        <div class="lsm-card-header">
                            <h2><span class="dashicons dashicons-sos"></span> <?php _e('Contact Support', 'landeseiten-maintenance'); ?></h2>
                        </div>
                        <div class="lsm-card-body">
                            <p class="lsm-help"><?php _e('Describe your issue or request below. Our team will get back to you as soon as possible.', 'landeseiten-maintenance'); ?></p>
                            
                            <form id="lsm-inline-support-form" class="lsm-support-form">
                                <div class="lsm-form-group">
                                    <label for="lsm-issue-type"><?php _e('Issue Type', 'landeseiten-maintenance'); ?></label>
                                    <select id="lsm-issue-type" name="issue_type" class="lsm-input" required>
                                        <option value=""><?php _e('Select type...', 'landeseiten-maintenance'); ?></option>
                                        <option value="bug"><?php _e('🐛 Bug / Error', 'landeseiten-maintenance'); ?></option>
                                        <option value="content"><?php _e('📝 Content Change', 'landeseiten-maintenance'); ?></option>
                                        <option value="design"><?php _e('🎨 Design Change', 'landeseiten-maintenance'); ?></option>
                                        <option value="feature"><?php _e('✨ New Feature', 'landeseiten-maintenance'); ?></option>
                                        <option value="question"><?php _e('❓ Question', 'landeseiten-maintenance'); ?></option>
                                        <option value="urgent"><?php _e('🚨 URGENT', 'landeseiten-maintenance'); ?></option>
                                    </select>
                                </div>

                                <div class="lsm-form-group">
                                    <label for="lsm-subject"><?php _e('Subject', 'landeseiten-maintenance'); ?></label>
                                    <input type="text" id="lsm-subject" name="subject" class="lsm-input" placeholder="<?php esc_attr_e('Brief description of your issue...', 'landeseiten-maintenance'); ?>" required>
                                </div>
                                
                                <div class="lsm-form-group">
                                    <label for="lsm-message"><?php _e('Description', 'landeseiten-maintenance'); ?></label>
                                    <textarea id="lsm-message" name="message" class="lsm-input lsm-textarea" rows="4" placeholder="<?php esc_attr_e('Please describe your issue in detail. Include steps to reproduce if applicable...', 'landeseiten-maintenance'); ?>" required></textarea>
                                </div>

                                <div class="lsm-form-group">
                                    <label for="lsm-problem-page"><?php _e('Problematic Page', 'landeseiten-maintenance'); ?></label>
                                    <select id="lsm-problem-page" name="problem_page" class="lsm-input">
                                        <option value=""><?php _e('Select a page...', 'landeseiten-maintenance'); ?></option>
                                        <option value="<?php echo esc_attr(home_url('/')); ?>"><?php _e('Homepage', 'landeseiten-maintenance'); ?></option>
                                        <?php
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
                                    <input type="email" value="<?php echo esc_attr(wp_get_current_user()->user_email); ?>" class="lsm-input" readonly>
                                </div>
                                
                                <input type="hidden" name="user_email" value="<?php echo esc_attr(wp_get_current_user()->user_email); ?>">
                                <input type="hidden" name="user_name" value="<?php echo esc_attr(wp_get_current_user()->display_name); ?>">
                                <input type="hidden" name="site_url" value="<?php echo esc_attr(get_site_url()); ?>">
                                <?php wp_nonce_field('lsm_support_nonce', 'lsm_nonce'); ?>
                                
                                <div class="lsm-form-actions lsm-form-actions-row">
                                    <button type="submit" class="lsm-btn lsm-btn-primary">
                                        <span class="lsm-btn-text"><?php _e('Send Request', 'landeseiten-maintenance'); ?></span>
                                        <span class="lsm-btn-loading" style="display: none;"><?php _e('Sending...', 'landeseiten-maintenance'); ?></span>
                                    </button>
                                </div>
                                
                                <div id="lsm-support-success" style="display: none;" class="lsm-notice lsm-notice-success">
                                    <?php _e('Thank you! Your support request has been sent successfully.', 'landeseiten-maintenance'); ?>
                                </div>
                            </form>
                        </div>
                    </div>

                    <!-- Maintenance Mode Card -->
                    <div class="lsm-card">
                        <div class="lsm-card-header">
                            <h2><span class="dashicons dashicons-hammer"></span> <?php _e('Maintenance Mode', 'landeseiten-maintenance'); ?></h2>
                        </div>
                        <div class="lsm-card-body">
                            <p class="lsm-help"><?php _e('Enable maintenance mode to show a custom page to visitors while you work on the site.', 'landeseiten-maintenance'); ?></p>
                            
                            <form method="post" action="options.php" class="lsm-maintenance-form">
                                <?php settings_fields('lsm_settings'); ?>
                                
                                <div class="lsm-form-group">
                                    <label class="lsm-toggle">
                                        <input type="checkbox" name="lsm_settings[maintenance_mode]" value="1" <?php checked(!empty($settings['maintenance_mode'])); ?>>
                                        <span class="lsm-toggle-slider"></span>
                                        <span class="lsm-toggle-label"><?php _e('Enable Maintenance Mode', 'landeseiten-maintenance'); ?></span>
                                    </label>
                                </div>

                                <div class="lsm-form-group">
                                    <label><?php _e('Page Title', 'landeseiten-maintenance'); ?></label>
                                    <input type="text" name="lsm_settings[maintenance_title]" value="<?php echo esc_attr($settings['maintenance_title'] ?? __('Site Under Maintenance', 'landeseiten-maintenance')); ?>" class="lsm-input">
                                </div>

                                <div class="lsm-form-group">
                                    <label><?php _e('Message', 'landeseiten-maintenance'); ?></label>
                                    <textarea name="lsm_settings[maintenance_message]" rows="3" class="lsm-input"><?php echo esc_textarea($settings['maintenance_message'] ?? __('We are performing scheduled maintenance. Please check back soon.', 'landeseiten-maintenance')); ?></textarea>
                                </div>

                                <!-- Preserve other settings -->
                                <input type="hidden" name="lsm_settings[api_key]" value="<?php echo esc_attr($settings['api_key'] ?? ''); ?>">
                                <input type="hidden" name="lsm_settings[support_email]" value="<?php echo esc_attr($settings['support_email'] ?? ''); ?>">
                                <input type="hidden" name="lsm_settings[token_lifetime]" value="<?php echo esc_attr($settings['token_lifetime'] ?? 300); ?>">
                                <input type="hidden" name="lsm_settings[enable_support]" value="<?php echo !empty($settings['enable_support']) ? '1' : '0'; ?>">

                                <div class="lsm-form-actions lsm-form-actions-row">
                                    <button type="submit" class="lsm-btn lsm-btn-primary"><?php _e('Save', 'landeseiten-maintenance'); ?></button>
                                    <a href="<?php echo home_url('/?lsm_preview_maintenance=1'); ?>" target="_blank" class="lsm-btn lsm-btn-secondary"><?php _e('Preview Page', 'landeseiten-maintenance'); ?></a>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Activity Log -->
                <div class="lsm-card lsm-card-wide">
                    <div class="lsm-card-header">
                        <h2><span class="dashicons dashicons-backup"></span> <?php _e('Recent Activity', 'landeseiten-maintenance'); ?></h2>
                    </div>
                    <div class="lsm-card-body">
                        <?php if (empty($activity_log)) : ?>
                            <p class="lsm-empty"><?php _e('No activity recorded yet.', 'landeseiten-maintenance'); ?></p>
                        <?php else : ?>
                            <table class="lsm-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('Action', 'landeseiten-maintenance'); ?></th>
                                        <th><?php _e('Status', 'landeseiten-maintenance'); ?></th>
                                        <th><?php _e('Time', 'landeseiten-maintenance'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($activity_log as $log) : ?>
                                        <tr>
                                            <td><?php echo esc_html($log['action']); ?></td>
                                            <td>
                                                <span class="lsm-badge lsm-badge-<?php echo esc_attr($log['status']); ?>">
                                                    <?php echo esc_html($log['status']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo esc_html($log['timestamp']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
}

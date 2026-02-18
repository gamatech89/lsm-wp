<?php
/**
 * SSO Authentication class for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Auth class.
 */
class LSM_Auth {

    /**
     * Token prefix.
     */
    const TOKEN_PREFIX = 'lsm_auth_token_';

    /**
     * Default token lifetime (5 minutes).
     */
    const DEFAULT_LIFETIME = 300;

    /**
     * Max token lifetime (15 minutes).
     */
    const MAX_LIFETIME = 900;

    /**
     * Constructor.
     */
    public function __construct() {
        add_action('init', [$this, 'handle_login_request'], 1);
    }

    /**
     * Generate SSO login token.
     *
     * @param string      $role User role.
     * @param int         $expires_in Token lifetime in seconds.
     * @param string|null $bind_ip IP to bind token to.
     * @param string|null $dashboard_user Dashboard user requesting login.
     * @param string|null $email Email of the platform user to log in as.
     * @param string|null $display_name Display name of the platform user.
     * @return array Token data.
     */
    public function generate_login_token($role = 'administrator', $expires_in = 300, $bind_ip = null, $dashboard_user = null, $email = null, $display_name = null) {
        $settings = Landeseiten_Maintenance::get_setting();
        $max_lifetime = $settings['token_lifetime'] ?? self::DEFAULT_LIFETIME;
        $expires_in = min(max(60, $expires_in), min($max_lifetime, self::MAX_LIFETIME));

        $token = wp_generate_password(48, false);
        $expires = time() + $expires_in;

        $token_data = [
            'token'          => $token,
            'role'           => $role,
            'expires'        => $expires,
            'bind_ip'        => $bind_ip,
            'dashboard_user' => $dashboard_user,
            'email'          => $email ? sanitize_email($email) : null,
            'display_name'   => $display_name ? sanitize_text_field($display_name) : null,
            'created'        => time(),
            'used'           => false,
        ];

        // Store directly in database
        global $wpdb;
        $option_name = self::TOKEN_PREFIX . $token;
        
        $wpdb->delete($wpdb->options, ['option_name' => $option_name]);
        $wpdb->insert($wpdb->options, [
            'option_name'  => $option_name,
            'option_value' => maybe_serialize($token_data),
            'autoload'     => 'no',
        ]);

        $login_url = add_query_arg(['lsm_token' => $token], home_url('/'));

        LSM_Logger::log('sso_token_generated', 'success', [
            'role'           => $role,
            'expires_in'     => $expires_in,
            'dashboard_user' => $dashboard_user,
            'email'          => $email,
        ]);

        return [
            'token'      => $token,
            'login_url'  => $login_url,
            'expires'    => $expires,
            'expires_in' => $expires_in,
        ];
    }

    /**
     * Handle login request.
     */
    public function handle_login_request() {
        if (empty($_GET['lsm_token'])) {
            return;
        }

        $token = sanitize_text_field($_GET['lsm_token']);
        $result = $this->validate_and_login($token);

        if (is_wp_error($result)) {
            LSM_Logger::log('sso_login_failed', 'failure', [
                'error' => $result->get_error_message(),
            ]);

            wp_die(
                esc_html($result->get_error_message()),
                __('Login Failed', 'landeseiten-maintenance'),
                ['response' => 403]
            );
        }

        // Success - redirect to admin
        wp_safe_redirect(admin_url());
        exit;
    }

    /**
     * Validate token and login.
     *
     * @param string $token Login token.
     * @return true|WP_Error
     */
    private function validate_and_login($token) {
        global $wpdb;

        $option_name = self::TOKEN_PREFIX . $token;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
            $option_name
        ));

        if (!$row) {
            return new WP_Error('invalid_token', __('Invalid or expired login token.', 'landeseiten-maintenance'));
        }

        $token_data = maybe_unserialize($row->option_value);

        if (!empty($token_data['used'])) {
            return new WP_Error('token_used', __('This login token has already been used.', 'landeseiten-maintenance'));
        }

        if (time() > $token_data['expires']) {
            $wpdb->delete($wpdb->options, ['option_name' => $option_name]);
            return new WP_Error('token_expired', __('Login token has expired.', 'landeseiten-maintenance'));
        }

        // Mark as used
        $token_data['used'] = true;
        $wpdb->update(
            $wpdb->options,
            ['option_value' => maybe_serialize($token_data)],
            ['option_name' => $option_name]
        );

        // Find or create user — prefer email-based lookup for per-user tracking
        $user = $this->get_or_create_admin_user(
            $token_data['role'],
            $token_data['dashboard_user'],
            $token_data['email'] ?? null,
            $token_data['display_name'] ?? null
        );
        if (is_wp_error($user)) {
            return $user;
        }

        // Log in user
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, false);
        do_action('wp_login', $user->user_login, $user);

        LSM_Logger::log('sso_login_success', 'success', [
            'user_id'        => $user->ID,
            'user_login'     => $user->user_login,
            'user_email'     => $user->user_email,
            'dashboard_user' => $token_data['dashboard_user'],
        ]);

        // Schedule token cleanup
        wp_schedule_single_event(time() + 3600, 'lsm_cleanup_token', [$option_name]);

        return true;
    }

    /**
     * Get or create admin user.
     *
     * When email is provided, finds or creates a user with that specific email
     * for per-user activity tracking. Falls back to generic admin for backward
     * compatibility.
     *
     * @param string      $role User role.
     * @param string|null $dashboard_user Dashboard user identifier.
     * @param string|null $email Email to find/create user by.
     * @param string|null $display_name Display name for new user.
     * @return WP_User|WP_Error
     */
    private function get_or_create_admin_user($role, $dashboard_user = null, $email = null, $display_name = null) {
        // If email is provided, find or create user by email (per-user tracking)
        if ($email && is_email($email)) {
            $user = get_user_by('email', $email);
            if ($user) {
                return $user;
            }

            // Create user with that email
            $username = sanitize_user(strtolower(explode('@', $email)[0]), true);
            $base_username = $username;
            $counter = 1;
            while (username_exists($username)) {
                $username = $base_username . '_' . $counter;
                $counter++;
            }

            $password = wp_generate_password(24);
            $user_id = wp_create_user($username, $password, $email);
            if (is_wp_error($user_id)) {
                return $user_id;
            }

            $user = get_user_by('id', $user_id);
            $user->set_role($role ?: 'administrator');

            if ($display_name) {
                wp_update_user([
                    'ID' => $user_id,
                    'display_name' => $display_name,
                ]);
            }

            update_user_meta($user_id, 'lsm_managed_account', true);

            return $user;
        }

        // Fallback: find existing admin (legacy behavior)
        $admins = get_users(['role' => 'administrator', 'number' => 1]);
        if (!empty($admins)) {
            return $admins[0];
        }

        // Create LSM admin user
        $username = 'lsm_admin_' . wp_generate_password(8, false, false);
        $password = wp_generate_password(24);
        $email = 'lsm-admin-' . wp_generate_password(8, false, false) . '@' . parse_url(home_url(), PHP_URL_HOST);

        $user_id = wp_create_user($username, $password, $email);
        if (is_wp_error($user_id)) {
            return $user_id;
        }

        $user = get_user_by('id', $user_id);
        $user->set_role('administrator');

        update_user_meta($user_id, 'lsm_managed_account', true);

        return $user;
    }
}

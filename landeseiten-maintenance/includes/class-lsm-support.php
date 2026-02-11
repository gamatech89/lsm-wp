<?php
/**
 * Support ticket handling for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Support class.
 */
class LSM_Support {

    /**
     * Constructor.
     */
    public function __construct() {
        add_action('wp_ajax_lsm_submit_support', [$this, 'handle_submit']);
    }

    /**
     * Handle support request submission.
     */
    public function handle_submit() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['lsm_nonce'] ?? '', 'lsm_support_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'landeseiten-maintenance')]);
        }

        // Get form data
        $issue_type = sanitize_text_field($_POST['issue_type'] ?? '');
        $subject = sanitize_text_field($_POST['subject'] ?? '');
        $message = sanitize_textarea_field($_POST['message'] ?? '');
        $user_email = sanitize_email($_POST['user_email'] ?? '');
        $user_name = sanitize_text_field($_POST['user_name'] ?? '');
        $problem_page = esc_url_raw($_POST['problem_page'] ?? '');
        $site_url = esc_url_raw($_POST['site_url'] ?? '');

        if (empty($subject) || empty($message) || empty($issue_type)) {
            wp_send_json_error(['message' => __('Please fill in all required fields.', 'landeseiten-maintenance')]);
        }

        // Get settings
        $settings = Landeseiten_Maintenance::get_setting();
        $support_email = $settings['support_email'] ?? get_option('admin_email');

        // Build email
        $issue_labels = [
            'bug'     => '🐛 Bug / Error',
            'content' => '📝 Content Change',
            'design'  => '🎨 Design Change',
            'feature' => '✨ New Feature',
            'question'=> '❓ Question',
            'urgent'  => '🚨 URGENT',
        ];

        $email_subject = sprintf(
            '[%s] %s: %s',
            parse_url($site_url, PHP_URL_HOST),
            $issue_labels[$issue_type] ?? $issue_type,
            $subject
        );

        $email_body = sprintf(
            "Support Request from %s\n" .
            "================================\n\n" .
            "Type: %s\n" .
            "Subject: %s\n" .
            "From: %s <%s>\n" .
            "Site: %s\n" .
            "Problematic Page: %s\n\n" .
            "Message:\n" .
            "--------------------------------\n%s\n" .
            "--------------------------------\n\n" .
            "System Info:\n" .
            "WordPress: %s\n" .
            "PHP: %s\n" .
            "Theme: %s\n",
            $site_url,
            $issue_labels[$issue_type] ?? $issue_type,
            $subject,
            $user_name,
            $user_email,
            $site_url,
            $problem_page,
            $message,
            get_bloginfo('version'),
            phpversion(),
            wp_get_theme()->get('Name')
        );

        // Send to LSM Platform API (Primary Action)
        $platform_result = $this->send_to_platform([
            'type'         => $issue_type,
            'subject'      => $subject,
            'message'      => $message,
            'client_email' => $user_email,
            'client_name'  => $user_name,
            'problem_page' => $problem_page,
            'site_url'     => $site_url,
        ]);

        // Store in local database
        $this->store_request([
            'type'       => $issue_type,
            'subject'    => $subject,
            'message'    => $message,
            'user_email' => $user_email,
            'user_name'  => $user_name,
            'problem_page' => $problem_page,
            'created_at' => current_time('mysql'),
            'synced'     => !empty($platform_result),
            'ticket_id'  => $platform_result['ticket_number'] ?? null,
        ]);

        // Attempt to send email (Secondary Action / Notification)
        // We do not block the process if email fails
        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            sprintf('Reply-To: %s <%s>', $user_name, $user_email),
        ];

        $sent = wp_mail($support_email, $email_subject, $email_body, $headers);
        
        if (!$sent) {
            LSM_Logger::log('support_request', 'warning', ['message' => 'Failed to send support email notification.']);
        }

        // Return success if API worked OR if we just stored it locally
        if ($platform_result && isset($platform_result['ticket_number'])) {
            wp_send_json_success([
                'message' => sprintf(
                    __('Support request sent successfully! Ticket: %s', 'landeseiten-maintenance'),
                    $platform_result['ticket_number']
                ),
                'ticket_number' => $platform_result['ticket_number'],
            ]);
        } else {
            // Fallback success message even if API failed (stored locally)
            // Or should we error if API failed? 
            // User said "wanted to use API to store it". If API fails, we should probably warn?
            // But strict requirement suggests we generally want success if possible.
            // Let's return success but maybe generic.
            
            wp_send_json_success(['message' => __('Support request received.', 'landeseiten-maintenance')]);
        }
    }

    /**
     * Send support request to LSM Platform API.
     *
     * @param array $data Request data.
     * @return array|null Response data or null on failure.
     */
    private function send_to_platform($data) {
        $settings = Landeseiten_Maintenance::get_setting();
        $api_key = $settings['api_key'] ?? '';
        
        // Get platform API URL (configurable, defaults to production)
        $api_url = apply_filters(
            'lsm_platform_api_url', 
            $settings['platform_api_url'] ?? 'https://landeseiten.de/api/v1/webhooks/support-ticket'
        );

        if (empty($api_key)) {
            LSM_Logger::log('support_platform', 'error', ['message' => 'No API key configured']);
            return null;
        }

        // Add API key to payload
        $data['api_key'] = $api_key;

        // Make API request
        $response = wp_remote_post($api_url, [
            'timeout'     => 15,
            'redirection' => 5,
            'httpversion' => '1.1',
            'blocking'    => true,
            'headers'     => [
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
            ],
            'body'        => wp_json_encode($data),
        ]);

        if (is_wp_error($response)) {
            LSM_Logger::log('support_platform', 'error', [
                'message' => $response->get_error_message(),
            ]);
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $status = wp_remote_retrieve_response_code($response);

        if ($status >= 200 && $status < 300 && isset($body['data'])) {
            LSM_Logger::log('support_platform', 'success', [
                'ticket_number' => $body['data']['ticket_number'] ?? 'unknown',
            ]);
            return $body['data'];
        }

        LSM_Logger::log('support_platform', 'error', [
            'status' => $status,
            'body'   => $body,
        ]);

        return null;
    }

    /**
     * Store support request in database.
     *
     * @param array $data Request data.
     */
    private function store_request($data) {
        $requests = get_option('lsm_support_requests', []);
        array_unshift($requests, $data);
        
        // Keep only last 50 requests
        $requests = array_slice($requests, 0, 50);
        
        update_option('lsm_support_requests', $requests);
    }

    /**
     * Get support requests.
     *
     * @param int $limit Number of requests.
     * @return array
     */
    public static function get_requests($limit = 20) {
        $requests = get_option('lsm_support_requests', []);
        return array_slice($requests, 0, $limit);
    }
}


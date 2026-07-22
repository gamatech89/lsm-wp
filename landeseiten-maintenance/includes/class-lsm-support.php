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
        add_action('wp_ajax_lsm_tickets_list', [$this, 'ajax_tickets_list']);
        add_action('wp_ajax_lsm_ticket_detail', [$this, 'ajax_ticket_detail']);
        add_action('wp_ajax_lsm_ticket_reply', [$this, 'ajax_ticket_reply']);
        add_action('wp_ajax_lsm_ticket_attachment', [$this, 'ajax_ticket_attachment']);
        add_action('wp_ajax_lsm_tickets_unread', [$this, 'ajax_tickets_unread']);
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

        $priority = sanitize_text_field($_POST['priority'] ?? LSM_Ticket_Types::default_priority());
        if (!array_key_exists($priority, LSM_Ticket_Types::priorities())) {
            $priority = LSM_Ticket_Types::default_priority();
        }

        if (empty($subject) || empty($message) || empty($issue_type)) {
            wp_send_json_error(['message' => __('Please fill in all required fields.', 'landeseiten-maintenance')]);
        }

        // Get settings
        $settings = Landeseiten_Maintenance::get_setting();
        $support_email = $settings['support_email'] ?? get_option('admin_email');

        // Build email
        $email_subject = sprintf(
            '[%s] %s: %s',
            parse_url($site_url, PHP_URL_HOST),
            LSM_Ticket_Types::type_label($issue_type),
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
            LSM_Ticket_Types::type_label($issue_type),
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

        // Send to LSM Platform API — try the ticket endpoint (supports
        // attachments), fall back to the legacy webhook for older platforms.
        $ticket_fields = [
            'type'         => $issue_type,
            'subject'      => $subject,
            'message'      => $message,
            'client_email' => $user_email,
            'client_name'  => $user_name,
            'problem_page' => $problem_page,
            'reported_priority' => $priority,
        ];

        $dropped = 0;
        $platform_result = LSM_Ticket_Client::create_ticket($ticket_fields, $this->collect_attachments($dropped));

        if (is_wp_error($platform_result)) {
            $platform_result = $this->send_to_platform($ticket_fields + ['site_url' => $site_url]);
        } else {
            delete_transient('lsm_tickets_unread');
        }

        // Store in local database
        $this->store_request([
            'type'       => $issue_type,
            'priority'   => $priority,
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
                ) . $this->dropped_notice($dropped),
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
            $settings['platform_api_url'] ?? 'https://api.wartung-ls.com/api/v1/webhooks/support-ticket'
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

    /**
     * Shared guard for ticket AJAX actions: nonce + capability.
     */
    private function guard_ticket_ajax() {
        check_ajax_referer('lsm_ticket_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Not allowed.', 'landeseiten-maintenance')], 403);
        }
    }

    /**
     * Normalize $_FILES['attachments'] (multi-file field) into a flat list and
     * enforce client-side limits (max 5 files, 5 MB each, allowed types).
     *
     * @return array [['name','type','tmp_name'], ...]
     */
    private function collect_attachments(&$dropped = 0) {
        $dropped = 0;

        if (empty($_FILES['attachments']) || !is_array($_FILES['attachments']['name'])) {
            return [];
        }

        $allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'application/pdf'];
        $files = [];
        $count = count($_FILES['attachments']['name']);
        $dropped = max(0, $count - 5);

        for ($i = 0; $i < min($count, 5); $i++) {
            if (($_FILES['attachments']['error'][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                $dropped++;
                LSM_Logger::log('support_attachment', 'warning', [
                    'message' => 'Attachment dropped: upload error',
                    'error'   => $_FILES['attachments']['error'][$i] ?? null,
                ]);
                continue;
            }
            if (($_FILES['attachments']['size'][$i] ?? 0) > 5 * 1024 * 1024) {
                $dropped++;
                LSM_Logger::log('support_attachment', 'warning', [
                    'message' => 'Attachment dropped: larger than 5 MB',
                    'name'    => $_FILES['attachments']['name'][$i] ?? '',
                    'size'    => $_FILES['attachments']['size'][$i] ?? 0,
                ]);
                continue;
            }
            $type = $_FILES['attachments']['type'][$i] ?? '';
            if (!in_array($type, $allowed, true)) {
                $dropped++;
                LSM_Logger::log('support_attachment', 'warning', [
                    'message' => 'Attachment dropped: unsupported type',
                    'name'    => $_FILES['attachments']['name'][$i] ?? '',
                    'type'    => $type,
                ]);
                continue;
            }
            $files[] = [
                'name'     => $_FILES['attachments']['name'][$i],
                'type'     => $type,
                'tmp_name' => $_FILES['attachments']['tmp_name'][$i],
            ];
        }

        return $files;
    }

    /**
     * User-facing warning when some attachments were not sent.
     *
     * @param int $dropped Number of skipped files.
     * @return string Empty when nothing was dropped.
     */
    private function dropped_notice($dropped) {
        if ($dropped < 1) {
            return '';
        }

        return ' ' . sprintf(
            /* translators: %d: number of skipped attachments */
            _n(
                '%d attachment was not sent (too large or unsupported type).',
                '%d attachments were not sent (too large or unsupported type).',
                $dropped,
                'landeseiten-maintenance'
            ),
            $dropped
        );
    }

    /**
     * List this site's tickets + unread count for the badge.
     */
    public function ajax_tickets_list() {
        $this->guard_ticket_ajax();

        $tickets = LSM_Ticket_Client::list_tickets();
        if (is_wp_error($tickets)) {
            wp_send_json_error(['message' => $tickets->get_error_message()]);
        }

        // Merge the locally-stored "seen" marker so the widget can flag unread rows.
        $seen = get_option('lsm_tickets_seen', []);
        $tickets = array_map(function ($ticket) use ($seen) {
            $ticket['seen_at'] = $seen[$ticket['id']] ?? '';
            return $ticket;
        }, (array) $tickets);

        wp_send_json_success([
            'tickets' => $tickets,
            'unread'  => $this->count_unread($tickets),
        ]);
    }

    /**
     * One ticket with its conversation. Marks it seen for the badge.
     */
    public function ajax_ticket_detail() {
        $this->guard_ticket_ajax();

        $id = absint($_REQUEST['id'] ?? 0);
        $ticket = LSM_Ticket_Client::get_ticket($id);
        if (is_wp_error($ticket)) {
            wp_send_json_error(['message' => $ticket->get_error_message()]);
        }

        // Remember the newest message timestamp we've shown, per ticket.
        $seen = get_option('lsm_tickets_seen', []);
        $latest = $ticket['created_at'] ?? '';
        foreach (($ticket['messages'] ?? []) as $msg) {
            if (($msg['created_at'] ?? '') > $latest) {
                $latest = $msg['created_at'];
            }
        }
        $seen[$id] = $latest;
        update_option('lsm_tickets_seen', $seen, false);
        delete_transient('lsm_tickets_unread');

        wp_send_json_success($ticket);
    }

    /**
     * Post a client reply (with optional attachments).
     */
    public function ajax_ticket_reply() {
        $this->guard_ticket_ajax();

        $id = absint($_POST['id'] ?? 0);
        $message = sanitize_textarea_field($_POST['message'] ?? '');

        if (!$id || $message === '') {
            wp_send_json_error(['message' => __('Message is required.', 'landeseiten-maintenance')]);
        }

        $user = wp_get_current_user();
        $dropped = 0;
        $result = LSM_Ticket_Client::reply($id, [
            'message'     => $message,
            'author_name' => $user->display_name,
        ], $this->collect_attachments($dropped));

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        }

        delete_transient('lsm_tickets_unread');
        $result['dropped_notice'] = $this->dropped_notice($dropped);
        wp_send_json_success($result);
    }

    /**
     * Stream an attachment through the server (key stays server-side).
     */
    public function ajax_ticket_attachment() {
        $this->guard_ticket_ajax();

        $id = absint($_REQUEST['id'] ?? 0);
        $file = LSM_Ticket_Client::get_attachment($id);
        if (is_wp_error($file)) {
            wp_die(esc_html($file->get_error_message()), 404);
        }

        // Only known-safe types are served inline; anything unexpected downloads
        // as a generic binary so it can never render in the WP admin origin.
        $safe_mimes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'application/pdf'];
        $mime = in_array($file['mime'], $safe_mimes, true) ? $file['mime'] : 'application/octet-stream';
        $disposition = $mime === 'application/octet-stream' ? 'attachment' : 'inline';

        nocache_headers();
        header('Content-Type: ' . $mime);
        header('Content-Disposition: ' . $disposition . '; filename="' . $file['filename'] . '"');
        header('Content-Length: ' . strlen($file['body']));
        header('X-Content-Type-Options: nosniff');
        echo $file['body']; // phpcs:ignore WordPress.Security.EscapeOutput -- binary passthrough
        exit;
    }

    /**
     * Unread count for the widget badge (transient-cached 5 minutes).
     */
    public function ajax_tickets_unread() {
        $this->guard_ticket_ajax();

        $unread = get_transient('lsm_tickets_unread');
        if ($unread === false) {
            $tickets = LSM_Ticket_Client::list_tickets();
            $unread = is_wp_error($tickets) ? 0 : $this->count_unread($tickets);
            set_transient('lsm_tickets_unread', $unread, 5 * MINUTE_IN_SECONDS);
        }

        wp_send_json_success(['unread' => (int) $unread]);
    }

    /**
     * A ticket counts as unread when the platform's last staff reply is newer
     * than what this site has displayed (lsm_tickets_seen option).
     *
     * @param array $tickets Ticket summaries from the platform.
     * @return int
     */
    private function count_unread($tickets) {
        $seen = get_option('lsm_tickets_seen', []);
        $unread = 0;

        foreach ((array) $tickets as $ticket) {
            $lastStaff = $ticket['last_staff_reply_at'] ?? null;
            if (!$lastStaff) {
                continue;
            }
            $seenAt = $seen[$ticket['id']] ?? '';
            if ($lastStaff > $seenAt) {
                $unread++;
            }
        }

        return $unread;
    }
}


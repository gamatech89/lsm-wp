<?php
/**
 * HTTP client for the LSM Platform plugin ticket endpoints.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Talks to /api/v1/plugin/support-tickets/* using the site API key
 * in the X-LSM-Key header. The key never leaves the server.
 */
class LSM_Ticket_Client {

    /**
     * Platform API base URL (no trailing slash).
     *
     * @return string
     */
    public static function base_url() {
        $settings = Landeseiten_Maintenance::get_setting();

        return untrailingslashit(apply_filters(
            'lsm_platform_api_base',
            $settings['platform_api_base'] ?? 'https://api.wartung-ls.com/api/v1'
        ));
    }

    /**
     * Common headers.
     *
     * @return array|WP_Error
     */
    private static function headers() {
        $settings = Landeseiten_Maintenance::get_setting();
        $api_key = $settings['api_key'] ?? '';

        if (empty($api_key)) {
            return new WP_Error('lsm_no_key', __('No API key configured.', 'landeseiten-maintenance'));
        }

        return [
            'X-LSM-Key' => $api_key,
            'Accept'    => 'application/json',
        ];
    }

    /**
     * GET a JSON endpoint. Returns the decoded 'data' payload.
     *
     * @param string $path Path after the base URL, e.g. '/plugin/support-tickets'.
     * @return array|WP_Error
     */
    private static function get_json($path) {
        $headers = self::headers();
        if (is_wp_error($headers)) {
            return $headers;
        }

        $response = wp_remote_get(self::base_url() . $path, [
            'timeout' => 15,
            'headers' => $headers,
        ]);

        return self::parse_json($response);
    }

    /**
     * Decode a JSON API response, normalizing errors.
     *
     * @param array|WP_Error $response wp_remote_* result.
     * @return array|WP_Error
     */
    private static function parse_json($response) {
        if (is_wp_error($response)) {
            LSM_Logger::log('ticket_client', 'error', ['message' => $response->get_error_message()]);
            return $response;
        }

        $status = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($status >= 200 && $status < 300 && isset($body['data'])) {
            return $body['data'];
        }

        LSM_Logger::log('ticket_client', 'error', ['status' => $status, 'body' => $body]);

        return new WP_Error(
            'lsm_platform_error',
            $body['message'] ?? sprintf(__('Platform request failed (HTTP %d).', 'landeseiten-maintenance'), $status)
        );
    }

    /**
     * POST multipart/form-data (fields + files) to a path.
     *
     * WP_Http has no native multipart support, so the body is built manually.
     *
     * @param string $path   Endpoint path.
     * @param array  $fields Scalar form fields.
     * @param array  $files  Normalized upload entries: [['name','type','tmp_name'], ...].
     * @return array|WP_Error
     */
    private static function post_multipart($path, $fields, $files = []) {
        $headers = self::headers();
        if (is_wp_error($headers)) {
            return $headers;
        }

        $boundary = 'lsm' . wp_generate_password(24, false);
        $body = '';

        foreach ($fields as $name => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"{$name}\"\r\n\r\n";
            $body .= $value . "\r\n";
        }

        foreach ($files as $file) {
            if (empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
                continue;
            }
            $filename = sanitize_file_name($file['name']);
            $mime = $file['type'] ?: 'application/octet-stream';
            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"attachments[]\"; filename=\"{$filename}\"\r\n";
            $body .= "Content-Type: {$mime}\r\n\r\n";
            $body .= file_get_contents($file['tmp_name']) . "\r\n";
        }

        $body .= "--{$boundary}--\r\n";

        $headers['Content-Type'] = 'multipart/form-data; boundary=' . $boundary;

        $response = wp_remote_post(self::base_url() . $path, [
            'timeout' => 30,
            'headers' => $headers,
            'body'    => $body,
        ]);

        return self::parse_json($response);
    }

    /**
     * List tickets for this site.
     *
     * @return array|WP_Error
     */
    public static function list_tickets() {
        return self::get_json('/plugin/support-tickets');
    }

    /**
     * Fetch one ticket with its conversation thread.
     *
     * @param int $id Ticket id.
     * @return array|WP_Error
     */
    public static function get_ticket($id) {
        return self::get_json('/plugin/support-tickets/' . absint($id));
    }

    /**
     * Create a ticket (with optional attachments).
     *
     * @param array $fields type, subject, message, client_email, client_name, problem_page, reported_priority.
     * @param array $files  Normalized upload entries.
     * @return array|WP_Error
     */
    public static function create_ticket($fields, $files = []) {
        return self::post_multipart('/plugin/support-tickets', $fields, $files);
    }

    /**
     * Add a client reply to a ticket.
     *
     * @param int   $id     Ticket id.
     * @param array $fields message, author_name.
     * @param array $files  Normalized upload entries.
     * @return array|WP_Error
     */
    public static function reply($id, $fields, $files = []) {
        return self::post_multipart('/plugin/support-tickets/' . absint($id) . '/messages', $fields, $files);
    }

    /**
     * Download an attachment (binary).
     *
     * @param int $id Attachment id.
     * @return array|WP_Error ['body' => raw bytes, 'mime' => string, 'filename' => string]
     */
    public static function get_attachment($id) {
        $headers = self::headers();
        if (is_wp_error($headers)) {
            return $headers;
        }

        $response = wp_remote_get(self::base_url() . '/plugin/support-tickets/attachments/' . absint($id), [
            'timeout' => 30,
            'headers' => $headers,
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $status = wp_remote_retrieve_response_code($response);
        if ($status < 200 || $status >= 300) {
            return new WP_Error('lsm_attachment_error', sprintf(__('Attachment download failed (HTTP %d).', 'landeseiten-maintenance'), $status));
        }

        $disposition = wp_remote_retrieve_header($response, 'content-disposition');
        $filename = 'attachment';
        if ($disposition && preg_match('/filename="?([^";]+)"?/', $disposition, $m)) {
            $filename = sanitize_file_name($m[1]);
        }

        return [
            'body'     => wp_remote_retrieve_body($response),
            'mime'     => wp_remote_retrieve_header($response, 'content-type') ?: 'application/octet-stream',
            'filename' => $filename,
        ];
    }
}

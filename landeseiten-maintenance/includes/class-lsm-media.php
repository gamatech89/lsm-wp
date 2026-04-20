<?php
/**
 * Media Library Scanner for unused images.
 *
 * Scans the WordPress media library and identifies images that are not
 * referenced anywhere on the site (post content, featured images, Elementor,
 * WooCommerce, theme customizer, widgets, etc.).
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Media {

    /**
     * Scan for unused media attachments.
     *
     * @return array {
     *     @type array  $unused      List of unused attachment objects.
     *     @type int    $total_media  Total attachments in library.
     *     @type int    $unused_count Number of unused attachments.
     *     @type int    $total_size   Total file size of unused attachments in bytes.
     *     @type string $scanned_at   ISO 8601 timestamp.
     * }
     */
    public static function scan_unused_media(): array {
        global $wpdb;

        // 1. Get all image attachments
        $attachments = $wpdb->get_results(
            "SELECT ID, post_title, post_name, post_mime_type, post_date, guid
             FROM {$wpdb->posts}
             WHERE post_type = 'attachment'
               AND post_mime_type LIKE 'image/%'
             ORDER BY post_date DESC",
            ARRAY_A
        );

        $total_media = count($attachments);

        if ($total_media === 0) {
            return [
                'unused'       => [],
                'total_media'  => 0,
                'unused_count' => 0,
                'total_size'   => 0,
                'scanned_at'   => gmdate('c'),
            ];
        }

        // 2. Build sets of used attachment IDs
        $used_ids = self::get_used_attachment_ids();

        // 3. Get upload URLs for content scanning
        $used_urls = self::get_used_attachment_urls();

        // 4. Filter unused attachments
        $unused = [];
        $total_size = 0;

        foreach ($attachments as $attachment) {
            $id = (int) $attachment['ID'];

            // Skip if referenced by ID
            if (isset($used_ids[$id])) {
                continue;
            }

            // Check if referenced by URL in content
            $file = get_post_meta($id, '_wp_attached_file', true);
            if ($file && isset($used_urls[$file])) {
                continue;
            }

            // Also check by filename (without path) for partial matches
            $filename = basename($file ?: $attachment['guid']);
            $filename_no_ext = pathinfo($filename, PATHINFO_FILENAME);

            // Check if this filename appears in any content (catches resized variants)
            if (self::is_filename_referenced($filename_no_ext, $id)) {
                continue;
            }

            // This attachment is unused — gather details
            $metadata = wp_get_attachment_metadata($id);
            $file_path = get_attached_file($id);
            $file_size = $file_path && file_exists($file_path) ? filesize($file_path) : 0;

            // Add sizes of generated thumbnails
            if (!empty($metadata['sizes']) && $file_path) {
                $upload_dir = dirname($file_path);
                foreach ($metadata['sizes'] as $size_info) {
                    $thumb_path = $upload_dir . '/' . $size_info['file'];
                    if (file_exists($thumb_path)) {
                        $file_size += filesize($thumb_path);
                    }
                }
            }

            $total_size += $file_size;

            $unused[] = [
                'id'            => $id,
                'title'         => $attachment['post_title'] ?: $filename,
                'filename'      => $filename,
                'url'           => wp_get_attachment_url($id),
                'thumbnail_url' => wp_get_attachment_image_url($id, 'thumbnail') ?: wp_get_attachment_url($id),
                'file_size'     => $file_size,
                'dimensions'    => isset($metadata['width'], $metadata['height'])
                    ? $metadata['width'] . 'x' . $metadata['height']
                    : null,
                'uploaded_date' => $attachment['post_date'],
                'mime_type'     => $attachment['post_mime_type'],
            ];
        }

        return [
            'unused'       => $unused,
            'total_media'  => $total_media,
            'unused_count' => count($unused),
            'total_size'   => $total_size,
            'scanned_at'   => gmdate('c'),
        ];
    }

    /**
     * Delete media attachments permanently.
     *
     * @param array $ids Array of attachment IDs to delete.
     * @return array Results with deleted/failed counts.
     */
    public static function delete_media(array $ids): array {
        $deleted = 0;
        $failed  = 0;
        $freed   = 0;

        foreach ($ids as $id) {
            $id = (int) $id;

            // Verify it's an attachment
            if (get_post_type($id) !== 'attachment') {
                $failed++;
                continue;
            }

            // Calculate file size before deletion
            $file_path = get_attached_file($id);
            $size = 0;
            if ($file_path && file_exists($file_path)) {
                $size += filesize($file_path);

                // Add thumbnail sizes
                $metadata = wp_get_attachment_metadata($id);
                if (!empty($metadata['sizes'])) {
                    $upload_dir = dirname($file_path);
                    foreach ($metadata['sizes'] as $size_info) {
                        $thumb_path = $upload_dir . '/' . $size_info['file'];
                        if (file_exists($thumb_path)) {
                            $size += filesize($thumb_path);
                        }
                    }
                }
            }

            // Delete permanently (true = force delete, skip trash)
            $result = wp_delete_attachment($id, true);

            if ($result) {
                $deleted++;
                $freed += $size;
            } else {
                $failed++;
            }
        }

        LSM_Logger::log('media_cleanup', 'success', [
            'deleted' => $deleted,
            'failed'  => $failed,
            'freed'   => $freed,
        ]);

        return [
            'deleted'     => $deleted,
            'failed'      => $failed,
            'freed_bytes' => $freed,
        ];
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    /**
     * Get a set of all attachment IDs that are referenced somewhere.
     *
     * @return array Associative array with ID as key (for O(1) lookup).
     */
    private static function get_used_attachment_ids(): array {
        global $wpdb;
        $used = [];

        // 1. Featured images (_thumbnail_id)
        $thumbnail_ids = $wpdb->get_col(
            "SELECT DISTINCT meta_value
             FROM {$wpdb->postmeta}
             WHERE meta_key = '_thumbnail_id'
               AND meta_value > 0"
        );
        foreach ($thumbnail_ids as $id) {
            $used[(int) $id] = true;
        }

        // 2. WooCommerce product gallery images
        $gallery_values = $wpdb->get_col(
            "SELECT meta_value
             FROM {$wpdb->postmeta}
             WHERE meta_key = '_product_image_gallery'
               AND meta_value != ''"
        );
        foreach ($gallery_values as $gallery) {
            $ids = array_filter(array_map('intval', explode(',', $gallery)));
            foreach ($ids as $id) {
                $used[$id] = true;
            }
        }

        // 3. Site icon
        $site_icon = (int) get_option('site_icon', 0);
        if ($site_icon > 0) {
            $used[$site_icon] = true;
        }

        // 4. Custom logo
        $custom_logo = (int) get_theme_mod('custom_logo', 0);
        if ($custom_logo > 0) {
            $used[$custom_logo] = true;
        }

        // 5. Header image (stored as attachment ID in some themes)
        $header_image_data = get_theme_mod('header_image_data');
        if (is_object($header_image_data) && !empty($header_image_data->attachment_id)) {
            $used[(int) $header_image_data->attachment_id] = true;
        }

        // 6. Elementor data — extract attachment IDs from JSON
        $elementor_meta = $wpdb->get_col(
            "SELECT meta_value
             FROM {$wpdb->postmeta}
             WHERE meta_key = '_elementor_data'
               AND meta_value != ''"
        );
        foreach ($elementor_meta as $json_string) {
            self::extract_elementor_ids($json_string, $used);
        }

        // 7. Images embedded in post_content via wp-image-{ID} class
        $content_ids = $wpdb->get_col(
            "SELECT DISTINCT CAST(
                SUBSTRING(post_content,
                    LOCATE('wp-image-', post_content) + 9,
                    10
                ) AS UNSIGNED
             )
             FROM {$wpdb->posts}
             WHERE post_content LIKE '%wp-image-%'
               AND post_status IN ('publish', 'draft', 'private', 'pending', 'future')
               AND post_type NOT IN ('revision', 'attachment')"
        );
        foreach ($content_ids as $id) {
            $id = (int) $id;
            if ($id > 0) {
                $used[$id] = true;
            }
        }

        // 8. Also extract from wp:image block data-id attributes
        $block_ids = $wpdb->get_col(
            "SELECT DISTINCT CAST(
                SUBSTRING(post_content,
                    LOCATE('\"id\":', post_content) + 4,
                    10
                ) AS UNSIGNED
             )
             FROM {$wpdb->posts}
             WHERE post_content LIKE '%\"id\":%'
               AND post_content LIKE '%wp:image%'
               AND post_status IN ('publish', 'draft', 'private', 'pending', 'future')
               AND post_type NOT IN ('revision', 'attachment')"
        );
        foreach ($block_ids as $id) {
            $id = (int) $id;
            if ($id > 0) {
                $used[$id] = true;
            }
        }

        return $used;
    }

    /**
     * Get a set of attachment file paths that are referenced by URL in content.
     *
     * @return array Associative array with file path as key.
     */
    private static function get_used_attachment_urls(): array {
        global $wpdb;
        $used = [];

        $upload_dir = wp_get_upload_dir();
        $upload_base_url = $upload_dir['baseurl'];

        // Get all URLs that appear in post_content (from uploads directory)
        $rows = $wpdb->get_col(
            "SELECT DISTINCT post_content
             FROM {$wpdb->posts}
             WHERE post_content LIKE '%{$upload_base_url}%'
               AND post_status IN ('publish', 'draft', 'private', 'pending', 'future')
               AND post_type NOT IN ('revision', 'attachment')"
        );

        foreach ($rows as $content) {
            // Extract all upload URLs from content
            if (preg_match_all('#' . preg_quote($upload_base_url, '#') . '/([^\s"\'<>]+)#', $content, $matches)) {
                foreach ($matches[1] as $relative_path) {
                    // Remove size suffix to get original file path
                    $original = preg_replace('/-\d+x\d+(\.[a-zA-Z]+)$/', '$1', $relative_path);
                    $used[$original] = true;
                    $used[$relative_path] = true;
                }
            }
        }

        // Also check widget content
        $widget_options = $wpdb->get_col(
            "SELECT option_value
             FROM {$wpdb->options}
             WHERE option_name LIKE 'widget_%'
               AND option_value LIKE '%{$upload_base_url}%'"
        );
        foreach ($widget_options as $value) {
            if (preg_match_all('#' . preg_quote($upload_base_url, '#') . '/([^\s"\'<>]+)#', $value, $matches)) {
                foreach ($matches[1] as $relative_path) {
                    $original = preg_replace('/-\d+x\d+(\.[a-zA-Z]+)$/', '$1', $relative_path);
                    $used[$original] = true;
                    $used[$relative_path] = true;
                }
            }
        }

        // Check theme mods for image URLs
        $theme_mods = get_theme_mods();
        if (is_array($theme_mods)) {
            $theme_mods_json = json_encode($theme_mods);
            if (preg_match_all('#' . preg_quote($upload_base_url, '#') . '/([^\s"\'<>\\\\]+)#', $theme_mods_json, $matches)) {
                foreach ($matches[1] as $relative_path) {
                    $original = preg_replace('/-\d+x\d+(\.[a-zA-Z]+)$/', '$1', $relative_path);
                    $used[$original] = true;
                    $used[$relative_path] = true;
                }
            }
        }

        return $used;
    }

    /**
     * Check if a filename (without extension) is referenced in any post content.
     * This catches images referenced by filename rather than ID.
     *
     * @param string $filename_no_ext Filename without extension.
     * @param int    $attachment_id   The attachment ID to exclude self-references.
     * @return bool True if referenced.
     */
    private static function is_filename_referenced(string $filename_no_ext, int $attachment_id): bool {
        global $wpdb;

        // Skip if filename is too generic (could match unrelated content)
        if (strlen($filename_no_ext) < 5) {
            return false;
        }

        // Check Elementor CSS
        $elementor_css = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*)
             FROM {$wpdb->postmeta}
             WHERE meta_key = '_elementor_css'
               AND meta_value LIKE %s",
            '%' . $wpdb->esc_like($filename_no_ext) . '%'
        ));

        return (int) $elementor_css > 0;
    }

    /**
     * Recursively extract attachment IDs from Elementor JSON data.
     *
     * Elementor stores images as { "id": 123, "url": "..." } objects
     * in various settings keys like background_image, image, etc.
     *
     * @param string $json_string Raw JSON string from _elementor_data.
     * @param array  &$used       Reference to the used IDs array.
     */
    private static function extract_elementor_ids(string $json_string, array &$used): void {
        // Quick regex extraction of "id": followed by a number
        // This is faster than full JSON decode for large datasets
        if (preg_match_all('/"id"\s*:\s*(\d+)/', $json_string, $matches)) {
            foreach ($matches[1] as $id) {
                $id = (int) $id;
                // Only consider reasonable attachment IDs (not element IDs which can be large hex)
                if ($id > 0 && $id < 999999999) {
                    $used[$id] = true;
                }
            }
        }

        // Also extract URL-based references from Elementor data
        $upload_dir = wp_get_upload_dir();
        $upload_base_url = $upload_dir['baseurl'];

        if (strpos($json_string, $upload_base_url) !== false) {
            if (preg_match_all('#' . preg_quote($upload_base_url, '#') . '/([^\s"\'<>\\\\]+)#', $json_string, $url_matches)) {
                // These URLs will be caught by the URL-based check in get_used_attachment_urls()
                // but we can also try to find the attachment ID for them
                foreach ($url_matches[1] as $relative_path) {
                    // Strip query strings
                    $relative_path = strtok($relative_path, '?');
                    // Remove size suffix
                    $clean_path = preg_replace('/-\d+x\d+(\.[a-zA-Z]+)$/', '$1', $relative_path);
                    // Try to find attachment by path
                    global $wpdb;
                    $att_id = $wpdb->get_var($wpdb->prepare(
                        "SELECT post_id FROM {$wpdb->postmeta}
                         WHERE meta_key = '_wp_attached_file'
                           AND (meta_value = %s OR meta_value = %s)
                         LIMIT 1",
                        $clean_path,
                        $relative_path
                    ));
                    if ($att_id) {
                        $used[(int) $att_id] = true;
                    }
                }
            }
        }
    }
}

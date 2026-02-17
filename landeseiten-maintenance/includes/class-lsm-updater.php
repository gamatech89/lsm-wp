<?php
/**
 * GitHub-based auto-updater for the LSM plugin.
 *
 * Checks the public GitHub repo for new releases and integrates
 * with WordPress's built-in plugin update system. Provides:
 * - Automatic update detection via GitHub Releases
 * - "Show details" modal with description, changelog, and metadata
 * - "Check for updates" manual link in the plugin row
 * - Proper folder renaming after update
 *
 * @package Landeseiten_Maintenance
 * @since 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Updater {

    private const GITHUB_REPO  = 'gamatech89/lsm-wp';
    private const PLUGIN_SLUG  = 'landeseiten-maintenance';
    private const LSM_API_URL  = 'https://api.wartung-ls.com/api';
    private const CACHE_KEY    = 'lsm_github_update_check';
    private const CACHE_TTL    = 43200; // 12 hours
    private const CACHE_ERR    = 3600;  // 1 hour on error

    private static $instance = null;

    public static function init() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Core update hooks
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        add_filter('plugins_api', [$this, 'plugin_info'], 20, 3);
        add_filter('upgrader_post_install', [$this, 'post_install'], 10, 3);

        // Clear cache when visiting the Updates page
        add_action('load-update-core.php', [$this, 'clear_cache']);

        // Plugin row meta links: "Show details" + "Check for updates"
        add_filter('plugin_row_meta', [$this, 'plugin_row_meta'], 10, 2);

        // Handle manual "Check for updates" click
        add_action('admin_init', [$this, 'handle_manual_check']);

        // Display manual check result notice
        add_action('all_admin_notices', [$this, 'display_manual_check_result']);
    }

    // ─────────────────────────────────────────────────────
    //  Update transient — injects update info for WP core
    // ─────────────────────────────────────────────────────

    public function check_for_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        $release = $this->get_latest_release();
        if (!$release) {
            return $transient;
        }

        $remote_version = ltrim($release['tag_name'], 'v');

        if (version_compare($remote_version, LSM_VERSION, '>')) {
            $download_url = $this->get_download_url($release);

            if ($download_url) {
                $transient->response[LSM_PLUGIN_BASENAME] = (object) [
                    'slug'         => self::PLUGIN_SLUG,
                    'plugin'       => LSM_PLUGIN_BASENAME,
                    'new_version'  => $remote_version,
                    'url'          => 'https://github.com/' . self::GITHUB_REPO,
                    'package'      => $download_url,
                    'icons'        => [],
                    'banners'      => [],
                    'requires'     => '5.8',
                    'tested'       => '6.7.999',
                    'requires_php' => '7.4',
                ];
            }
        }

        return $transient;
    }

    // ─────────────────────────────────────────────────────
    //  Plugin info — "Show details" / "View Details" modal
    // ─────────────────────────────────────────────────────

    public function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== self::PLUGIN_SLUG) {
            return $result;
        }

        $release = $this->get_latest_release();
        $remote_version = $release ? ltrim($release['tag_name'], 'v') : LSM_VERSION;
        $last_updated   = $release ? ($release['published_at'] ?? '') : '';
        $changelog      = $release ? nl2br(esc_html($release['body'] ?? 'No changelog provided.')) : 'No release information available.';
        $download_link  = $release ? $this->get_download_url($release) : '';

        return (object) [
            'name'            => 'Landeseiten Maintenance',
            'slug'            => self::PLUGIN_SLUG,
            'version'         => $remote_version,
            'author'          => '<a href="https://landeseiten.at">Landeseiten GmbH</a>',
            'author_profile'  => 'https://landeseiten.at',
            'homepage'        => 'https://landeseiten.at',
            'requires'        => '5.8',
            'tested'          => '6.7.999',
            'requires_php'    => '7.4',
            'last_updated'    => $last_updated,
            'sections'        => [
                'description'  => $this->get_description_html(),
                'changelog'    => $changelog,
                'installation' => $this->get_installation_html(),
            ],
            'download_link'   => $download_link,
            'banners'         => [],
        ];
    }

    // ─────────────────────────────────────────────────────
    //  Plugin row meta — adds links under the plugin name
    // ─────────────────────────────────────────────────────

    public function plugin_row_meta($meta, $plugin_file) {
        if ($plugin_file !== LSM_PLUGIN_BASENAME) {
            return $meta;
        }

        // Replace "Visit the plugin website" with our Author link
        // WordPress auto-adds it from Plugin URI header, but we removed that.
        // Now add "Show details" before any existing trailing links.
        $details_url = network_admin_url(
            'plugin-install.php?tab=plugin-information&plugin=' . urlencode(self::PLUGIN_SLUG) .
            '&TB_iframe=true&width=772&height=840'
        );

        $meta[] = sprintf(
            '<a href="%s" class="thickbox open-plugin-details-modal" aria-label="%s" data-title="%s">%s</a>',
            esc_url($details_url),
            esc_attr(sprintf(__('More information about %s'), 'Landeseiten Maintenance')),
            esc_attr('Landeseiten Maintenance'),
            __('Show details')
        );

        // "Check for updates" link
        $check_url = wp_nonce_url(
            add_query_arg([
                'lsm_check_updates' => 1,
            ], self_admin_url('plugins.php')),
            'lsm_check_updates'
        );

        $meta[] = sprintf(
            '<a href="%s">%s</a>',
            esc_attr($check_url),
            __('Check for updates')
        );

        return $meta;
    }

    // ─────────────────────────────────────────────────────
    //  Manual "Check for updates" handler
    // ─────────────────────────────────────────────────────

    public function handle_manual_check() {
        if (!isset($_GET['lsm_check_updates'])) {
            return;
        }

        if (!check_admin_referer('lsm_check_updates') || !current_user_can('update_plugins')) {
            return;
        }

        // Clear the cache so we get fresh data
        delete_transient(self::CACHE_KEY);

        // Force WP to re-check plugin updates
        delete_site_transient('update_plugins');
        wp_update_plugins();

        // Determine result
        $update_plugins = get_site_transient('update_plugins');
        $has_update = isset($update_plugins->response[LSM_PLUGIN_BASENAME]);

        wp_redirect(add_query_arg([
            'lsm_update_result' => $has_update ? 'available' : 'up_to_date',
        ], self_admin_url('plugins.php')));
        exit;
    }

    public function display_manual_check_result() {
        if (!isset($_GET['lsm_update_result'])) {
            return;
        }

        $result = sanitize_key($_GET['lsm_update_result']);

        if ($result === 'available') {
            $class   = 'notice notice-warning is-dismissible';
            $message = __('A new version of Landeseiten Maintenance is available! Please update.');
        } else {
            $class   = 'notice notice-success is-dismissible';
            $message = __('Landeseiten Maintenance is up to date.');
        }

        printf('<div class="%s"><p>%s</p></div>', esc_attr($class), esc_html($message));
    }

    // ─────────────────────────────────────────────────────
    //  Post-install — rename extracted folder
    // ─────────────────────────────────────────────────────

    public function post_install($response, $hook_extra, $result) {
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== LSM_PLUGIN_BASENAME) {
            return $result;
        }

        global $wp_filesystem;

        $proper_dir = WP_PLUGIN_DIR . '/' . self::PLUGIN_SLUG;

        if ($result['destination'] !== $proper_dir) {
            $wp_filesystem->move($result['destination'], $proper_dir);
            $result['destination'] = $proper_dir;
            $result['destination_name'] = self::PLUGIN_SLUG;
        }

        activate_plugin(self::PLUGIN_SLUG . '/landeseiten-maintenance.php');

        return $result;
    }

    // ─────────────────────────────────────────────────────
    //  Cache management
    // ─────────────────────────────────────────────────────

    public function clear_cache() {
        delete_transient(self::CACHE_KEY);
    }

    /**
     * Fetch latest release from GitHub (cached 12h).
     */
    private function get_latest_release() {
        $cached = get_transient(self::CACHE_KEY);

        // We store 'none' string when no release found to avoid re-fetching
        if ($cached === 'none') {
            return null;
        }
        if (!empty($cached) && is_array($cached)) {
            return $cached;
        }

        // Try our own API first (always reachable from any hosting)
        $body = $this->fetch_release_from_lsm_api();

        // Fallback to GitHub directly
        if (!$body) {
            $body = $this->fetch_release_from_github();
        }

        if (!$body) {
            set_transient(self::CACHE_KEY, 'none', self::CACHE_ERR);
            return null;
        }

        set_transient(self::CACHE_KEY, $body, self::CACHE_TTL);
        return $body;
    }

    /**
     * Fetch latest release from our own API (proxy for GitHub).
     * This is the primary source — always reachable from any hosting.
     */
    private function fetch_release_from_lsm_api() {
        $response = wp_remote_get(
            self::LSM_API_URL . '/v1/plugin/latest-release',
            [
                'timeout' => 10,
                'headers' => [
                    'Accept'     => 'application/json',
                    'User-Agent' => 'LSM-WordPress-Plugin/' . LSM_VERSION,
                ],
            ]
        );

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($body) || !isset($body['tag_name'])) {
            return null;
        }

        return $body;
    }

    /**
     * Fetch latest release from GitHub directly (fallback).
     * May fail on shared hosting that blocks api.github.com.
     */
    private function fetch_release_from_github() {
        $response = wp_remote_get(
            'https://api.github.com/repos/' . self::GITHUB_REPO . '/releases/latest',
            [
                'timeout' => 10,
                'headers' => [
                    'Accept'     => 'application/vnd.github.v3+json',
                    'User-Agent' => 'LSM-WordPress-Plugin/' . LSM_VERSION,
                ],
            ]
        );

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($body) || !isset($body['tag_name'])) {
            return null;
        }

        return $body;
    }

    /**
     * Get download URL — prefers .zip asset, falls back to zipball.
     */
    private function get_download_url($release) {
        if (!empty($release['assets'])) {
            foreach ($release['assets'] as $asset) {
                if (substr($asset['name'], -4) === '.zip') {
                    return $asset['browser_download_url'];
                }
            }
        }

        return $release['zipball_url'] ?? null;
    }

    // ─────────────────────────────────────────────────────
    //  Static content for the details modal
    // ─────────────────────────────────────────────────────

    private function get_description_html() {
        return '
            <h3>Landeseiten Maintenance</h3>
            <p>The all-in-one remote management plugin for Landeseiten managed WordPress sites. Provides seamless integration with the LSM Platform dashboard for centralized site monitoring and administration.</p>

            <h4>Key Features</h4>
            <ul>
                <li><strong>SSO Login:</strong> One-click secure login from the LSM dashboard — no passwords needed.</li>
                <li><strong>Health Monitoring:</strong> Real-time PHP version, WordPress version, and disk usage reporting.</li>
                <li><strong>Security Scanner:</strong> 3-tier malware scanning (Quick/Standard/Full) with entropy analysis, fake plugin detection, and database persistence checks.</li>
                <li><strong>Plugin &amp; Theme Management:</strong> Remote update, activate, and deactivate plugins and themes.</li>
                <li><strong>PHP Error Tracking:</strong> Captures and reports PHP errors back to the dashboard.</li>
                <li><strong>Recovery Mode:</strong> Remote emergency disable of plugins and theme switching.</li>
                <li><strong>Maintenance Mode:</strong> One-click maintenance page with customizable IP whitelist.</li>
                <li><strong>Auto-Updates:</strong> Automatic plugin updates via GitHub releases.</li>
            </ul>

            <h4>Requirements</h4>
            <ul>
                <li>WordPress 5.8 or higher</li>
                <li>PHP 7.4 or higher</li>
                <li>Active LSM Platform subscription</li>
            </ul>
        ';
    }

    private function get_installation_html() {
        return '
            <h4>Automatic Installation</h4>
            <p>This plugin is installed and managed automatically through the LSM Platform. Updates are delivered via GitHub releases and appear in your WordPress dashboard.</p>

            <h4>Manual Installation</h4>
            <ol>
                <li>Download the latest release from GitHub</li>
                <li>Upload the <code>landeseiten-maintenance</code> folder to <code>/wp-content/plugins/</code></li>
                <li>Activate the plugin through the WordPress Plugins menu</li>
                <li>Configure the API key in the plugin settings page</li>
            </ol>
        ';
    }
}

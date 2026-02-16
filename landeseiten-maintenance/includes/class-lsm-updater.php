<?php
/**
 * GitHub-based auto-updater for the LSM plugin.
 *
 * Checks GitHub releases for new versions and integrates
 * with WordPress's built-in plugin update system.
 *
 * @package Landeseiten_Maintenance
 * @since 2.0.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class LSM_Updater {

    /**
     * GitHub repository owner/name.
     */
    private const GITHUB_REPO = 'gamatech89/lsm-wp';

    /**
     * Plugin slug (folder name).
     */
    private const PLUGIN_SLUG = 'landeseiten-maintenance';

    /**
     * Cache transient key.
     */
    private const CACHE_KEY = 'lsm_github_update_check';

    /**
     * Cache duration in seconds (12 hours).
     */
    private const CACHE_TTL = 43200;

    /**
     * Singleton instance.
     */
    private static $instance = null;

    /**
     * GitHub token for private repo access.
     */
    private $token = '';

    /**
     * Initialize the updater.
     */
    public static function init() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor – register WordPress hooks.
     */
    private function __construct() {
        // Token from wp-config.php constant or plugin settings
        $this->token = defined('LSM_GITHUB_TOKEN') ? LSM_GITHUB_TOKEN : '';

        // Check for updates
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);

        // Plugin info popup
        add_filter('plugins_api', [$this, 'plugin_info'], 20, 3);

        // Rename folder after update
        add_filter('upgrader_post_install', [$this, 'post_install'], 10, 3);

        // Clear cache when force-checking
        add_action('load-update-core.php', [$this, 'clear_cache']);
    }

    /**
     * Check GitHub for a newer release.
     *
     * @param object $transient The update_plugins transient.
     * @return object Modified transient.
     */
    public function check_for_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        $release = $this->get_latest_release();
        if (!$release) {
            return $transient;
        }

        $remote_version = ltrim($release['tag_name'], 'v');
        $current_version = LSM_VERSION;

        if (version_compare($remote_version, $current_version, '>')) {
            $download_url = $this->get_download_url($release);

            if ($download_url) {
                $plugin_file = LSM_PLUGIN_BASENAME;

                $transient->response[$plugin_file] = (object) [
                    'slug'        => self::PLUGIN_SLUG,
                    'plugin'      => $plugin_file,
                    'new_version' => $remote_version,
                    'url'         => "https://github.com/" . self::GITHUB_REPO,
                    'package'     => $download_url,
                    'icons'       => [],
                    'banners'     => [],
                    'tested'      => '',
                    'requires'    => '5.0',
                    'requires_php'=> '7.4',
                ];
            }
        }

        return $transient;
    }

    /**
     * Provide plugin info for the "View Details" popup.
     *
     * @param false|object|array $result
     * @param string $action
     * @param object $args
     * @return false|object
     */
    public function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== self::PLUGIN_SLUG) {
            return $result;
        }

        $release = $this->get_latest_release();
        if (!$release) {
            return $result;
        }

        $remote_version = ltrim($release['tag_name'], 'v');

        return (object) [
            'name'          => 'Landeseiten Maintenance',
            'slug'          => self::PLUGIN_SLUG,
            'version'       => $remote_version,
            'author'        => '<a href="https://landeseiten.at">Landeseiten GmbH</a>',
            'homepage'      => 'https://landeseiten.at/maintenance',
            'requires'      => '5.0',
            'requires_php'  => '7.4',
            'downloaded'    => 0,
            'last_updated'  => $release['published_at'] ?? '',
            'sections'      => [
                'description' => 'Remote site management, SSO login, health monitoring, security scanning, and client support for Landeseiten managed WordPress sites.',
                'changelog'   => nl2br(esc_html($release['body'] ?? 'No changelog provided.')),
            ],
            'download_link' => $this->get_download_url($release),
        ];
    }

    /**
     * Rename the extracted folder to match the expected plugin slug.
     *
     * GitHub zips extract to "lsm-wp-main/" or "lsm-wp-v2.0.0/" but
     * WordPress expects "landeseiten-maintenance/".
     *
     * @param bool  $response
     * @param array $hook_extra
     * @param array $result
     * @return array
     */
    public function post_install($response, $hook_extra, $result) {
        // Only act on our plugin
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== LSM_PLUGIN_BASENAME) {
            return $result;
        }

        global $wp_filesystem;

        $install_dir = $result['destination'];
        $proper_dir  = WP_PLUGIN_DIR . '/' . self::PLUGIN_SLUG;

        // Move to proper directory if needed
        if ($install_dir !== $proper_dir) {
            $wp_filesystem->move($install_dir, $proper_dir);
            $result['destination'] = $proper_dir;
            $result['destination_name'] = self::PLUGIN_SLUG;
        }

        // Re-activate the plugin
        $plugin_file = self::PLUGIN_SLUG . '/landeseiten-maintenance.php';
        if (!is_plugin_active($plugin_file)) {
            activate_plugin($plugin_file);
        }

        return $result;
    }

    /**
     * Clear cached release data when user manually checks for updates.
     */
    public function clear_cache() {
        delete_transient(self::CACHE_KEY);
    }

    /**
     * Fetch the latest release from GitHub API (cached).
     *
     * @return array|null Release data or null on failure.
     */
    private function get_latest_release() {
        $cached = get_transient(self::CACHE_KEY);
        if ($cached !== false) {
            return $cached;
        }

        $url = "https://api.github.com/repos/" . self::GITHUB_REPO . "/releases/latest";

        $args = [
            'timeout' => 10,
            'headers' => [
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'LSM-WordPress-Plugin/' . LSM_VERSION,
            ],
        ];

        // Add auth token for private repos
        if (!empty($this->token)) {
            $args['headers']['Authorization'] = 'Bearer ' . $this->token;
        }

        $response = wp_remote_get($url, $args);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Cache failure for 1 hour to avoid hammering
            set_transient(self::CACHE_KEY, null, 3600);
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($body) || !isset($body['tag_name'])) {
            return null;
        }

        set_transient(self::CACHE_KEY, $body, self::CACHE_TTL);

        return $body;
    }

    /**
     * Get the download URL from a release.
     *
     * Prefers an attached .zip asset; falls back to the source zipball.
     *
     * @param array $release GitHub release data.
     * @return string|null Download URL.
     */
    private function get_download_url($release) {
        // Look for a .zip asset (our build artifact)
        if (!empty($release['assets'])) {
            foreach ($release['assets'] as $asset) {
                if (substr($asset['name'], -4) === '.zip') {
                    if (!empty($this->token)) {
                        // Use the API URL with Accept header for private repos
                        $url = $asset['url'];
                        $this->register_download_auth($url);
                        return $url;
                    }
                    return $asset['browser_download_url'];
                }
            }
        }

        // Fallback: source code zipball
        $url = $release['zipball_url'] ?? null;
        if ($url && !empty($this->token)) {
            $this->register_download_auth($url);
        }
        return $url;
    }

    /**
     * Register a one-time filter to inject auth headers when WordPress
     * downloads a file from the GitHub API.
     *
     * @param string $url The URL that needs authentication.
     */
    private function register_download_auth($url) {
        $token = $this->token;
        add_filter('http_request_args', function ($args, $request_url) use ($url, $token) {
            if (strpos($request_url, $url) !== false || $request_url === $url) {
                $args['headers']['Authorization'] = 'Bearer ' . $token;
                $args['headers']['Accept'] = 'application/octet-stream';
            }
            return $args;
        }, 10, 2);
    }
}

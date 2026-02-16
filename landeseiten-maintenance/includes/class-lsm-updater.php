<?php
/**
 * GitHub-based auto-updater for the LSM plugin.
 *
 * Checks the public GitHub repo for new releases and integrates
 * with WordPress's built-in plugin update system. Zero configuration needed.
 *
 * @package Landeseiten_Maintenance
 * @since 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Updater {

    private const GITHUB_REPO = 'gamatech89/lsm-wp';
    private const PLUGIN_SLUG = 'landeseiten-maintenance';
    private const CACHE_KEY   = 'lsm_github_update_check';
    private const CACHE_TTL   = 43200; // 12 hours

    private static $instance = null;

    public static function init() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        add_filter('plugins_api', [$this, 'plugin_info'], 20, 3);
        add_filter('upgrader_post_install', [$this, 'post_install'], 10, 3);
        add_action('load-update-core.php', [$this, 'clear_cache']);
    }

    /**
     * Check GitHub for a newer release.
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
                    'requires'     => '5.0',
                    'requires_php' => '7.4',
                ];
            }
        }

        return $transient;
    }

    /**
     * Populate the "View Details" popup.
     */
    public function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information' || !isset($args->slug) || $args->slug !== self::PLUGIN_SLUG) {
            return $result;
        }

        $release = $this->get_latest_release();
        if (!$release) {
            return $result;
        }

        return (object) [
            'name'          => 'Landeseiten Maintenance',
            'slug'          => self::PLUGIN_SLUG,
            'version'       => ltrim($release['tag_name'], 'v'),
            'author'        => '<a href="https://landeseiten.at">Landeseiten GmbH</a>',
            'homepage'      => 'https://landeseiten.at/maintenance',
            'requires'      => '5.0',
            'requires_php'  => '7.4',
            'last_updated'  => $release['published_at'] ?? '',
            'sections'      => [
                'description' => 'Remote site management, SSO login, health monitoring, security scanning, and client support for Landeseiten managed WordPress sites.',
                'changelog'   => nl2br(esc_html($release['body'] ?? 'No changelog provided.')),
            ],
            'download_link' => $this->get_download_url($release),
        ];
    }

    /**
     * Rename extracted folder to match plugin slug after update.
     */
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

    public function clear_cache() {
        delete_transient(self::CACHE_KEY);
    }

    /**
     * Fetch latest release from GitHub (cached 12h).
     */
    private function get_latest_release() {
        $cached = get_transient(self::CACHE_KEY);
        if ($cached !== false) {
            return $cached;
        }

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
}

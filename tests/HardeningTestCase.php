<?php

use PHPUnit\Framework\TestCase;

/**
 * Base class for the LSM_Hardening tests: a fresh temp wp-content per test,
 * a testable engine pointed at it and the fake server as canned HTTP.
 */
abstract class HardeningTestCase extends TestCase {

    /** @var string */
    protected $root;

    /** @var string */
    protected $content;

    /** @var string */
    protected $uploads;

    /** @var LSM_Testable_Hardening */
    protected $h;

    /** @var LSM_Fake_Server */
    protected $server;

    protected function setUp(): void {
        LSM_Test_Env::reset();
        unset($_SERVER['LSWS_EDITION'], $_SERVER['REQUEST_URI'], $_GET['rest_route']);

        $this->root    = rtrim(sys_get_temp_dir(), '/\\') . '/lsm-hardening-' . bin2hex(random_bytes(6));
        $this->content = $this->root . '/wp-content';
        $this->uploads = $this->content . '/uploads';
        $plugin        = $this->content . '/plugins/landeseiten-maintenance/';

        mkdir($this->uploads, 0777, true);
        mkdir($plugin . 'assets/css', 0777, true);
        file_put_contents($plugin . 'assets/css/ticket-ui.css', '.lsm-ticket{display:block}');

        $this->h          = new LSM_Testable_Hardening();
        $this->h->content = $this->content;
        $this->h->uploads = $this->uploads;
        $this->h->plugin  = $plugin;
        LSM_Hardening::set_instance($this->h);

        $this->server       = new LSM_Fake_Server($this->content, $this->uploads);
        LSM_Test_Env::$http = [$this->server, 'handle'];
    }

    protected function tearDown(): void {
        LSM_Hardening::set_instance(null);
        $this->remove($this->root);
    }

    /**
     * Path of a target's .htaccess.
     */
    protected function htaccess($target) {
        return ($target === 'uploads' ? $this->uploads : $this->content) . '/.htaccess';
    }

    /**
     * Write a target's .htaccess directly (test setup).
     */
    protected function put($target, $content) {
        file_put_contents($this->htaccess($target), $content);
    }

    /**
     * Read a target's .htaccess, or null when it does not exist.
     */
    protected function get($target) {
        return is_file($this->htaccess($target)) ? file_get_contents($this->htaccess($target)) : null;
    }

    /**
     * Names of leftover probe and snapshot files in both directories.
     */
    protected function artifacts() {
        $found = [];
        foreach ([$this->content, $this->uploads] as $dir) {
            foreach (scandir($dir) as $name) {
                if (LSM_Hardening::is_own_artifact($name)) {
                    $found[] = $name;
                }
            }
        }
        return $found;
    }

    /**
     * Put a CDN edge in front of the fake server. Like Cloudflare at its default "Standard"
     * cache level it caches every 200 for a .zip by extension, keyed by URL + query string,
     * and ignores the request's "Cache-Control: no-cache". Entries never expire within a
     * test (the real edge keeps a 200 for about two hours).
     *
     * @return ArrayObject The edge cache: full URL => cached response.
     */
    protected function put_an_edge_cache_in_front() {
        $server = $this->server;
        $edge   = new ArrayObject();

        LSM_Test_Env::$http = function ($url, $args) use ($server, $edge) {
            $is_zip = (bool) preg_match('~\.zip$~', (string) parse_url($url, PHP_URL_PATH));
            if ($is_zip && isset($edge[$url])) {
                return $edge[$url]; // HIT: the origin and its .htaccess are never asked
            }
            $response = $server->handle($url, $args);
            if ($is_zip && !is_wp_error($response) && $response['response']['code'] === 200) {
                $edge[$url] = $response;
            }
            return $response;
        };

        return $edge;
    }

    private function remove($path) {
        if (!file_exists($path) && !is_link($path)) {
            return;
        }
        @chmod($path, 0777);
        if (is_dir($path) && !is_link($path)) {
            foreach (scandir($path) as $name) {
                if ($name !== '.' && $name !== '..') {
                    $this->remove($path . '/' . $name);
                }
            }
            rmdir($path);
            return;
        }
        unlink($path);
    }
}

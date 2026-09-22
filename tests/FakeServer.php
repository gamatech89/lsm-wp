<?php
/**
 * A tiny stand-in for Apache, used as the canned HTTP handler.
 *
 * It maps http://example.test/wp-content/... onto two real temp directories and
 * honours the <FilesMatch "..."> and <Files "..."> containers it finds in their
 * .htaccess files, so a test observes what the engine really wrote: 403 when a
 * rule covers the file, 200 + file body when it exists, 404 otherwise.
 *
 * Scripted responses (script()/always()) override the simulation per URL.
 */
class LSM_Fake_Server {

    /** @var string */
    public $content_dir;

    /** @var string */
    public $uploads_dir;

    /** @var array list of ['url' => string, 'args' => array, 'file_existed' => bool] */
    public $requests = [];

    /** @var string|null regex of URL paths (no query string) answered 403 no matter what the .htaccess says (a vhost / WAF rule) */
    public $foreign_deny = null;

    /** @var string|null regex of URL paths (no query string) served without looking at .htaccess (nginx serving static files) */
    public $bypass_htaccess = null;

    /** @var string|null a directive this "server" rejects: any .htaccess containing it answers 500 (AllowOverride without AuthConfig) */
    public $rejected_directive = null;

    /** @var string body of the homepage */
    public $home_body = '<html>home</html>';

    /** @var array list of [regex, responses[]] consumed one response per matching request */
    private $scripts = [];

    /** @var array list of [regex, response] applied to every matching request */
    private $always = [];

    public function __construct($content_dir, $uploads_dir) {
        $this->content_dir = $content_dir;
        $this->uploads_dir = $uploads_dir;
    }

    /**
     * Build a response array.
     */
    public static function response($code, $body = '', array $headers = []) {
        return ['response' => ['code' => $code], 'body' => $body, 'headers' => $headers];
    }

    /**
     * Queue responses for URLs matching $regex. Each matching request consumes one;
     * the string 'pass' means "answer this one from the simulation". An exhausted
     * queue falls through to the simulation. A Throwable in the queue is thrown.
     */
    public function script($regex, array $responses) {
        $this->scripts[] = [$regex, $responses];
    }

    /**
     * Answer every request matching $regex with $response.
     */
    public function always($regex, $response) {
        $this->always[] = [$regex, $response];
    }

    /**
     * Requests whose URL matches $regex.
     */
    public function requests_matching($regex) {
        return array_values(array_filter($this->requests, function ($request) use ($regex) {
            return preg_match($regex, $request['url']) === 1;
        }));
    }

    /**
     * The canned HTTP handler: LSM_Test_Env::$http = [$server, 'handle'].
     */
    public function handle($url, $args) {
        $file = $this->file_for($url);
        $this->requests[] = [
            'url'          => $url,
            'args'         => $args,
            'file_existed' => $file !== null && is_file($file),
        ];

        foreach ($this->scripts as $i => $script) {
            if (preg_match($script[0], $url) && !empty($script[1])) {
                $next = array_shift($this->scripts[$i][1]);
                if ($next instanceof Throwable) {
                    throw $next;
                }
                if ($next !== 'pass') {
                    return $next;
                }
                return $this->simulate($url, $file);
            }
        }

        foreach ($this->always as $rule) {
            if (preg_match($rule[0], $url)) {
                return $rule[1];
            }
        }

        return $this->simulate($url, $file);
    }

    /**
     * Map a URL onto a file below the temp wp-content, or null for non-content URLs.
     */
    private function file_for($url) {
        $path   = (string) parse_url($url, PHP_URL_PATH);
        $prefix = '/wp-content/';
        if (strpos($path, $prefix) !== 0) {
            return null;
        }
        $relative = substr($path, strlen($prefix));
        if (strpos($relative, 'uploads/') === 0) {
            return $this->uploads_dir . '/' . substr($relative, strlen('uploads/'));
        }
        return $this->content_dir . '/' . $relative;
    }

    private function simulate($url, $file) {
        if ($file === null) {
            return self::response(200, $this->home_body);
        }

        // The two knobs look at the path only: the engine appends a fresh cache-buster to every
        // probe URL, and their patterns are anchored with "$" ('~\.zip$~').
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($this->foreign_deny !== null && preg_match($this->foreign_deny, $path)) {
            return self::response(403, 'Forbidden');
        }

        $bypass = $this->bypass_htaccess !== null && preg_match($this->bypass_htaccess, $path);
        if (!$bypass) {
            // .htaccess files apply from wp-content downwards.
            $chain = [$this->content_dir . '/.htaccess'];
            if (strpos($file, $this->uploads_dir . '/') === 0) {
                $chain[] = $this->uploads_dir . '/.htaccess';
            }
            foreach ($chain as $htaccess) {
                if (!is_file($htaccess)) {
                    continue;
                }
                $rules = (string) file_get_contents($htaccess);
                if ($this->rejected_directive !== null && strpos($rules, $this->rejected_directive) !== false) {
                    return self::response(500, 'Internal Server Error');
                }
                if ($this->denies($rules, basename($file))) {
                    return self::response(403, 'Forbidden');
                }
            }
        }

        if (is_file($file)) {
            return self::response(200, (string) file_get_contents($file));
        }
        return self::response(404, 'Not Found');
    }

    /**
     * Does any <FilesMatch>/<Files> container in $rules cover $basename?
     * Every container in these tests denies, so matching the container is enough.
     */
    private function denies($rules, $basename) {
        if (preg_match_all('/^\s*<FilesMatch\s+"(.+)">\s*$/m', $rules, $matches)) {
            foreach ($matches[1] as $pattern) {
                if (preg_match('~' . $pattern . '~', $basename)) {
                    return true;
                }
            }
        }
        if (preg_match_all('/^\s*<Files\s+"(.+)">\s*$/m', $rules, $matches)) {
            foreach ($matches[1] as $name) {
                if ($name === $basename) {
                    return true;
                }
            }
        }
        return false;
    }
}

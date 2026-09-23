<?php
/**
 * LSM_Hardening with its seams pointed at temp directories and a fixed clock.
 *
 * HTTP is not overridden here: http_request() calls the wp_remote_get() fake,
 * which hands the request to LSM_Test_Env::$http (the fake server).
 *
 * Some overrides below belong to seams that later parts of the class add
 * (put_contents, plugin_dir, is_cli, finish_request). PHP does not mind an
 * override whose parent method does not exist yet.
 */
class LSM_Testable_Hardening extends LSM_Hardening {

    /** @var string */
    public $content = '';

    /** @var string */
    public $uploads = '';

    /** @var string */
    public $plugin = '';

    /** @var int */
    public $time = 1790000000;

    /** @var string */
    public $software = 'Apache/2.4.57 (Unix)';

    /** @var bool */
    public $cli = false;

    /** @var int number of finish_request() calls that actually flushed */
    public $finished = 0;

    /** @var bool whether finish_request() can hand off the response (a finisher function exists) */
    public $can_finish = true;

    /** @var callable|null function($file, $content): return null to write normally, anything else is returned instead of writing */
    public $put_hook = null;

    protected function content_dir() {
        return $this->content;
    }

    protected function uploads_dir() {
        return $this->uploads;
    }

    protected function plugin_dir() {
        return $this->plugin;
    }

    protected function now() {
        return $this->time;
    }

    protected function server_software() {
        return $this->software;
    }

    protected function is_cli() {
        return $this->cli;
    }

    protected function finish_request() {
        if ($this->can_finish) {
            $this->finished++;
        }
        return $this->can_finish;
    }

    protected function put_contents($file, $content) {
        if ($this->put_hook !== null) {
            $result = call_user_func($this->put_hook, $file, $content);
            if ($result !== null) {
                return $result;
            }
        }
        return parent::put_contents($file, $content);
    }
}

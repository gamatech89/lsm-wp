<?php
// landeseiten-maintenance/includes/class-lsm-scan-data-collector.php
if (!defined('ABSPATH')) { exit; }

class LSM_Scan_Data_Collector {

    private $spam_keywords;

    public function __construct($spam_keywords = []) {
        $this->spam_keywords = is_array($spam_keywords) ? $spam_keywords : [];
    }

    public function collect() {
        global $wpdb;
        return [
            'admins'        => $this->admins($wpdb),
            'crons'         => $this->cron_hooks(),
            'widgets'       => $this->widget_texts(),
            'code_snippets' => $this->code_snippets($wpdb),
            'options'       => $this->suspicious_option_rows($wpdb),
            'posts'         => $this->post_stats($wpdb),
            'db_objects'    => $this->db_objects($wpdb),
            'siteurl'       => $this->siteurl_data(),
            'plugins'       => $this->plugin_dirs(),
        ];
    }

    private function admins($wpdb) {
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered
             FROM {$wpdb->users} u
             INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
             WHERE um.meta_key = %s AND um.meta_value LIKE %s",
            $wpdb->prefix . 'capabilities', '%administrator%'
        ));
        $out = [];
        foreach ($rows as $r) {
            $out[] = ['id' => (int) $r->ID, 'login' => $r->user_login, 'email' => $r->user_email, 'registered' => $r->user_registered];
        }
        return $out;
    }

    private function cron_hooks() {
        $crons = _get_cron_array();
        if (!$crons) return [];
        $hooks = [];
        foreach ($crons as $events) {
            foreach (array_keys($events) as $hook) $hooks[] = $hook;
        }
        return array_values(array_unique($hooks));
    }

    private function widget_texts() {
        $widget_text = get_option('widget_text');
        if (!is_array($widget_text)) return [];
        $out = [];
        foreach ($widget_text as $w) {
            if (is_array($w) && isset($w['text'])) $out[] = $w['text'];
        }
        return $out;
    }

    private function code_snippets($wpdb) {
        $out = [];
        // WPCode custom post type
        $wpcode = $wpdb->get_results("SELECT ID, post_title, post_content FROM {$wpdb->posts} WHERE post_type = 'wpcode' AND post_status = 'publish'");
        foreach ($wpcode as $s) $out[] = ['source' => 'wpcode', 'id' => (int) $s->ID, 'title' => $s->post_title, 'code' => $s->post_content];

        foreach (['hfcm_scripts' => ['name', 'snippet'], 'snippets' => ['name', 'code']] as $suffix => $cols) {
            $table = $wpdb->prefix . $suffix;
            if ($wpdb->get_var("SHOW TABLES LIKE '{$table}'")) {
                $rows = $wpdb->get_results("SELECT * FROM {$table}");
                foreach ($rows as $r) {
                    $out[] = ['source' => $suffix, 'id' => (int) ($r->id ?? 0), 'title' => $r->{$cols[0]} ?? '', 'code' => $r->{$cols[1]} ?? ''];
                }
            }
        }
        return $out;
    }

    private function suspicious_option_rows($wpdb) {
        // Return option names + previews that CONTAIN the tokens; classification is server-side.
        // Exclude our own plugin's options (lsm_*): e.g. lsm_php_errors stores captured
        // PHP error text that legitimately contains these tokens, which would otherwise
        // make the scanner flag its own companion plugin.
        $rows = $wpdb->get_results(
            "SELECT option_name, LEFT(option_value, 200) AS preview
             FROM {$wpdb->options}
             WHERE (option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode%' OR option_value LIKE '%gzinflate(%')
             AND option_name NOT IN ('active_plugins','uninstall_plugins','rewrite_rules')
             AND option_name NOT LIKE 'lsm\_%'
             LIMIT 30"
        );
        $out = [];
        foreach ($rows as $r) $out[] = ['name' => $r->option_name, 'preview' => $r->preview];
        return $out;
    }

    private function post_stats($wpdb) {
        $mass = $wpdb->get_results(
            "SELECT DATE(post_date) AS d, COUNT(*) AS c FROM {$wpdb->posts}
             WHERE post_status='publish' AND post_type='post'
             GROUP BY DATE(post_date) HAVING c > 50 ORDER BY c DESC LIMIT 10"
        );
        $mass_days = [];
        foreach ($mass as $m) $mass_days[] = ['date' => $m->d, 'count' => (int) $m->c];

        $spam_count = 0; $spam_sample = '';
        if ($this->spam_keywords) {
            $conds = []; $vals = [];
            foreach ($this->spam_keywords as $kw) { $conds[] = 'post_title LIKE %s'; $vals[] = '%' . $wpdb->esc_like($kw) . '%'; }
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT COUNT(*) AS c, GROUP_CONCAT(DISTINCT SUBSTRING(post_title,1,60) SEPARATOR ' | ') AS s
                 FROM {$wpdb->posts} WHERE post_status IN ('publish','draft','pending')
                 AND post_type IN ('post','page') AND (" . implode(' OR ', $conds) . ') LIMIT 1',
                ...$vals
            ));
            $spam_count = (int) ($row->c ?? 0);
            $spam_sample = (string) ($row->s ?? '');
        }

        return [
            'mass_days' => $mass_days,
            'spam_keyword_count' => $spam_count,
            'spam_sample' => $spam_sample,
            'total' => (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status='publish' AND post_type='post'"),
        ];
    }

    private function db_objects($wpdb) {
        $db = DB_NAME;
        $map = fn($rows, $stmtCol) => array_map(fn($r) => ['name' => $r->name, 'statement' => $r->$stmtCol ?? ''], $rows ?: []);

        $triggers = $wpdb->get_results($wpdb->prepare("SELECT TRIGGER_NAME AS name, ACTION_STATEMENT AS stmt FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = %s", $db));
        $events   = $wpdb->get_results($wpdb->prepare("SELECT EVENT_NAME AS name, EVENT_DEFINITION AS stmt FROM information_schema.EVENTS WHERE EVENT_SCHEMA = %s", $db));
        $routines = $wpdb->get_results($wpdb->prepare("SELECT ROUTINE_NAME AS name, ROUTINE_DEFINITION AS stmt FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = %s", $db));

        return [
            'triggers' => $map($triggers, 'stmt'),
            'events'   => $map($events, 'stmt'),
            'routines' => $map($routines, 'stmt'),
        ];
    }

    private function siteurl_data() {
        return [
            'db_siteurl'     => get_option('siteurl'),
            'config_siteurl' => defined('WP_SITEURL') ? WP_SITEURL : null,
            'db_home'        => get_option('home'),
            'config_home'    => defined('WP_HOME') ? WP_HOME : null,
        ];
    }

    private function plugin_dirs() {
        $dir = WP_CONTENT_DIR . '/plugins';
        if (!is_dir($dir)) return [];
        $out = [];
        foreach (glob($dir . '/*', GLOB_ONLYDIR) ?: [] as $d) {
            $name = basename($d);
            $main = $d . '/' . $name . '.php';
            $has_header = false;
            if (file_exists($main)) {
                $h = @file_get_contents($main, false, null, 0, 2000);
                $has_header = $h && stripos($h, 'Plugin Name:') !== false;
            }
            $out[] = ['dir' => $name, 'has_readme' => file_exists($d . '/readme.txt'), 'has_header' => $has_header];
        }
        return $out;
    }
}

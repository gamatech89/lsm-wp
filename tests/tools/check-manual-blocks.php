<?php
/**
 * One-off release gate: run the adoption matcher over .htaccess files pulled from the fleet.
 *
 * Usage:   php tests/tools/check-manual-blocks.php <dir>
 * Input:   one file per site and target, named <site>.content.htaccess or <site>.uploads.htaccess
 * Output:  one line per file and rule: ADOPTABLE (recognised manual block), MANAGED (already ours),
 *          UNRECOGNISED (mentions what the rule is about, but the matcher does not recognise it), or nothing.
 * Exit:    1 when at least one UNRECOGNISED line was printed — read those files before releasing.
 */

// The matcher needs no WordPress: the class file only insists on ABSPATH.
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require dirname(__DIR__, 2) . '/landeseiten-maintenance/includes/class-lsm-hardening.php';

$dir = isset($argv[1]) ? rtrim($argv[1], '/') : '';
if ($dir === '' || !is_dir($dir)) {
    fwrite(STDERR, "Usage: php tests/tools/check-manual-blocks.php <dir>\n");
    exit(2);
}

// What a hand-written rule for each key would at least mention.
$hints = [
    'block_archives'    => '/wpress/i',
    'block_debug_log'   => '/debug\.log/i',
    'block_uploads_php' => '/<Files(Match)?\s[^>]*php/i',
];

$hardening    = new LSM_Hardening();
$unrecognised = 0;

foreach (glob($dir . '/*.htaccess') ?: [] as $file) {
    if (!preg_match('/\.(content|uploads)\.htaccess$/', $file, $m)) {
        continue;
    }
    $content = (string) file_get_contents($file);
    $managed = $hardening->parse_markers($content);
    $outside = $managed['found']
        ? substr($content, 0, $managed['start']) . (string) substr($content, $managed['end'])
        : $content;

    foreach ($hardening->rules_of($m[1]) as $rule) {
        if (!empty($hardening->find_manual_blocks($content, $rule))) {
            echo 'ADOPTABLE     ' . basename($file) . '  ' . $rule . "\n";
        } elseif (preg_match($hints[$rule], $outside)) {
            echo 'UNRECOGNISED  ' . basename($file) . '  ' . $rule . "\n";
            $unrecognised++;
        } elseif ($managed['found']) {
            echo 'MANAGED       ' . basename($file) . '  ' . $rule . "\n";
        }
    }
    if ($managed['corrupt']) {
        echo 'CORRUPT       ' . basename($file) . "  markers\n";
        $unrecognised++;
    }
}

exit($unrecognised > 0 ? 1 : 0);

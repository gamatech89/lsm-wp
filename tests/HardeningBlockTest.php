<?php

/**
 * Rule definitions and the generated block.
 */
class HardeningBlockTest extends HardeningTestCase {

    /**
     * The regex inside a rule's <FilesMatch "..."> line, as a PHP pattern.
     */
    private function pattern($rule) {
        $open = $this->h->rule_lines($rule)[0];
        $this->assertSame(1, preg_match('/^<FilesMatch "(.+)">$/', $open, $m), $open);
        return '~' . $m[1] . '~';
    }

    public function test_rule_keys_and_targets() {
        $this->assertSame(['block_archives', 'block_debug_log', 'block_uploads_php'], LSM_Hardening::RULES);
        $this->assertSame('content', $this->h->target_of('block_archives'));
        $this->assertSame('content', $this->h->target_of('block_debug_log'));
        $this->assertSame('uploads', $this->h->target_of('block_uploads_php'));
        $this->assertSame(['block_archives', 'block_debug_log'], $this->h->rules_of('content'));
        $this->assertSame(['block_uploads_php'], $this->h->rules_of('uploads'));
    }

    public function test_opening_lines_are_the_spec_patterns() {
        $this->assertSame(
            '<FilesMatch "(?i)\.((wpress|sql|zip|tar|tgz|bak)|(sql|tar|bak|wpress|zip)\.gz)$">',
            $this->h->rule_lines('block_archives')[0]
        );
        $this->assertSame('<Files "debug.log">', $this->h->rule_lines('block_debug_log')[0]);
        $this->assertSame(
            '<FilesMatch "(?i)\.(php[0-9]?|phtml?|pht|phps|phar)(\.|$)">',
            $this->h->rule_lines('block_uploads_php')[0]
        );
    }

    public function test_rule_body_denies_in_both_syntaxes_and_never_grants() {
        foreach (LSM_Hardening::RULES as $rule) {
            $lines = $this->h->rule_lines($rule);
            $this->assertSame([
                '  <IfModule mod_authz_core.c>',
                '    Require all denied',
                '  </IfModule>',
                '  <IfModule !mod_authz_core.c>',
                '    Order deny,allow',
                '    Deny from all',
                '  </IfModule>',
            ], array_slice($lines, 1, 7), $rule);
            $this->assertStringNotContainsStringIgnoringCase('granted', implode("\n", $lines));
            $this->assertStringNotContainsStringIgnoringCase('allow from', implode("\n", $lines));
        }
        $this->assertSame('</FilesMatch>', $this->h->rule_lines('block_archives')[8]);
        $this->assertSame('</Files>', $this->h->rule_lines('block_debug_log')[8]);
        $this->assertSame('</FilesMatch>', $this->h->rule_lines('block_uploads_php')[8]);
    }

    public function test_archive_pattern_blocks_archives_but_not_bare_gz() {
        $pattern = $this->pattern('block_archives');
        foreach (['site.wpress', 'dump.sql', 'backup.ZIP', 'x.tar', 'x.tgz', 'wp-config.php.bak', 'db.sql.gz', 'site.tar.gz', 'a.bak.gz', 'b.wpress.gz', 'c.zip.GZ'] as $name) {
            $this->assertSame(1, preg_match($pattern, $name), $name . ' must be blocked');
        }
        // WP Super Cache and precompressed assets live under wp-content as *.html.gz / *.css.gz.
        foreach (['index-https.html.gz', 'style.css.gz', 'app.js.gz', 'plain.gz', 'photo.jpg', 'zip.txt', 'notes.sqlite'] as $name) {
            $this->assertSame(0, preg_match($pattern, $name), $name . ' must stay reachable');
        }
    }

    public function test_uploads_pattern_blocks_php_variants_and_double_extensions() {
        $pattern = $this->pattern('block_uploads_php');
        foreach (['shell.php', 'SHELL.PHP', 'x.pHp', 'x.php5', 'x.php8', 'x.phtml', 'x.pht', 'x.phps', 'x.phar', 'x.php.jpg', 'x.phtml.png'] as $name) {
            $this->assertSame(1, preg_match($pattern, $name), $name . ' must be blocked');
        }
        foreach (['photo.jpg', 'document.pdf', 'php.txt', 'x.phpx', 'graph.png'] as $name) {
            $this->assertSame(0, preg_match($pattern, $name), $name . ' must stay reachable');
        }
    }

    public function test_block_for_content_holds_archives_then_debug_log() {
        $block = $this->h->build_block('content', ['block_debug_log', 'block_archives', 'block_uploads_php']);
        $lines = explode("\n", $block);

        $this->assertSame('# BEGIN LSM-HARDENING', $lines[0]);
        $this->assertSame('#', $lines[1][0]);
        $this->assertSame('# END LSM-HARDENING', $lines[count($lines) - 1]);
        $this->assertSame(
            array_merge($this->h->rule_lines('block_archives'), $this->h->rule_lines('block_debug_log')),
            array_slice($lines, 2, -1)
        );
        $this->assertStringNotContainsString('php[0-9]', $block);
        $this->assertSame($block, rtrim($block, "\n"), 'no trailing newline');
    }

    public function test_block_for_uploads_holds_only_the_php_rule() {
        $lines = explode("\n", $this->h->build_block('uploads', LSM_Hardening::RULES));
        $this->assertSame($this->h->rule_lines('block_uploads_php'), array_slice($lines, 2, -1));
    }

    public function test_no_enabled_rule_means_no_block_at_all() {
        $this->assertSame('', $this->h->build_block('content', []));
        $this->assertSame('', $this->h->build_block('content', ['block_uploads_php']));
        $this->assertSame('', $this->h->build_block('uploads', ['block_archives', 'block_debug_log']));
    }

    public function test_instance_is_shared_and_replaceable() {
        $this->assertSame($this->h, LSM_Hardening::instance());
        LSM_Hardening::set_instance(null);
        $this->assertInstanceOf(LSM_Hardening::class, LSM_Hardening::instance());
        $this->assertNotSame($this->h, LSM_Hardening::instance());
    }
}

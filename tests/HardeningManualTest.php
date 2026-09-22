<?php

/**
 * Recognition and removal of the hand-written deny blocks the audit procedure left on sites.
 */
class HardeningManualTest extends HardeningTestCase {

    public function test_real_fixtures_are_recognised() {
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_archives'));
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_debug_log'));
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::AUDITED_UPLOADS, 'block_uploads_php'));
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::SKILL_CONTENT, 'block_archives'));
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::SKILL_CONTENT, 'block_debug_log'));
        $this->assertCount(1, $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::SKILL_UPLOADS, 'block_uploads_php'));
    }

    public function test_a_rule_is_only_recognised_by_its_own_opening_line() {
        $this->assertSame([], $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_uploads_php'));
        $this->assertSame([], $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::AUDITED_UPLOADS, 'block_archives'));
        $this->assertSame([], $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::AUDITED_UPLOADS, 'block_debug_log'));
    }

    public function test_block_range_covers_whole_lines() {
        $blocks = $this->h->find_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_debug_log');
        $this->assertSame(
            "<Files \"debug.log\">\nRequire all denied\n</Files>\n",
            substr(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, $blocks[0]['start'], $blocks[0]['length'])
        );
    }

    public function test_whitespace_variants_and_the_dual_syntax_body_are_recognised() {
        $content = "\t<FilesMatch   \"\\.php$\">  \r\n"
            . "  <IfModule mod_authz_core.c>\r\n    Require all denied\r\n  </IfModule>\r\n"
            . "  <IfModule !mod_authz_core.c>\r\n    Order allow,deny\r\n    Deny   from  all\r\n  </IfModule>\r\n"
            . "\r\n"
            . "</FilesMatch>";
        $blocks = $this->h->find_manual_blocks($content, 'block_uploads_php');
        $this->assertCount(1, $blocks);
        $this->assertSame(strlen($content), $blocks[0]['length']);
    }

    public function test_stripping_removes_only_the_recognised_block() {
        $this->assertSame(
            "<IfModule litespeed>\nphp_value \n</IfModule>\n<Files \"debug.log\">\nRequire all denied\n</Files>\n",
            $this->h->strip_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_archives')
        );
        $this->assertSame(
            "<IfModule litespeed>\nphp_value \n</IfModule>\n<FilesMatch \"\\.(wpress|sql|zip|tar|gz|bak)$\">\nRequire all denied\n</FilesMatch>\n",
            $this->h->strip_manual_blocks(LSM_Htaccess_Fixtures::MIDNIGHTBLUE_CONTENT, 'block_debug_log')
        );
        $this->assertSame('', $this->h->strip_manual_blocks(LSM_Htaccess_Fixtures::AUDITED_UPLOADS, 'block_uploads_php'));
    }

    public function test_a_block_appended_twice_is_stripped_twice() {
        $content = LSM_Htaccess_Fixtures::AUDITED_UPLOADS . "Options -Indexes\n" . LSM_Htaccess_Fixtures::AUDITED_UPLOADS;
        $this->assertCount(2, $this->h->find_manual_blocks($content, 'block_uploads_php'));
        $this->assertSame("Options -Indexes\n", $this->h->strip_manual_blocks($content, 'block_uploads_php'));
    }

    public function test_near_misses_are_never_recognised() {
        $near_misses = [
            'other archive list'        => ['block_archives', "<FilesMatch \"\\.(wpress|sql|zip)$\">\nRequire all denied\n</FilesMatch>\n"],
            'our own managed pattern'   => ['block_archives', "<FilesMatch \"(?i)\\.((wpress|sql|zip|tar|tgz|bak)|(sql|tar|bak|wpress|zip)\\.gz)$\">\nRequire all denied\n</FilesMatch>\n"],
            'grants instead of denies'  => ['block_uploads_php', "<FilesMatch \"\\.php$\">\nRequire all granted\n</FilesMatch>\n"],
            'ip allow-list in the body' => ['block_uploads_php', "<FilesMatch \"\\.php$\">\nOrder deny,allow\nDeny from all\nAllow from 203.0.113.7\n</FilesMatch>\n"],
            'require ip in the body'    => ['block_debug_log', "<Files \"debug.log\">\nRequire ip 203.0.113.7\n</Files>\n"],
            'handler in the body'       => ['block_uploads_php', "<FilesMatch \"\\.php$\">\nSetHandler none\nDeny from all\n</FilesMatch>\n"],
            'comment in the body'       => ['block_debug_log', "<Files \"debug.log\">\n# keep\nDeny from all\n</Files>\n"],
            'no deny at all'            => ['block_debug_log', "<Files \"debug.log\">\nOrder allow,deny\n</Files>\n"],
            'empty body'                => ['block_debug_log', "<Files \"debug.log\">\n</Files>\n"],
            'never closed'              => ['block_debug_log', "<Files \"debug.log\">\nDeny from all\n"],
            'wrong close tag'           => ['block_uploads_php', "<FilesMatch \"\\.php$\">\nDeny from all\n</Files>\n"],
            'unbalanced IfModule'       => ['block_archives', "<FilesMatch \"\\.(wpress|sql|zip|tar|gz|bak)$\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</FilesMatch>\n"],
            'stray IfModule close'      => ['block_archives', "<FilesMatch \"\\.(wpress|sql|zip|tar|gz|bak)$\">\n</IfModule>\nRequire all denied\n</FilesMatch>\n"],
            'commented out'             => ['block_debug_log', "# <Files \"debug.log\">\n# Deny from all\n# </Files>\n"],
            'unquoted file name'        => ['block_debug_log', "<Files debug.log>\nDeny from all\n</Files>\n"],
            'other file'                => ['block_debug_log', "<Files \"error.log\">\nDeny from all\n</Files>\n"],
            'uppercase directive'       => ['block_debug_log', "<FILES \"debug.log\">\nDeny from all\n</FILES>\n"],
        ];

        foreach ($near_misses as $case => $near_miss) {
            list($rule, $content) = $near_miss;
            $this->assertSame([], $this->h->find_manual_blocks($content, $rule), $case);
            $this->assertSame($content, $this->h->strip_manual_blocks($content, $rule), $case);
        }
    }

    public function test_a_foreign_line_resets_the_match_but_a_later_clean_block_still_counts() {
        $content = "<Files \"debug.log\">\nSatisfy any\n<Files \"debug.log\">\nDeny from all\n</Files>\n";
        $blocks  = $this->h->find_manual_blocks($content, 'block_debug_log');
        $this->assertCount(1, $blocks);
        $this->assertSame("<Files \"debug.log\">\nDeny from all\n</Files>\n", substr($content, $blocks[0]['start'], $blocks[0]['length']));
    }

    public function test_a_manual_looking_block_inside_our_markers_is_not_manual() {
        $content = "# BEGIN LSM-HARDENING\n<Files \"debug.log\">\nDeny from all\n</Files>\n# END LSM-HARDENING\n";
        $this->assertSame([], $this->h->find_manual_blocks($content, 'block_debug_log'));
        $this->assertSame($content, $this->h->strip_manual_blocks($content, 'block_debug_log'));
    }

    public function test_the_managed_block_itself_is_never_mistaken_for_a_manual_one() {
        $content = $this->h->build_block('content', ['block_archives', 'block_debug_log']) . "\n";
        $this->assertSame([], $this->h->find_manual_blocks($content, 'block_debug_log'));
        $this->assertSame([], $this->h->find_manual_blocks($content, 'block_archives'));
    }
}

<?php

/**
 * Strict marker parser and writer.
 */
class HardeningWriterTest extends HardeningTestCase {

    /** Foreign content as found on a real site: no LSM markers, WebP Express block, CRLF-free. */
    const FOREIGN = "# BEGIN WebP Express\n<IfModule mod_mime.c>\n  AddType image/webp .webp\n</IfModule>\n# END WebP Express\n";

    private function block() {
        return $this->h->build_block('content', ['block_archives']);
    }

    public function test_parse_absent_markers() {
        $parsed = $this->h->parse_markers(self::FOREIGN);
        $this->assertFalse($parsed['corrupt']);
        $this->assertFalse($parsed['found']);
        $this->assertSame([], $parsed['lines']);
    }

    public function test_parse_present_markers_returns_the_body_lines() {
        $parsed = $this->h->parse_markers(self::FOREIGN . "\n" . $this->block() . "\nOptions -Indexes\n");
        $this->assertFalse($parsed['corrupt']);
        $this->assertTrue($parsed['found']);
        $this->assertSame('<FilesMatch "(?i)\.((wpress|sql|zip|tar|tgz|bak)|(sql|tar|bak|wpress|zip)\.gz)$">', $parsed['lines'][1]);
        $this->assertSame('</FilesMatch>', $parsed['lines'][count($parsed['lines']) - 1]);
    }

    public function test_parse_tolerates_crlf_and_indented_markers() {
        $parsed = $this->h->parse_markers("Options -Indexes\r\n  # BEGIN LSM-HARDENING\r\n<Files \"debug.log\">\r\n</Files>\r\n# END LSM-HARDENING  \r\n");
        $this->assertTrue($parsed['found']);
        $this->assertSame(['<Files "debug.log">', '</Files>'], $parsed['lines']);
    }

    public function test_corrupt_markers_are_detected_and_never_rewritten() {
        $corrupt = [
            'begin without end'  => "# BEGIN LSM-HARDENING\n<Files \"debug.log\">\n</Files>\n",
            'end without begin'  => "<Files \"debug.log\">\n</Files>\n# END LSM-HARDENING\n",
            'end before begin'   => "# END LSM-HARDENING\n# BEGIN LSM-HARDENING\n",
            'two blocks'         => "# BEGIN LSM-HARDENING\n# END LSM-HARDENING\n# BEGIN LSM-HARDENING\n# END LSM-HARDENING\n",
            'two begins one end' => "# BEGIN LSM-HARDENING\n# BEGIN LSM-HARDENING\n# END LSM-HARDENING\n",
            'one begin two ends' => "# BEGIN LSM-HARDENING\n# END LSM-HARDENING\n# END LSM-HARDENING\n",
        ];

        foreach ($corrupt as $case => $content) {
            $this->assertTrue($this->h->parse_markers($content)['corrupt'], $case);
            $this->assertNull($this->h->replace_block($content, $this->block()), $case);
            $this->assertNull($this->h->replace_block($content, ''), $case);
        }
    }

    public function test_a_marker_that_is_only_part_of_a_line_is_not_a_marker() {
        $content = "# BEGIN LSM-HARDENING-OLD\n# see # END LSM-HARDENING in the docs\n";
        $parsed  = $this->h->parse_markers($content);
        $this->assertFalse($parsed['corrupt']);
        $this->assertFalse($parsed['found']);
    }

    public function test_append_to_empty_content() {
        $this->assertSame($this->block() . "\n", $this->h->replace_block('', $this->block()));
    }

    public function test_append_puts_a_blank_line_before_the_block() {
        $this->assertSame(self::FOREIGN . "\n" . $this->block() . "\n", $this->h->replace_block(self::FOREIGN, $this->block()));
    }

    public function test_append_never_fuses_onto_a_last_line_without_newline() {
        // wirbewegen.schule: "# END WebP Express<FilesMatch ...>" took every upload down with a 500.
        $content = rtrim(self::FOREIGN, "\n");
        $this->assertSame($content . "\n\n" . $this->block() . "\n", $this->h->replace_block($content, $this->block()));
    }

    public function test_replace_in_place_preserves_outside_bytes() {
        $before  = "# top\r\nOptions -Indexes\r\n\n";
        $after   = "\n\n<IfModule litespeed>\nphp_value \n</IfModule>\n\t# tail without newline";
        $content = $before . $this->block() . $after;

        $new_block = $this->h->build_block('content', ['block_archives', 'block_debug_log']);
        $result    = $this->h->replace_block($content, $new_block);

        $this->assertSame($before . $new_block . $after, $result);
    }

    public function test_enable_then_remove_gives_back_the_original_bytes() {
        $with = $this->h->replace_block(self::FOREIGN, $this->block());
        $this->assertSame(self::FOREIGN, $this->h->replace_block($with, ''));
    }

    public function test_removal_in_the_middle_keeps_both_sides() {
        $content = "Options -Indexes\n" . $this->block() . "\nErrorDocument 404 /404.html\n";
        $this->assertSame("Options -Indexes\nErrorDocument 404 /404.html\n", $this->h->replace_block($content, ''));
    }

    public function test_removal_without_a_block_changes_nothing() {
        $this->assertSame(self::FOREIGN, $this->h->replace_block(self::FOREIGN, ''));
    }

    public function test_read_target_reports_absent_and_present_files() {
        $this->assertSame(['existed' => false, 'content' => ''], $this->h->read_target('uploads'));
        $this->put('uploads', self::FOREIGN);
        $this->assertSame(['existed' => true, 'content' => self::FOREIGN], $this->h->read_target('uploads'));
        $this->assertSame($this->uploads . '/.htaccess', $this->h->target_file('uploads'));
        $this->assertSame($this->content . '/.htaccess', $this->h->target_file('content'));
    }

    public function test_read_target_never_reports_an_unreadable_file_as_empty() {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('Running as root: every file is readable.');
        }
        $this->put('content', self::FOREIGN);
        // Writable but not readable: is_writable() is true, file_get_contents() fails.
        chmod($this->htaccess('content'), 0200);

        $this->assertSame(['existed' => true, 'content' => '', 'unreadable' => true], $this->h->read_target('content'));
    }

    public function test_commit_creates_the_file_and_reads_it_back() {
        $content = $this->block() . "\n";
        $this->assertTrue($this->h->commit_target('content', $content, '', false));
        $this->assertSame($content, $this->get('content'));
    }

    public function test_commit_deletes_a_file_it_created_once_it_is_empty() {
        $this->put('content', $this->block() . "\n");
        $this->assertTrue($this->h->commit_target('content', '', $this->block() . "\n", false));
        $this->assertFileDoesNotExist($this->htaccess('content'));
    }

    public function test_commit_keeps_an_emptied_file_that_existed_before() {
        $this->put('content', $this->block() . "\n");
        $this->assertTrue($this->h->commit_target('content', '', $this->block() . "\n", true));
        $this->assertSame('', $this->get('content'));
    }

    public function test_commit_with_unchanged_content_writes_nothing() {
        $writes = 0;
        $this->h->put_hook = function () use (&$writes) {
            $writes++;
            return null;
        };
        $this->assertTrue($this->h->commit_target('content', '', '', false));
        $this->put('content', self::FOREIGN);
        $this->assertTrue($this->h->commit_target('content', self::FOREIGN, self::FOREIGN, true));
        $this->assertSame(0, $writes);
        $this->assertSame(self::FOREIGN, $this->get('content'));
    }

    public function test_commit_detects_a_short_write_by_sha1_and_restore_puts_the_bytes_back() {
        $this->put('content', self::FOREIGN);
        $new = $this->h->replace_block(self::FOREIGN, $this->block());

        // Quota exhausted mid-write: only the first 40 bytes reach the disk, once.
        $failed = false;
        $this->h->put_hook = function ($file, $content) use (&$failed) {
            if ($failed) {
                return null;
            }
            $failed = true;
            return file_put_contents($file, substr($content, 0, 40));
        };

        $this->assertFalse($this->h->commit_target('content', $new, self::FOREIGN, true));
        $this->assertNotSame(self::FOREIGN, $this->get('content'));

        $this->assertTrue($this->h->restore_target('content', self::FOREIGN, true));
        $this->assertSame(self::FOREIGN, $this->get('content'));
    }

    public function test_restore_deletes_a_file_that_did_not_exist_before() {
        $this->put('uploads', $this->h->build_block('uploads', ['block_uploads_php']) . "\n");
        $this->assertTrue($this->h->restore_target('uploads', '', false));
        $this->assertFileDoesNotExist($this->htaccess('uploads'));
    }

    public function test_restore_reports_failure_when_the_bytes_do_not_come_back() {
        $this->put('content', 'garbage');
        $this->h->put_hook = function () {
            return false;
        };
        $this->assertFalse($this->h->restore_target('content', self::FOREIGN, true));
    }
}

<?php
/**
 * Real .htaccess content from audited sites and from the audit procedure, used by
 * the adoption tests. Never "tidy" these strings: the matcher has to cope with
 * exactly what is on the servers.
 */
class LSM_Htaccess_Fixtures {

    /**
     * wp-content/.htaccess of midnightblue-duck-937654.hostingersite.com, byte for byte
     * (wp-audits/midnightblue-duck-..._2026-09-07/scan_verify.txt:319-327). Written with explicit
     * escapes because line 2 really ends in a space ("php_value ") that editors like to strip.
     */
    const MIDNIGHTBLUE_CONTENT = "<IfModule litespeed>\nphp_value \n</IfModule>\n"
        . "<Files \"debug.log\">\nRequire all denied\n</Files>\n"
        . "<FilesMatch \"\\.(wpress|sql|zip|tar|gz|bak)$\">\nRequire all denied\n</FilesMatch>\n";

    /**
     * uploads/.htaccess of midnightblue-duck and of drjung.ch — identical
     * (scan_verify.txt:333-335 and audits/drjung.ch_2026-09-10/scan_verify.txt:288-290).
     */
    const AUDITED_UPLOADS = <<<'HT'
<FilesMatch "\.php$">
Require all denied
</FilesMatch>

HT;

    /**
     * The three blocks exactly as the audit skill appends them (SKILL.md:344-350 and :377-381),
     * each after the blank line harden_htaccess() puts in front.
     */
    const SKILL_CONTENT = <<<'HT'
# BEGIN WebP Express
AddType image/webp .webp
# END WebP Express

<Files "debug.log">
Deny from all
</Files>

<FilesMatch "\.(wpress|sql|zip|tar|gz|bak)$">
  <IfModule mod_authz_core.c>
    Require all denied
  </IfModule>
</FilesMatch>

HT;

    const SKILL_UPLOADS = <<<'HT'

<FilesMatch "\.php$">
Deny from all
</FilesMatch>

HT;
}

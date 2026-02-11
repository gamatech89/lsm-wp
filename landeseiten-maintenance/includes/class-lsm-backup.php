<?php
/**
 * Backup functionality for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM Backup class.
 * 
 * Handles WordPress site backups including database and files.
 */
class LSM_Backup {

    /**
     * Backup directory path.
     */
    const BACKUP_DIR = 'lsm-backups';

    /**
     * Get the backup directory path.
     *
     * @return string
     */
    public static function get_backup_dir() {
        $upload_dir = wp_upload_dir();
        $backup_dir = $upload_dir['basedir'] . '/' . self::BACKUP_DIR;
        
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
            // Add .htaccess to protect backups
            file_put_contents($backup_dir . '/.htaccess', 'deny from all');
            // Add index.php to prevent directory listing
            file_put_contents($backup_dir . '/index.php', '<?php // Silence is golden');
        }
        
        return $backup_dir;
    }

    /**
     * Create a full site backup.
     *
     * @param array $options Backup options.
     * @return array Backup result.
     */
    public static function create_backup($options = []) {
        $defaults = [
            'includes_database' => true,
            'includes_files' => true,
            'includes_uploads' => true,
        ];
        $options = wp_parse_args($options, $defaults);

        // Check if ZipArchive is available
        if (!class_exists('ZipArchive')) {
            return [
                'success' => false,
                'message' => 'ZipArchive extension is not available',
            ];
        }

        // Generate backup filename
        $timestamp = date('Y-m-d_His');
        $site_name = sanitize_file_name(parse_url(home_url(), PHP_URL_HOST));
        $backup_name = "backup_{$site_name}_{$timestamp}.zip";
        $backup_path = self::get_backup_dir() . '/' . $backup_name;

        // Create temporary directory for backup files
        $temp_dir = self::get_backup_dir() . '/temp_' . $timestamp;
        wp_mkdir_p($temp_dir);

        try {
            // Export database if requested
            if ($options['includes_database']) {
                $db_file = self::export_database($temp_dir);
                if (!$db_file) {
                    throw new Exception('Failed to export database');
                }
            }

            // Create the ZIP archive
            $zip = new ZipArchive();
            if ($zip->open($backup_path, ZipArchive::CREATE) !== true) {
                throw new Exception('Failed to create ZIP archive');
            }

            // Add database dump to ZIP
            if ($options['includes_database'] && isset($db_file)) {
                $zip->addFile($db_file, 'database.sql');
            }

            // Add WordPress files if requested
            if ($options['includes_files']) {
                self::add_files_to_zip($zip, ABSPATH, '', $options['includes_uploads']);
            }

            $zip->close();

            // Get backup size
            $backup_size = filesize($backup_path);

            // Clean up temp directory
            self::delete_directory($temp_dir);

            // Log the backup
            LSM_Logger::log('Backup created: ' . $backup_name . ' (' . size_format($backup_size) . ')');

            // Generate download token
            $download_token = wp_generate_password(32, false);
            set_transient('lsm_backup_token_' . $download_token, $backup_name, HOUR_IN_SECONDS);

            return [
                'success' => true,
                'message' => 'Backup created successfully',
                'backup_file' => $backup_name,
                'backup_size' => $backup_size,
                'backup_size_human' => size_format($backup_size),
                'download_url' => rest_url('lsm/v1/backup/download') . '?token=' . $download_token,
                'created_at' => current_time('mysql'),
            ];

        } catch (Exception $e) {
            // Clean up on failure
            self::delete_directory($temp_dir);
            if (file_exists($backup_path)) {
                unlink($backup_path);
            }

            LSM_Logger::log('Backup failed: ' . $e->getMessage(), 'error');

            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Export database to SQL file.
     *
     * @param string $dir Directory to save the SQL file.
     * @return string|false Path to SQL file or false on failure.
     */
    private static function export_database($dir) {
        global $wpdb;

        $sql_file = $dir . '/database.sql';
        $handle = fopen($sql_file, 'w');

        if (!$handle) {
            return false;
        }

        // Add header
        fwrite($handle, "-- LSM Backup Database Export\n");
        fwrite($handle, "-- Generated: " . date('Y-m-d H:i:s') . "\n");
        fwrite($handle, "-- WordPress: " . get_bloginfo('version') . "\n");
        fwrite($handle, "-- Site URL: " . get_site_url() . "\n\n");
        fwrite($handle, "SET NAMES utf8mb4;\n");
        fwrite($handle, "SET SQL_MODE = '';\n\n");

        // Get all tables with WordPress prefix
        $tables = $wpdb->get_results("SHOW TABLES LIKE '{$wpdb->prefix}%'", ARRAY_N);

        foreach ($tables as $table) {
            $table_name = $table[0];

            // Get CREATE TABLE statement
            $create = $wpdb->get_row("SHOW CREATE TABLE `{$table_name}`", ARRAY_N);
            fwrite($handle, "\n-- Table: {$table_name}\n");
            fwrite($handle, "DROP TABLE IF EXISTS `{$table_name}`;\n");
            fwrite($handle, $create[1] . ";\n\n");

            // Get table data
            $rows = $wpdb->get_results("SELECT * FROM `{$table_name}`", ARRAY_A);

            if (!empty($rows)) {
                $columns = array_keys($rows[0]);
                $column_list = '`' . implode('`, `', $columns) . '`';

                foreach ($rows as $row) {
                    $values = array_map(function($value) use ($wpdb) {
                        if ($value === null) {
                            return 'NULL';
                        }
                        return "'" . esc_sql($value) . "'";
                    }, $row);

                    fwrite($handle, "INSERT INTO `{$table_name}` ({$column_list}) VALUES (" . implode(', ', $values) . ");\n");
                }
            }
        }

        fclose($handle);
        return $sql_file;
    }

    /**
     * Add files to ZIP archive.
     *
     * @param ZipArchive $zip ZIP archive object.
     * @param string $source Source directory.
     * @param string $prefix Path prefix in archive.
     * @param bool $include_uploads Whether to include uploads.
     */
    private static function add_files_to_zip($zip, $source, $prefix = '', $include_uploads = true) {
        $source = realpath($source);
        
        // Directories to skip
        $skip_dirs = [
            self::get_backup_dir(), // Don't backup backups
            WP_CONTENT_DIR . '/cache',
            WP_CONTENT_DIR . '/upgrade',
            WP_CONTENT_DIR . '/wflogs', // Wordfence logs
        ];
        
        if (!$include_uploads) {
            $skip_dirs[] = WP_CONTENT_DIR . '/uploads';
        }

        // Files to skip
        $skip_files = [
            '.git',
            '.gitignore',
            '.htaccess.bak',
            'debug.log',
            'error_log',
        ];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $path = $file->getRealPath();
            $relative_path = $prefix . substr($path, strlen($source) + 1);

            // Skip directories in skip list
            $skip = false;
            foreach ($skip_dirs as $skip_dir) {
                if (strpos($path, $skip_dir) === 0) {
                    $skip = true;
                    break;
                }
            }

            // Skip specific files
            foreach ($skip_files as $skip_file) {
                if (strpos($file->getFilename(), $skip_file) !== false) {
                    $skip = true;
                    break;
                }
            }

            if ($skip) {
                continue;
            }

            if ($file->isDir()) {
                $zip->addEmptyDir($relative_path);
            } else {
                // Skip files larger than 100MB
                if ($file->getSize() > 100 * 1024 * 1024) {
                    continue;
                }
                $zip->addFile($path, $relative_path);
            }
        }
    }

    /**
     * List available backups.
     *
     * @return array List of backups.
     */
    public static function list_backups() {
        $backup_dir = self::get_backup_dir();
        $backups = [];

        if (!is_dir($backup_dir)) {
            return $backups;
        }

        $files = glob($backup_dir . '/backup_*.zip');
        
        foreach ($files as $file) {
            $backups[] = [
                'filename' => basename($file),
                'size' => filesize($file),
                'size_human' => size_format(filesize($file)),
                'created_at' => date('Y-m-d H:i:s', filemtime($file)),
            ];
        }

        // Sort by date, newest first
        usort($backups, function($a, $b) {
            return strtotime($b['created_at']) - strtotime($a['created_at']);
        });

        return $backups;
    }

    /**
     * Download a backup file.
     *
     * @param string $token Download token.
     * @return bool|string Path to backup file or false.
     */
    public static function get_backup_by_token($token) {
        $backup_name = get_transient('lsm_backup_token_' . $token);
        
        if (!$backup_name) {
            return false;
        }

        $backup_path = self::get_backup_dir() . '/' . $backup_name;
        
        if (!file_exists($backup_path)) {
            return false;
        }

        return $backup_path;
    }

    /**
     * Delete a backup.
     *
     * @param string $filename Backup filename.
     * @return bool
     */
    public static function delete_backup($filename) {
        // Sanitize filename
        $filename = sanitize_file_name($filename);
        
        // Ensure it's a backup file
        if (strpos($filename, 'backup_') !== 0 || substr($filename, -4) !== '.zip') {
            return false;
        }

        $backup_path = self::get_backup_dir() . '/' . $filename;
        
        if (file_exists($backup_path)) {
            unlink($backup_path);
            LSM_Logger::log('Backup deleted: ' . $filename);
            return true;
        }

        return false;
    }

    /**
     * Restore from a backup.
     *
     * @param string $filename Backup filename.
     * @return array Restore result.
     */
    public static function restore_backup($filename) {
        // Sanitize filename
        $filename = sanitize_file_name($filename);
        $backup_path = self::get_backup_dir() . '/' . $filename;

        if (!file_exists($backup_path)) {
            return [
                'success' => false,
                'message' => 'Backup file not found',
            ];
        }

        try {
            // Enable maintenance mode during restore
            LSM_Maintenance_Mode::enable();

            $zip = new ZipArchive();
            if ($zip->open($backup_path) !== true) {
                throw new Exception('Failed to open backup archive');
            }

            // Extract to temporary directory
            $temp_dir = self::get_backup_dir() . '/restore_' . time();
            wp_mkdir_p($temp_dir);

            $zip->extractTo($temp_dir);
            $zip->close();

            // Restore database if present
            $db_file = $temp_dir . '/database.sql';
            if (file_exists($db_file)) {
                self::import_database($db_file);
            }

            // Clean up
            self::delete_directory($temp_dir);

            // Disable maintenance mode
            LSM_Maintenance_Mode::disable();

            LSM_Logger::log('Backup restored: ' . $filename);

            return [
                'success' => true,
                'message' => 'Backup restored successfully',
            ];

        } catch (Exception $e) {
            LSM_Maintenance_Mode::disable();
            LSM_Logger::log('Restore failed: ' . $e->getMessage(), 'error');

            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Import database from SQL file.
     *
     * @param string $sql_file Path to SQL file.
     */
    private static function import_database($sql_file) {
        global $wpdb;

        $sql = file_get_contents($sql_file);
        
        // Split into individual queries
        $queries = preg_split('/;\s*$/m', $sql);

        foreach ($queries as $query) {
            $query = trim($query);
            if (!empty($query) && strpos($query, '--') !== 0) {
                $wpdb->query($query);
            }
        }
    }

    /**
     * Delete directory recursively.
     *
     * @param string $dir Directory path.
     */
    private static function delete_directory($dir) {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (is_dir($path)) {
                self::delete_directory($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }

    /**
     * Cleanup old backups based on retention settings.
     *
     * @param int $max_backups Maximum number of backups to keep.
     * @param int $max_age_days Maximum age of backups in days.
     * @return int Number of backups deleted.
     */
    public static function cleanup_old_backups($max_backups = 10, $max_age_days = 30) {
        $backups = self::list_backups();
        $deleted = 0;
        $kept = 0;

        foreach ($backups as $backup) {
            $age_days = (time() - strtotime($backup['created_at'])) / DAY_IN_SECONDS;

            // Delete if too old or over max count
            if ($age_days > $max_age_days || $kept >= $max_backups) {
                if (self::delete_backup($backup['filename'])) {
                    $deleted++;
                }
            } else {
                $kept++;
            }
        }

        return $deleted;
    }
}

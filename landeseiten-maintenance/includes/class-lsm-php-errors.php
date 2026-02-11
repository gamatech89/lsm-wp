<?php
/**
 * PHP Error logging for Landeseiten Maintenance.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * LSM PHP Errors class.
 * 
 * Captures and logs PHP errors for reporting to the management dashboard.
 */
class LSM_Php_Errors {

    /**
     * Error log option name.
     */
    const OPTION_NAME = 'lsm_php_errors';

    /**
     * Maximum number of errors to store.
     */
    const MAX_ERRORS = 100;

    /**
     * Initialize error handling.
     */
    public static function init() {
        // Register error handler
        set_error_handler([__CLASS__, 'handle_error']);
        
        // Register shutdown function for fatal errors
        register_shutdown_function([__CLASS__, 'handle_shutdown']);
    }

    /**
     * Handle PHP errors.
     *
     * @param int $errno Error number.
     * @param string $errstr Error message.
     * @param string $errfile Error file.
     * @param int $errline Error line.
     * @return bool
     */
    public static function handle_error($errno, $errstr, $errfile, $errline) {
        // Don't log suppressed errors
        if (!(error_reporting() & $errno)) {
            return false;
        }

        $type = self::get_error_type($errno);
        
        // Only log errors, warnings, and notices
        if (!in_array($type, ['fatal', 'warning', 'notice', 'deprecated'])) {
            return false;
        }

        self::log_error([
            'type' => $type,
            'message' => $errstr,
            'file' => $errfile,
            'line' => $errline,
        ]);

        // Continue with normal error handling
        return false;
    }

    /**
     * Handle shutdown for fatal errors.
     */
    public static function handle_shutdown() {
        $error = error_get_last();
        
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            self::log_error([
                'type' => 'fatal',
                'message' => $error['message'],
                'file' => $error['file'],
                'line' => $error['line'],
            ]);
        }
    }

    /**
     * Get error type string.
     *
     * @param int $errno Error number.
     * @return string
     */
    private static function get_error_type($errno) {
        switch ($errno) {
            case E_ERROR:
            case E_PARSE:
            case E_CORE_ERROR:
            case E_COMPILE_ERROR:
            case E_USER_ERROR:
                return 'fatal';
            case E_WARNING:
            case E_CORE_WARNING:
            case E_COMPILE_WARNING:
            case E_USER_WARNING:
                return 'warning';
            case E_NOTICE:
            case E_USER_NOTICE:
                return 'notice';
            case E_DEPRECATED:
            case E_USER_DEPRECATED:
                return 'deprecated';
            case E_STRICT:
                return 'strict';
            default:
                return 'unknown';
        }
    }

    /**
     * Log an error.
     *
     * @param array $error Error data.
     */
    public static function log_error($error) {
        $errors = get_option(self::OPTION_NAME, []);
        
        // Generate hash for grouping similar errors
        $hash = md5($error['type'] . $error['message'] . $error['file'] . $error['line']);
        
        // Check if this error already exists
        $found = false;
        foreach ($errors as $key => $existing) {
            if (isset($existing['hash']) && $existing['hash'] === $hash) {
                // Increment count and update last seen
                $errors[$key]['count'] = ($existing['count'] ?? 1) + 1;
                $errors[$key]['last_seen_at'] = current_time('mysql');
                $found = true;
                break;
            }
        }

        if (!$found) {
            // Add new error
            $error['hash'] = $hash;
            $error['count'] = 1;
            $error['first_seen_at'] = current_time('mysql');
            $error['last_seen_at'] = current_time('mysql');
            $error['resolved'] = false;
            
            // Detect plugin if error is in plugins directory
            $error['plugin_slug'] = self::detect_plugin($error['file']);
            
            // Add to beginning of array
            array_unshift($errors, $error);
        }

        // Keep only recent errors
        $errors = array_slice($errors, 0, self::MAX_ERRORS);

        update_option(self::OPTION_NAME, $errors, false);
    }

    /**
     * Detect which plugin an error belongs to.
     *
     * @param string $file File path.
     * @return string|null
     */
    private static function detect_plugin($file) {
        if (strpos($file, WP_PLUGIN_DIR) === false) {
            return null;
        }

        $relative = str_replace(WP_PLUGIN_DIR . '/', '', $file);
        $parts = explode('/', $relative);
        
        return $parts[0] ?? null;
    }

    /**
     * Get all errors.
     *
     * @param array $filters Optional filters.
     * @return array
     */
    public static function get_errors($filters = []) {
        $errors = get_option(self::OPTION_NAME, []);
        
        // Filter by type
        if (!empty($filters['type'])) {
            $errors = array_filter($errors, function($error) use ($filters) {
                return $error['type'] === $filters['type'];
            });
        }

        // Filter unresolved only
        if (!empty($filters['unresolved'])) {
            $errors = array_filter($errors, function($error) {
                return empty($error['resolved']);
            });
        }

        // Search
        if (!empty($filters['search'])) {
            $search = strtolower($filters['search']);
            $errors = array_filter($errors, function($error) use ($search) {
                return strpos(strtolower($error['message']), $search) !== false ||
                       strpos(strtolower($error['file']), $search) !== false;
            });
        }

        return array_values($errors);
    }

    /**
     * Get error statistics.
     *
     * @return array
     */
    public static function get_stats() {
        $errors = get_option(self::OPTION_NAME, []);
        
        $stats = [
            'total' => count($errors),
            'unresolved' => 0,
            'by_type' => [
                'fatal' => 0,
                'warning' => 0,
                'notice' => 0,
                'deprecated' => 0,
            ],
            'last_error' => null,
        ];

        foreach ($errors as $error) {
            if (empty($error['resolved'])) {
                $stats['unresolved']++;
            }
            if (isset($stats['by_type'][$error['type']])) {
                $stats['by_type'][$error['type']]++;
            }
        }

        if (!empty($errors)) {
            $stats['last_error'] = $errors[0]['last_seen_at'] ?? null;
        }

        return $stats;
    }

    /**
     * Resolve an error by hash.
     *
     * @param string $hash Error hash.
     * @return bool
     */
    public static function resolve_error($hash) {
        $errors = get_option(self::OPTION_NAME, []);
        
        foreach ($errors as $key => $error) {
            if (isset($error['hash']) && $error['hash'] === $hash) {
                $errors[$key]['resolved'] = true;
                $errors[$key]['resolved_at'] = current_time('mysql');
                update_option(self::OPTION_NAME, $errors, false);
                return true;
            }
        }

        return false;
    }

    /**
     * Delete an error by hash.
     *
     * @param string $hash Error hash.
     * @return bool
     */
    public static function delete_error($hash) {
        $errors = get_option(self::OPTION_NAME, []);
        
        foreach ($errors as $key => $error) {
            if (isset($error['hash']) && $error['hash'] === $hash) {
                unset($errors[$key]);
                update_option(self::OPTION_NAME, array_values($errors), false);
                return true;
            }
        }

        return false;
    }

    /**
     * Clear all errors.
     *
     * @return bool
     */
    public static function clear_errors() {
        return delete_option(self::OPTION_NAME);
    }
}

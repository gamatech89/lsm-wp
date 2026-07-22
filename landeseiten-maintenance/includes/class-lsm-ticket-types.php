<?php
/**
 * Single source of truth for support-ticket types, client priorities, and
 * their inline SVG icons. Consumed by the flying widget (via
 * wp_localize_script), the wp-admin support form, and the email builder.
 *
 * @package Landeseiten_Maintenance
 */

if (!defined('ABSPATH')) {
    exit;
}

class LSM_Ticket_Types {

    /**
     * Ticket types offered in the pickers: code => [label, icon].
     * 'urgent' is intentionally absent — urgency is now a priority, not a
     * type. (The platform keeps 'urgent' in its enum for historical tickets.)
     */
    public static function types() {
        return [
            'bug'      => ['label' => __('Bug / Error', 'landeseiten-maintenance'),    'icon' => 'bug'],
            'content'  => ['label' => __('Content Change', 'landeseiten-maintenance'), 'icon' => 'file-text'],
            'design'   => ['label' => __('Design Change', 'landeseiten-maintenance'),  'icon' => 'palette'],
            'feature'  => ['label' => __('New Feature', 'landeseiten-maintenance'),    'icon' => 'sparkles'],
            'question' => ['label' => __('Question', 'landeseiten-maintenance'),       'icon' => 'help-circle'],
        ];
    }

    /**
     * Client-facing priority levels: code => [label, severity]. `severity` is
     * the platform's staff-owned scale that the client choice seeds.
     */
    public static function priorities() {
        return [
            'normal' => ['label' => __('Normal', 'landeseiten-maintenance'), 'severity' => 'medium'],
            'high'   => ['label' => __('High', 'landeseiten-maintenance'),   'severity' => 'high'],
            'urgent' => ['label' => __('Urgent', 'landeseiten-maintenance'), 'severity' => 'critical'],
        ];
    }

    /** Default priority code. */
    public static function default_priority() {
        return 'normal';
    }

    /** Human label for a type code (email/back-compat), falls back to the code. */
    public static function type_label($code) {
        $types = self::types();
        return isset($types[$code]) ? $types[$code]['label'] : $code;
    }

    /** Inline SVG icon markup for a key ('' for unknown keys). */
    public static function icon($key) {
        $icons = self::icons();
        return isset($icons[$key]) ? $icons[$key] : '';
    }

    /**
     * icon-key => SVG string. Static trusted markup — Lucide-style line icons,
     * 24x24, stroke:currentColor. Safe to echo without escaping.
     */
    public static function icons() {
        return [
            'bug' => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>',
            'file-text' => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>',
            'palette' => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/></svg>',
            'sparkles' => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .962 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.962 0z"/><path d="M20 3v4"/><path d="M22 5h-4"/><path d="M4 17v2"/><path d="M5 18H3"/></svg>',
            'help-circle' => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>',
        ];
    }
}

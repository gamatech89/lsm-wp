# LSM WordPress Plugin

WordPress plugin for the LSM Platform maintenance management.

## Installation

1. Download the plugin zip
2. Upload to WordPress via Plugins → Add New → Upload Plugin
3. Activate the plugin
4. Configure the plugin settings

## Features

- Maintenance reporting
- Client dashboard
- Integration with LSM Platform API

## Development

The plugin follows WordPress coding standards.

## Structure

```
lsm-maintenance-plugin/
├── includes/         # PHP includes
├── assets/          # CSS/JS assets
└── lsm-maintenance.php   # Main plugin file
```

## Deployment

Package the plugin:

```bash
zip -r lsm-maintenance-plugin.zip lsm-maintenance-plugin/
```

Upload to WordPress sites via admin panel or FTP.

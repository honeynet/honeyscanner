ERROR_MESSAGES = {
    'invalid_ip': {
        'user': 'Invalid IP address provided. Please enter a valid IP address.',
        'log': 'IP validation failed for: {ip}'
    },
    'connection_timeout': {
        'user': 'Connection timed out. Please check if target is reachable.',
        'log': 'Connection timeout for {ip} after {timeout}s'
    },
    'port_scan_failed': {
        'user': 'Port scan failed. Please verify target accessibility.',
        'log': 'Port scan error on {ip}: {error}'
    }
}

#!/usr/local/bin/php
<?php
require_once 'util.inc';
require_once 'config.inc';
require_once 'XMLRPC_Client.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/EndpointSync.php';

use OPNsense\ApiExtensions\EndpointSync;

try {
    global $config;
    if (empty($config['hasync']['synchronizetoip'])) {
        throw new \RuntimeException('HA configuration synchronization peer is not configured');
    }

    $preparePayload = EndpointSync::buildPayload($config, false);
    $prepared = xmlrpc_execute('opnsense.api_extensions_sync_endpoints', $preparePayload);
    if (!is_array($prepared) || ($prepared['status'] ?? '') !== 'ok') {
        throw new \RuntimeException('endpoint scaffold peer prepare failed');
    }

    $output = [];
    $status = 0;
    exec('/usr/local/etc/rc.filter_synchronize restart_services 2>&1', $output, $status);
    if ($status !== 0) {
        throw new \RuntimeException(sprintf('standard HA configuration synchronization failed with exit status %d', $status));
    }

    $prunePayload = EndpointSync::buildPayload($config, true);
    $pruned = xmlrpc_execute('opnsense.api_extensions_sync_endpoints', $prunePayload);
    if (!is_array($pruned) || ($pruned['status'] ?? '') !== 'ok') {
        throw new \RuntimeException('endpoint scaffold peer prune failed');
    }

    echo json_encode([
        'status' => 'ok',
        'endpoint_count' => count($preparePayload['endpoints']),
        'endpoint_changed' => !empty($prepared['changed']) || !empty($pruned['changed']),
    ]);
    echo PHP_EOL;
} catch (\Throwable $error) {
    echo json_encode(['status' => 'failed', 'message' => $error->getMessage()]), PHP_EOL;
    exit(1);
}

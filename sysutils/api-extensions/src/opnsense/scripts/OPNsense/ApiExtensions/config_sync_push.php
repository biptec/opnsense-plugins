#!/usr/local/bin/php
<?php
require_once 'util.inc';
require_once 'config.inc';
require_once 'XMLRPC_Client.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';

use OPNsense\ApiExtensions\InterfaceSync;

try {
    global $config;
    if (empty($config['hasync']['synchronizetoip'])) {
        throw new \RuntimeException('HA configuration synchronization peer is not configured');
    }

    $preparePayload = InterfaceSync::buildPayload($config, false);
    $prepared = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $preparePayload);
    if (!is_array($prepared) || ($prepared['status'] ?? '') !== 'ok') {
        throw new \RuntimeException('policy-managed interface peer prepare failed');
    }

    $output = [];
    $status = 0;
    // The standard restore path already applies VIPs and calls remote filter_configure,
    // which reconfigures routing, resolver state, and PF.  Do not request the optional
    // global service restart sweep here: it restarts configd itself while CARP hooks are
    // still issuing configd requests and creates a transient control-plane outage.
    exec('/usr/local/etc/rc.filter_synchronize 2>&1', $output, $status);
    if ($status !== 0) {
        throw new \RuntimeException(sprintf('standard HA configuration synchronization failed with exit status %d', $status));
    }

    $prunePayload = InterfaceSync::buildPayload($config, true);
    $pruned = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $prunePayload);
    if (!is_array($pruned) || ($pruned['status'] ?? '') !== 'ok') {
        throw new \RuntimeException('policy-managed interface peer prune failed');
    }

    echo json_encode([
        'status' => 'ok',
        'interface_count' => count($preparePayload['interfaces']),
        'interface_changed' => !empty($prepared['changed']) || !empty($pruned['changed']),
    ]);
    echo PHP_EOL;
} catch (\Throwable $error) {
    echo json_encode(['status' => 'failed', 'message' => $error->getMessage()]), PHP_EOL;
    exit(1);
}

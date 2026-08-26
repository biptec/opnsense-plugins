#!/usr/local/bin/php
<?php
require_once 'util.inc';
require_once 'config.inc';
require_once 'XMLRPC_Client.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;

try {
    global $config;
    if (empty($config['hasync']['synchronizetoip'])) {
        throw new \RuntimeException('HA configuration synchronization peer is not configured');
    }

    $interfaceEnabled = InterfaceSync::isEnabled($config);
    $haproxyEnabled = HAProxySync::isEnabled($config);
    if (!$interfaceEnabled && !$haproxyEnabled) {
        throw new \RuntimeException('no policy-managed HA synchronization service is enabled');
    }

    // Validate all selected custom services before changing the peer. A bad HAProxy
    // assignment must fail before native VIP/rule/static-route synchronization starts.
    $preparePayload = $interfaceEnabled ? InterfaceSync::buildPayload($config, false) : null;
    $prunePayload = $interfaceEnabled ? InterfaceSync::buildPayload($config, true) : null;
    $haproxyPayload = $haproxyEnabled ? HAProxySync::buildPayload($config) : null;

    $prepared = ['changed' => false];
    if ($interfaceEnabled) {
        $prepared = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $preparePayload);
        if (!is_array($prepared) || ($prepared['status'] ?? '') !== 'ok') {
            throw new \RuntimeException('policy-managed interface peer prepare failed');
        }
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

    $pruned = ['changed' => false];
    if ($interfaceEnabled) {
        $pruned = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $prunePayload);
        if (!is_array($pruned) || ($pruned['status'] ?? '') !== 'ok') {
            throw new \RuntimeException('policy-managed interface peer prune failed');
        }
    }

    $haproxy = ['changed' => false];
    if ($haproxyEnabled) {
        $haproxy = xmlrpc_execute('opnsense.api_extensions_sync_haproxy', $haproxyPayload);
        if (!is_array($haproxy) || ($haproxy['status'] ?? '') !== 'ok') {
            $peerMessage = is_array($haproxy) ? trim((string)($haproxy['message'] ?? '')) : '';
            throw new \RuntimeException(
                'policy-managed HAProxy peer synchronization failed' .
                ($peerMessage !== '' ? ': ' . $peerMessage : '')
            );
        }
    }

    echo json_encode([
        'status' => 'ok',
        'interface_count' => $interfaceEnabled ? count($preparePayload['interfaces']) : 0,
        'interface_changed' => !empty($prepared['changed']) || !empty($pruned['changed']),
        'haproxy_count' => $haproxyEnabled ? count($haproxyPayload['objects']) : 0,
        'haproxy_changed' => !empty($haproxy['changed']),
    ]);
    echo PHP_EOL;
} catch (\Throwable $error) {
    // configd script_output actions discard useful stdout when the command exits
    // non-zero. The synchronization contract is JSON, so return failures in-band
    // and let the API/client fail on status=failed with the original message.
    echo json_encode(['status' => 'failed', 'message' => $error->getMessage()]), PHP_EOL;
}

<?php

require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;

function api_extensions_interface_sync_validate()
{
    global $config;
    InterfaceSync::buildPayload($config, false);
    InterfaceSync::buildPayload($config, true);
    return true;
}

function api_extensions_interface_sync_prepare()
{
    global $config;
    $payload = InterfaceSync::buildPayload($config, false);
    $result = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $payload);
    if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
        $message = is_array($result) ? trim((string)($result['message'] ?? '')) : '';
        throw new \RuntimeException('policy-managed interface peer prepare failed' . ($message !== '' ? ': ' . $message : ''));
    }
    return true;
}

function api_extensions_interface_sync_finalize()
{
    global $config;
    $payload = InterfaceSync::buildPayload($config, true);
    $result = xmlrpc_execute('opnsense.api_extensions_sync_interfaces', $payload);
    if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
        $message = is_array($result) ? trim((string)($result['message'] ?? '')) : '';
        throw new \RuntimeException('policy-managed interface peer prune failed' . ($message !== '' ? ': ' . $message : ''));
    }
    return true;
}

function api_extensions_haproxy_sync_validate()
{
    global $config;
    HAProxySync::buildPayload($config);
    return true;
}

function api_extensions_haproxy_sync_finalize()
{
    global $config;
    $payload = HAProxySync::buildPayload($config);
    $result = xmlrpc_execute('opnsense.api_extensions_sync_haproxy', $payload);
    if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
        $message = is_array($result) ? trim((string)($result['message'] ?? '')) : '';
        throw new \RuntimeException('policy-managed HAProxy peer synchronization failed' . ($message !== '' ? ': ' . $message : ''));
    }
    return true;
}

function api_extensions_xmlrpc_sync()
{
    return [
        [
            'description' => gettext('Interfaces'),
            'help' => gettext(
                'Synchronize interfaces selected by explicit HA policies to the other HA host.'
            ),
            'id' => 'interface_vlans',
            'sync_validate' => 'api_extensions_interface_sync_validate',
            'sync_prepare' => 'api_extensions_interface_sync_prepare',
            'sync_finalize' => 'api_extensions_interface_sync_finalize',
        ],
        [
            'description' => gettext('HAProxy Objects'),
            'help' => gettext(
                'Synchronize explicitly assigned HAProxy servers and backends without replacing node-local HAProxy settings or frontends.'
            ),
            'id' => 'haproxy_objects',
            'sync_validate' => 'api_extensions_haproxy_sync_validate',
            'sync_finalize' => 'api_extensions_haproxy_sync_finalize',
        ],
    ];
}

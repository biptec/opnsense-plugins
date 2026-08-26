<?php
require_once 'config.inc';
require_once 'filter.inc';
require_once 'interfaces.inc';
require_once 'util.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

function xmlrpc_publishable_api_extensions()
{
    return [
        'api_extensions_sync_interfaces_xmlrpc',
        'api_extensions_sync_haproxy_xmlrpc',
    ];
}

function api_extensions_sync_interfaces_xmlrpc($payload)
{
    global $config;

    try {
        Config::getInstance()->lock();
        $result = InterfaceSync::reconcile($config, $payload, fn() => generate_uuid());
        if (!$result['changed']) {
            return ['status' => 'ok', 'changed' => false, 'count' => $result['count']];
        }

        foreach ($result['plan']['reset_interfaces'] as $identifier) {
            interface_reset($identifier);
        }

        $config = $result['config'];
        $saved = write_config('Synchronize endpoint interface scaffold from HA primary');
        if ($saved === false || $saved === -1) {
            throw new \RuntimeException('unable to save synchronized policy-managed interface scaffold');
        }

        foreach ($result['plan']['destroy_vlans'] as $device) {
            legacy_interface_destroy($device);
        }
        foreach ($result['plan']['configure_vlans'] as $device) {
            interfaces_vlan_configure($device);
        }
        foreach ($result['plan']['configure_interfaces'] as $identifier) {
            interface_configure(false, $identifier, true);
        }

        return [
            'status' => 'ok',
            'changed' => true,
            'count' => $result['count'],
        ];
    } catch (\Throwable $error) {
        log_msg('Policy-managed interface HA synchronization failed: ' . $error->getMessage(), LOG_ERR);
        return ['status' => 'failed', 'message' => $error->getMessage()];
    }
}

function api_extensions_sync_haproxy_xmlrpc($payload)
{
    global $config;

    $previous = $config;
    $savedNewConfig = false;
    try {
        Config::getInstance()->lock();
        $result = HAProxySync::reconcile(
            $config,
            $payload,
            fn() => generate_uuid(),
            fn() => uniqid('', true)
        );
        if (!$result['changed']) {
            return ['status' => 'ok', 'changed' => false, 'count' => $result['count']];
        }

        $config = $result['config'];
        $saved = write_config('Synchronize policy-managed HAProxy objects from HA primary');
        if ($saved === false || $saved === -1) {
            throw new \RuntimeException('unable to save synchronized HAProxy objects');
        }
        $savedNewConfig = true;

        $backend = new Backend();
        // HAProxy's configtest action validates haproxy.conf.staging, so the MVC
        // templates must be rendered after write_config() and before syntax testing.
        $backend->configdRun('template reload OPNsense/HAProxy');
        $configTest = trim($backend->configdRun('haproxy configtest'));
        // The native HAProxy WebUI treats ALERT output as the critical failure
        // signal. A valid configuration commonly returns an empty response.
        if (stripos($configTest, 'ALERT') !== false) {
            throw new \RuntimeException('synchronized HAProxy configuration failed validation: ' . api_extensions_haproxy_test_summary($configTest));
        }

        $enabled = api_extensions_haproxy_enabled($config);
        $backend->configdRun($enabled ? 'haproxy reload' : 'haproxy deploy');

        return [
            'status' => 'ok',
            'changed' => true,
            'count' => $result['count'],
        ];
    } catch (\Throwable $error) {
        if ($savedNewConfig) {
            $config = $previous;
            try {
                $rolledBack = write_config('Rollback failed policy-managed HAProxy synchronization');
                if ($rolledBack === false || $rolledBack === -1) {
                    throw new \RuntimeException('unable to save HAProxy synchronization rollback');
                }
                $backend = new Backend();
                $backend->configdRun('template reload OPNsense/HAProxy');
                $backend->configdRun(api_extensions_haproxy_enabled($previous) ? 'haproxy reload' : 'haproxy deploy');
            } catch (\Throwable $rollbackError) {
                log_msg('Policy-managed HAProxy synchronization rollback failed: ' . $rollbackError->getMessage(), LOG_ERR);
            }
        }
        log_msg('Policy-managed HAProxy synchronization failed: ' . $error->getMessage(), LOG_ERR);
        return ['status' => 'failed', 'message' => $error->getMessage()];
    }
}

function api_extensions_haproxy_enabled($candidate)
{
    return in_array(
        $candidate['OPNsense']['HAProxy']['general']['enabled'] ?? null,
        [1, '1', true, 'yes', 'on'],
        true
    );
}

function api_extensions_haproxy_test_summary($output)
{
    $summary = trim(preg_replace('/\s+/', ' ', (string)$output));
    if ($summary === '') {
        return 'empty configtest response';
    }
    if (strlen($summary) > 400) {
        return substr($summary, 0, 400) . '...';
    }
    return $summary;
}

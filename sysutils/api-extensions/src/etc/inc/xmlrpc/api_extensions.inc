<?php
require_once 'config.inc';
require_once 'filter.inc';
require_once 'interfaces.inc';
require_once 'util.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';

use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\Core\Config;

function xmlrpc_publishable_api_extensions()
{
    return ['api_extensions_sync_interfaces_xmlrpc'];
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

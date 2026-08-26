<?php

function api_extensions_xmlrpc_sync()
{
    return [
        [
            'description' => gettext('Policy-managed Interfaces / VLANs'),
            'help' => gettext(
                'Synchronize VLAN/interface scaffolding selected by explicit HA policies to the other HA host.'
            ),
            'section' => 'OPNsense.ApiExtensions.InterfaceSyncPolicy.sync_marker',
            'id' => 'interface_vlans',
        ],
        [
            'description' => gettext('Policy-managed HAProxy Objects'),
            'help' => gettext(
                'Synchronize explicitly assigned HAProxy servers and backends without replacing node-local HAProxy settings or frontends.'
            ),
            'section' => 'OPNsense.ApiExtensions.InterfaceSyncPolicy.haproxy_sync_marker',
            'id' => 'haproxy_objects',
        ],
    ];
}

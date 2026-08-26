<?php

function api_extensions_xmlrpc_sync()
{
    return [[
        'description' => gettext('Policy-managed Interfaces / VLANs'),
        'help' => gettext(
            'Synchronize VLAN/interface scaffolding selected by explicit interface policies to the other HA host.'
        ),
        'section' => 'OPNsense.ApiExtensions.InterfaceSyncPolicy.sync_marker',
        'id' => 'interface_vlans',
    ]];
}

<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/ReplacementHandoff.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\ApiExtensions\ReplacementHandoff;

function rhEq($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, $message . "\nexpected=" . var_export($expected, true) . "\nactual=" . var_export($actual, true) . "\n");
        exit(1);
    }
}

function rhBad(callable $fn, string $message): void
{
    try {
        $fn();
    } catch (InvalidArgumentException $error) {
        return;
    }
    fwrite(STDERR, $message . ": expected InvalidArgumentException\n");
    exit(1);
}

function rhPolicies(): array
{
    return [
        '@attributes' => ['uuid' => 'policy-root'],
        'shared' => [
            'policies' => [
                'policy' => [
                    [
                        '@attributes' => ['uuid' => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],
                        'id' => 'core',
                        'description' => 'Router core',
                        'synchronize' => '0',
                    ],
                    [
                        '@attributes' => ['uuid' => 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],
                        'id' => 'endpoint',
                        'description' => 'Endpoint consumers',
                        'synchronize' => '1',
                    ],
                ],
            ],
        ],
        'assignments' => ['assignment' => [
            [
                '@attributes' => ['uuid' => 'cccccccc-cccc-cccc-cccc-cccccccccccc'],
                'interface' => 'core_ha_control',
                'policy_id' => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            ],
            [
                '@attributes' => ['uuid' => 'cccccccc-cccc-cccc-cccc-dddddddddddd'],
                'interface' => 'lan',
                'policy_id' => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            ],
        ]],
        'replicas' => '',
        'haproxy_assignments' => '',
        'haproxy_replicas' => '',
    ];
}

function rhBase(string $syncTarget): array
{
    return [
        'hasync' => [
            'pfsyncinterface' => 'core_ha_control',
            'synchronizetoip' => $syncTarget,
            'syncitems' => 'virtualip,rules,staticroutes,aliases,users,interface_vlans,haproxy_objects',
        ],
        'interfaces' => [
            'lan' => ['if' => 'vtnet0', 'descr' => 'Bootstrap', 'enable' => '1'],
            'core_ha_control' => ['if' => 'vlan1901', 'descr' => 'HA control', 'enable' => '1'],
        ],
        'vlans' => ['vlan' => [
            [
                '@attributes' => ['uuid' => 'dddddddd-dddd-dddd-dddd-dddddddddddd'],
                'if' => 'vtnet1',
                'tag' => '1901',
                'pcp' => '0',
                'proto' => '',
                'descr' => 'HA control',
                'vlanif' => 'vlan1901',
            ],
        ]],
        'OPNsense' => [
            'ApiExtensions' => [
                'InterfaceSyncPolicy' => rhPolicies(),
            ],
            'HAProxy' => [
                'general' => ['enabled' => '1'],
                'healthchecks' => '',
                'servers' => '',
                'backends' => '',
                'frontends' => '',
            ],
            'Firewall' => [
                'Filter' => ['rules' => []],
                'Alias' => ['aliases' => []],
            ],
            'Gateways' => [],
        ],
        'virtualip' => ['vip' => []],
        'filter' => [],
        'staticroutes' => [],
        'gateways' => [],
        'aliases' => [],
        'system' => ['user' => [], 'group' => []],
    ];
}

function rhReplica(): array
{
    $config = rhBase('');
    $config['interfaces']['ep_customer'] = [
        'if' => 'vlan777',
        'descr' => 'Customer endpoint',
        'lock' => '0',
        'enable' => '1',
    ];
    $config['vlans']['vlan'][] = [
        '@attributes' => ['uuid' => 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'],
        'if' => 'vtnet1',
        'tag' => '777',
        'pcp' => '0',
        'proto' => '',
        'descr' => 'Customer endpoint',
        'vlanif' => 'vlan777',
    ];
    $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['replicas'] = ['replica' => [
        '@attributes' => ['uuid' => 'ffffffff-ffff-ffff-ffff-ffffffffffff'],
        'interface' => 'ep_customer',
        'policy_id' => 'endpoint',
    ]];

    $config['OPNsense']['HAProxy']['servers'] = ['server' => [
        '@attributes' => ['uuid' => '11111111-aaaa-bbbb-cccc-111111111111'],
        'id' => 'rigi-local-id',
        'enabled' => '1',
        'name' => 'customer-origin',
        'description' => 'Customer origin',
        'address' => '192.0.2.44',
        'port' => '443',
        'mode' => 'active',
        'type' => 'static',
        'linkedResolver' => '',
        'ssl' => '0',
        'sslCA' => '',
        'sslCRL' => '',
        'sslClientCertificate' => '',
        'unix_socket' => '',
    ]];
    $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_replicas'] = ['replica' => [
        '@attributes' => ['uuid' => '22222222-aaaa-bbbb-cccc-222222222222'],
        'object_type' => 'server',
        'object_name' => 'customer-origin',
        'policy_id' => 'endpoint',
    ]];

    $config['virtualip']['vip'] = [
        [
            '@attributes' => ['uuid' => '33333333-aaaa-bbbb-cccc-333333333333'],
            'mode' => 'carp',
            'interface' => 'ep_customer',
            'subnet' => '10.77.0.1',
            'subnet_bits' => '24',
            'vhid' => '77',
            'advbase' => '1',
            'advskew' => '110',
            'descr' => 'Endpoint CARP',
        ],
        [
            '@attributes' => ['uuid' => '34343434-aaaa-bbbb-cccc-343434343434'],
            'mode' => 'ipalias',
            'interface' => 'ep_customer',
            'subnet' => '2001:db8:77::1',
            'subnet_bits' => '64',
            'vhid' => '77',
            'advbase' => '1',
            'advskew' => '100',
            'descr' => 'Endpoint IPv6 alias bound to CARP VHID',
        ],
        [
            '@attributes' => ['uuid' => '44444444-aaaa-bbbb-cccc-444444444444'],
            'mode' => 'carp',
            'interface' => 'core_wan',
            'subnet' => '198.51.100.10',
            'subnet_bits' => '32',
            'vhid' => '101',
            'advbase' => '1',
            'advskew' => '100',
            'nosync' => '1',
            'descr' => 'Rigi local router baseline',
        ],
    ];

    $config['OPNsense']['Firewall']['Filter']['rules'] = ['rule' => [
        [
            '@attributes' => ['uuid' => '55555555-aaaa-bbbb-cccc-555555555555'],
            'description' => 'Endpoint allow',
            'interface' => 'ep_customer',
            'action' => 'pass',
        ],
        [
            '@attributes' => ['uuid' => '66666666-aaaa-bbbb-cccc-666666666666'],
            'description' => 'Rigi baseline',
            'interface' => 'lan',
            'action' => 'pass',
            'nosync' => '1',
        ],
    ]];
    $config['staticroutes'] = ['route' => [
        [
            '@attributes' => ['uuid' => '77777777-aaaa-bbbb-cccc-777777777777'],
            'network' => '203.0.113.0/24',
            'gateway' => 'EP_GW',
        ],
        [
            '@attributes' => ['uuid' => '12121212-1212-1212-1212-121212121212'],
            'network' => '198.18.0.0/24',
            'gateway' => 'EP_GW',
        ],
    ]];
    $config['gateways'] = ['gateway_item' => [
        [
            '@attributes' => ['uuid' => '88888888-aaaa-bbbb-cccc-888888888888'],
            'name' => 'EP_GW',
            'interface' => 'ep_customer',
        ],
        [
            '@attributes' => ['uuid' => '99999999-aaaa-bbbb-cccc-999999999999'],
            'name' => 'RIGI_LOCAL',
            'interface' => 'core_wan',
            'nosync' => '1',
        ],
    ]];
    $config['aliases'] = ['alias' => [
        [
            '@attributes' => ['uuid' => 'aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa'],
            'name' => 'endpoint_alias',
            'type' => 'host',
            'content' => '203.0.113.10',
        ],
    ]];
    $config['system']['user'] = [
        ['name' => 'sysops', 'uid' => '1000'],
    ];
    $config['system']['group'] = [
        ['name' => 'admins', 'gid' => '1999'],
    ];
    return $config;
}

function rhFreshPrimary(): array
{
    $config = rhBase('10.16.214.6');
    $config['virtualip']['vip'] = [
        [
            '@attributes' => ['uuid' => 'abababab-abab-abab-abab-abababababab'],
            'mode' => 'carp',
            'interface' => 'core_wan',
            'subnet' => '198.51.100.20',
            'subnet_bits' => '32',
            'vhid' => '201',
            'advbase' => '1',
            'advskew' => '0',
            'nosync' => '1',
            'descr' => 'Fresh Etna router baseline',
        ],
    ];
    $config['OPNsense']['Firewall']['Filter']['rules'] = ['rule' => [
        [
            '@attributes' => ['uuid' => 'cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd'],
            'description' => 'Fresh Etna baseline rule',
            'interface' => 'lan',
            'action' => 'pass',
            'nosync' => '1',
        ],
    ]];
    $config['gateways'] = ['gateway_item' => [
        [
            '@attributes' => ['uuid' => 'dededede-dede-dede-dede-dededededede'],
            'name' => 'ETNA_LOCAL',
            'interface' => 'core_wan',
            'nosync' => '1',
        ],
    ]];
    $config['staticroutes'] = ['route' => [
        [
            '@attributes' => ['uuid' => 'efefefef-efef-efef-efef-efefefefefef'],
            'network' => '192.0.2.0/24',
            'gateway' => 'ETNA_LOCAL',
        ],
    ]];
    $config['system']['user'] = [
        ['name' => 'temporary-bootstrap-api', 'uid' => '1001'],
    ];
    return $config;
}

$rigi = rhReplica();
$bundle = ReplacementHandoff::buildReplicaBundle(
    $rigi,
    'endpoint',
    ['12121212-1212-1212-1212-121212121212']
);

rhEq(1, $bundle['version'], 'replacement bundle version');
rhEq(['virtualip', 'rules', 'staticroutes', 'aliases', 'users'], $bundle['native_items'], 'native allowlist is fixed');
rhEq(['12121212-1212-1212-1212-121212121212'], $bundle['excluded_uuids'], 'Router-owned native UUID exclusions are explicit in the bundle');
rhEq(1, count($bundle['native']['staticroutes']['route']), 'Router-owned syncable static route is excluded while consumer route remains');
rhEq(1, count($bundle['interfaces']['interfaces']), 'one replica interface exported');
rhEq(1, count($bundle['haproxy']['objects']), 'one replica HAProxy object exported');
rhEq(2, count($bundle['native']['virtualip']['vip']), 'consumer CARP and VHID-bound IP alias exported while Rigi-local nosync VIP is excluded');
rhEq(1, count($bundle['native']['OPNsense']['Firewall']['Filter']['rules']['rule']), 'Rigi-local nosync firewall rule excluded');
rhEq(1, count($bundle['native']['gateways']['gateway_item']), 'Rigi-local nosync gateway excluded');

$identity = [
    'version' => 1,
    'policy_id' => 'endpoint',
    'interfaces' => [
        'ep_customer' => [
            'vlan_uuid' => '10101010-1010-1010-1010-101010101010',
            'assignment_uuid' => '20202020-2020-2020-2020-202020202020',
        ],
    ],
    'haproxy' => [
        'server:customer-origin' => [
            'object_uuid' => '30303030-3030-3030-3030-303030303030',
            'assignment_uuid' => '40404040-4040-4040-4040-404040404040',
        ],
    ],
    'carp_advskew' => [
        '33333333-aaaa-bbbb-cccc-333333333333' => 10,
    ],
];

$fresh = rhFreshPrimary();
$result = ReplacementHandoff::reconcileAsPrimaryOwner(
    $fresh,
    $bundle,
    $identity,
    'endpoint',
    fn() => '50505050-5050-5050-5050-505050505050',
    fn() => 'temporary-id'
);
$etna = $result['config'];

rhEq('endpoint', InterfaceSync::assignments($etna)['ep_customer']['policy_id'], 'new Etna owns promoted interface');
rhEq(false, isset(InterfaceSync::replicas($etna)['ep_customer']), 'new Etna does not mark promoted interface as replica');
rhEq('20202020-2020-2020-2020-202020202020', InterfaceSync::assignments($etna)['ep_customer']['@attributes']['uuid'], 'primary interface assignment UUID restored');

$vlanUuid = '';
foreach ($etna['vlans']['vlan'] as $row) {
    if (($row['vlanif'] ?? '') === 'vlan777') {
        $vlanUuid = $row['@attributes']['uuid'] ?? '';
    }
}
rhEq('10101010-1010-1010-1010-101010101010', $vlanUuid, 'primary VLAN UUID restored');

rhEq('endpoint', HAProxySync::assignments($etna)['server:customer-origin']['policy_id'], 'new Etna owns promoted HAProxy object');
rhEq(false, isset(HAProxySync::replicas($etna)['server:customer-origin']), 'new Etna does not mark promoted HAProxy object as replica');
rhEq('30303030-3030-3030-3030-303030303030', HAProxySync::inventory($etna)['objects']['server:customer-origin']['uuid'], 'primary HAProxy UUID restored');

$endpointVip = array_values(array_filter(
    $etna['virtualip']['vip'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === '33333333-aaaa-bbbb-cccc-333333333333'
))[0];
rhEq('10', $endpointVip['advskew'], 'primary CARP skew restored exactly from manifest');
$endpointAlias = array_values(array_filter(
    $etna['virtualip']['vip'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === '34343434-aaaa-bbbb-cccc-343434343434'
))[0];
rhEq('ipalias', $endpointAlias['mode'], 'VHID-bound IPv6 alias remains an IP alias during handoff');
rhEq('100', $endpointAlias['advskew'], 'VHID-bound IPv6 alias is not treated as a CARP identity');
rhEq(true, count(array_filter(
    $etna['virtualip']['vip'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === 'abababab-abab-abab-abab-abababababab'
)) === 1, 'fresh Etna nosync VIP baseline preserved');
rhEq(true, count(array_filter(
    $etna['OPNsense']['Firewall']['Filter']['rules']['rule'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === 'cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd'
)) === 1, 'fresh Etna nosync firewall baseline preserved');
rhEq(true, count(array_filter(
    $etna['gateways']['gateway_item'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === 'dededede-dede-dede-dede-dededededede'
)) === 1, 'fresh Etna nosync gateway baseline preserved');
rhEq(true, count(array_filter(
    $etna['staticroutes']['route'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === 'efefefef-efef-efef-efef-efefefefefef'
)) === 1, 'fresh Etna syncable Router static route preserved by additive native recovery');
rhEq(true, count(array_filter(
    $etna['staticroutes']['route'],
    fn($row) => ($row['@attributes']['uuid'] ?? '') === '77777777-aaaa-bbbb-cccc-777777777777'
)) === 1, 'consumer static route recovered additively from Rigi');
rhEq('sysops', $etna['system']['user'][0]['name'], 'shared users restored authoritatively from accepted Rigi');

rhEq(
    InterfaceSync::validatePayload($bundle['interfaces']),
    InterfaceSync::validatePayload(InterfaceSync::buildPayload($etna)),
    'promoted Etna can immediately export normal interface sync'
);
rhEq(
    HAProxySync::validatePayload($bundle['haproxy']),
    HAProxySync::validatePayload(HAProxySync::buildPayload($etna)),
    'promoted Etna can immediately export normal HAProxy sync'
);

rhBad(
    fn() => ReplacementHandoff::reconcileAsPrimaryOwner($etna, $bundle, $identity, 'endpoint'),
    'ownership handoff cannot be applied twice'
);

$wrongSource = $rigi;
$wrongSource['hasync']['synchronizetoip'] = '10.16.214.2';
rhBad(fn() => ReplacementHandoff::buildReplicaBundle($wrongSource, 'endpoint'), 'primary cannot export replica handoff bundle');

$wrongTarget = $fresh;
$wrongTarget['hasync']['synchronizetoip'] = '';
rhBad(
    fn() => ReplacementHandoff::reconcileAsPrimaryOwner($wrongTarget, $bundle, $identity, 'endpoint'),
    'secondary cannot import owner handoff bundle'
);

$badCarp = $identity;
$badCarp['carp_advskew'] = [];
rhBad(
    fn() => ReplacementHandoff::reconcileAsPrimaryOwner($fresh, $bundle, $badCarp, 'endpoint'),
    'CARP owner skew cannot be guessed'
);

fwrite(STDOUT, "replacement ownership handoff tests passed\n");

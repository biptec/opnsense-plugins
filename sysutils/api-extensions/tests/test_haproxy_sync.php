<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;

function eq($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "$message\nexpected=" . var_export($expected, true) . "\nactual=" . var_export($actual, true) . "\n");
        exit(1);
    }
}

function bad(callable $fn, string $message): void
{
    try {
        $fn();
    } catch (InvalidArgumentException $error) {
        return;
    }
    fwrite(STDERR, "$message: expected InvalidArgumentException\n");
    exit(1);
}

function policyModel(array $policies, array $haproxyAssignments = [], array $haproxyReplicas = []): array
{
    return [
        'shared' => ['policies' => ['policy' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'p-' . $row['id']]],
            $row
        ), $policies)]],
        'assignments' => '',
        'replicas' => '',
        'haproxy_assignments' => ['assignment' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'ha-' . $row['object_type'] . '-' . $row['object_name']]],
            $row
        ), $haproxyAssignments)],
        'haproxy_replicas' => ['replica' => array_map(fn($row) => array_merge(
            ['@attributes' => ['uuid' => 'hr-' . $row['object_type'] . '-' . $row['object_name']]],
            $row
        ), $haproxyReplicas)],
    ];
}

function policies(): array
{
    return [
        ['id' => 'core', 'description' => 'Router core', 'synchronize' => '0'],
        ['id' => 'endpoint', 'description' => 'HA shared service objects', 'synchronize' => '1'],
    ];
}

function sourceConfig(): array
{
    $serverName = 'origin-customer-example';
    $backendName = 'sni-customer.example';
    return [
        'hasync' => ['syncitems' => 'virtualip,rules,staticroutes,interface_vlans,haproxy_objects'],
        'OPNsense' => [
            'ApiExtensions' => [
                'InterfaceSyncPolicy' => policyModel(policies(), [
                    ['object_type' => 'server', 'object_name' => $serverName, 'policy_id' => 'endpoint'],
                    ['object_type' => 'backend', 'object_name' => $backendName, 'policy_id' => 'endpoint'],
                ]),
            ],
            'HAProxy' => [
                'general' => ['enabled' => '1'],
                'servers' => ['server' => [
                    '@attributes' => ['uuid' => 'source-server-uuid'],
                    'id' => 'source-server-id',
                    'enabled' => '1',
                    'name' => $serverName,
                    'description' => 'Customer origin',
                    'address' => '192.0.2.44',
                    'port' => '443',
                    'checkport' => '',
                    'mode' => 'active',
                    'type' => 'static',
                    'linkedResolver' => '',
                    'ssl' => '0',
                    'sslCA' => '',
                    'sslCRL' => '',
                    'sslClientCertificate' => '',
                    'maxConnections' => '',
                    'weight' => '',
                    'checkInterval' => '',
                    'checkDownInterval' => '',
                    'advanced' => '',
                    'unix_socket' => '',
                ]],
                'backends' => ['backend' => [
                    '@attributes' => ['uuid' => 'source-backend-uuid'],
                    'id' => 'source-backend-id',
                    'enabled' => '1',
                    'name' => $backendName,
                    'description' => 'Customer SNI backend',
                    'mode' => 'tcp',
                    'algorithm' => 'roundrobin',
                    'linkedServers' => 'source-server-uuid',
                    'linkedFcgi' => '',
                    'linkedResolver' => '',
                    'healthCheckEnabled' => '0',
                    'healthCheck' => '',
                    'checkInterval' => '',
                    'checkDownInterval' => '',
                    'healthCheckFall' => '',
                    'healthCheckRise' => '',
                    'linkedMailer' => '',
                    'basicAuthUsers' => '',
                    'basicAuthGroups' => '',
                    'linkedActions' => '',
                    'linkedErrorfiles' => '',
                    'customOptions' => '',
                ]],
                'frontends' => ['frontend' => [
                    '@attributes' => ['uuid' => 'receiver-independent-frontend'],
                    'id' => 'frontend-id',
                    'enabled' => '1',
                    'name' => 'nc-sni-tls',
                    'mode' => 'tcp',
                    'customOptions' => 'use_backend nc-sni-%[req.ssl_sni,lower]',
                ]],
            ],
        ],
    ];
}

function receiverBase(): array
{
    return [
        'hasync' => ['syncitems' => 'virtualip,rules,staticroutes,interface_vlans,haproxy_objects'],
        'OPNsense' => [
            'ApiExtensions' => ['InterfaceSyncPolicy' => policyModel(policies())],
            'HAProxy' => [
                'general' => ['enabled' => '1'],
                'servers' => '',
                'backends' => '',
                'frontends' => ['frontend' => [
                    '@attributes' => ['uuid' => 'receiver-independent-frontend'],
                    'id' => 'frontend-id',
                    'enabled' => '1',
                    'name' => 'nc-sni-tls',
                    'mode' => 'tcp',
                    'customOptions' => 'use_backend nc-sni-%[req.ssl_sni,lower]',
                ]],
            ],
        ],
    ];
}

function rows($container, string $item): array
{
    if ($container === '' || $container === null || $container === []) {
        return [];
    }
    $value = $container[$item] ?? [];
    if ($value === '' || $value === null || $value === []) {
        return [];
    }
    return array_is_list($value) ? $value : [$value];
}

function nextFactory(string $prefix): callable
{
    $counter = 0;
    return function () use (&$counter, $prefix): string {
        $counter++;
        return $prefix . $counter;
    };
}

$source = sourceConfig();

// Real OPNsense HAProxy config may serialize a singleton server as a list of
// one-key wrappers while a singleton backend remains a normal item container.
// The sync layer must normalize both forms before resolving UUID relations.
$wrappedSingleton = $source;
$wrappedSingleton['OPNsense']['HAProxy']['servers'] = [[
    'server' => $source['OPNsense']['HAProxy']['servers']['server'],
]];
$wrappedPayload = HAProxySync::buildPayload($wrappedSingleton);
eq(2, count($wrappedPayload['objects']), 'list-wrapped singleton HAProxy server is normalized');
eq(['origin-customer-example'], $wrappedPayload['objects'][1]['linked_server_names'], 'list-wrapped singleton server UUID relation resolves by semantic name');

$payload = HAProxySync::buildPayload($source);
eq(true, HAProxySync::isEnabled($source), 'HAProxy custom sync service enabled');
eq(1, $payload['version'], 'payload version');
eq(2, count($payload['objects']), 'server and backend selected by explicit policy');
eq('server', $payload['objects'][0]['object_type'], 'server emitted first');
eq('origin-customer-example', $payload['objects'][0]['object_name'], 'server semantic name');
eq(false, array_key_exists('@attributes', $payload['objects'][0]['data']), 'source MVC UUID stripped');
eq(false, array_key_exists('id', $payload['objects'][0]['data']), 'source HAProxy id stripped');
eq(['origin-customer-example'], $payload['objects'][1]['linked_server_names'], 'backend relation converted to semantic server name');
eq(false, array_key_exists('linkedServers', $payload['objects'][1]['data']), 'source linkedServers UUID stripped');

$receiver = receiverBase();
$created = HAProxySync::reconcile($receiver, $payload, nextFactory('receiver-uuid-'), nextFactory('receiver-id-'));
eq(true, $created['changed'], 'create changes receiver');
eq(2, $created['count'], 'two managed objects');
$createdConfig = $created['config'];
$serverRows = rows($createdConfig['OPNsense']['HAProxy']['servers'], 'server');
$backendRows = rows($createdConfig['OPNsense']['HAProxy']['backends'], 'backend');
eq(1, count($serverRows), 'one receiver server');
eq(1, count($backendRows), 'one receiver backend');
eq('receiver-uuid-1', $serverRows[0]['@attributes']['uuid'], 'receiver generates local server UUID');
eq('receiver-id-1', $serverRows[0]['id'], 'receiver generates local server id');
eq('receiver-uuid-2', $backendRows[0]['@attributes']['uuid'], 'receiver generates local backend UUID');
eq('receiver-id-2', $backendRows[0]['id'], 'receiver generates local backend id');
eq('receiver-uuid-1', $backendRows[0]['linkedServers'], 'backend remapped to receiver-local server UUID');
eq('192.0.2.44', $serverRows[0]['address'], 'server scalar configuration copied');
eq('receiver-independent-frontend', $createdConfig['OPNsense']['HAProxy']['frontends']['frontend']['@attributes']['uuid'], 'frontend baseline untouched');
eq('endpoint', HAProxySync::replicas($createdConfig)['server:origin-customer-example']['policy_id'], 'server replica ownership recorded');
eq('endpoint', HAProxySync::replicas($createdConfig)['backend:sni-customer.example']['policy_id'], 'backend replica ownership recorded');

$idempotent = HAProxySync::reconcile(
    $createdConfig,
    $payload,
    fn() => throw new RuntimeException('idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('idempotent id factory should not run')
);
eq(false, $idempotent['changed'], 'second sync is idempotent');

$malformedDirectList = $createdConfig;
$malformedDirectList['OPNsense']['HAProxy']['servers'] = [$serverRows[0]];
$malformedDirectList['OPNsense']['HAProxy']['backends'] = [$backendRows[0]];
$healedDirectList = HAProxySync::reconcile(
    $malformedDirectList,
    $payload,
    fn() => throw new RuntimeException('healing direct-list UUID factory should not run'),
    fn() => throw new RuntimeException('healing direct-list id factory should not run')
);
eq(true, $healedDirectList['changed'], 'malformed direct-list persistence shape is repaired');
eq(true, isset($healedDirectList['config']['OPNsense']['HAProxy']['servers']['server']), 'malformed server list is canonicalized');
eq(true, isset($healedDirectList['config']['OPNsense']['HAProxy']['backends']['backend']), 'malformed backend list is canonicalized');

$persistedShape = $createdConfig;
$persistedShape['OPNsense']['HAProxy']['servers'] = [[
    'server' => $serverRows[0],
]];
$persistedIdempotent = HAProxySync::reconcile(
    $persistedShape,
    $payload,
    fn() => throw new RuntimeException('persisted-shape UUID factory should not run'),
    fn() => throw new RuntimeException('persisted-shape id factory should not run')
);
eq(false, $persistedIdempotent['changed'], 'OPNsense list-wrapped persisted server shape remains idempotent');
eq($persistedShape['OPNsense']['HAProxy']['servers'], $persistedIdempotent['config']['OPNsense']['HAProxy']['servers'], 'receiver preserves persisted HAProxy server container shape');

$updatedSource = $source;
$updatedSource['OPNsense']['HAProxy']['servers']['server']['address'] = '192.0.2.55';
$updated = HAProxySync::reconcile(
    $createdConfig,
    HAProxySync::buildPayload($updatedSource),
    fn() => throw new RuntimeException('update UUID factory should not run'),
    fn() => throw new RuntimeException('update id factory should not run')
);
$updatedServer = rows($updated['config']['OPNsense']['HAProxy']['servers'], 'server')[0];
eq('receiver-uuid-1', $updatedServer['@attributes']['uuid'], 'update preserves local server UUID');
eq('receiver-id-1', $updatedServer['id'], 'update preserves local server id');
eq('192.0.2.55', $updatedServer['address'], 'update changes scalar data');

$localOnly = $source;
$localOnly['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment'][0]['policy_id'] = 'core';
bad(fn() => HAProxySync::buildPayload($localOnly), 'sync backend cannot depend on a local-only server');

$missingAssignment = $source;
array_pop($missingAssignment['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment']);
bad(fn() => HAProxySync::buildPayload($missingAssignment), 'every supported HAProxy object requires a policy');

$unsupported = $source;
$unsupported['OPNsense']['HAProxy']['servers']['server']['linkedResolver'] = 'resolver-uuid';
bad(fn() => HAProxySync::buildPayload($unsupported), 'unsupported node-local resolver relation rejected');

$disabled = $source;
$disabled['hasync']['syncitems'] = 'virtualip,rules,staticroutes,interface_vlans';
bad(fn() => HAProxySync::buildPayload($disabled), 'standard HA selector item is authoritative');

$collision = receiverBase();
$collision['OPNsense']['HAProxy']['servers'] = ['server' => [
    '@attributes' => ['uuid' => 'local-collision-uuid'],
    'id' => 'local-collision-id',
    'enabled' => '1',
    'name' => 'origin-customer-example',
    'address' => '198.51.100.10',
]];
bad(fn() => HAProxySync::reconcile($collision, $payload), 'unassigned local semantic name cannot be overwritten');

$legacy = receiverBase();
$legacy['OPNsense']['HAProxy']['servers'] = $source['OPNsense']['HAProxy']['servers'];
$legacy['OPNsense']['HAProxy']['backends'] = $source['OPNsense']['HAProxy']['backends'];
$legacy['OPNsense']['HAProxy']['servers']['server']['@attributes']['uuid'] = 'legacy-server-uuid';
$legacy['OPNsense']['HAProxy']['servers']['server']['id'] = 'legacy-server-id';
$legacy['OPNsense']['HAProxy']['backends']['backend']['@attributes']['uuid'] = 'legacy-backend-uuid';
$legacy['OPNsense']['HAProxy']['backends']['backend']['id'] = 'legacy-backend-id';
$legacy['OPNsense']['HAProxy']['backends']['backend']['linkedServers'] = 'legacy-server-uuid';
$legacy['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'] = $source['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'];
$adopted = HAProxySync::reconcile($legacy, $payload, nextFactory('adopt-meta-'), nextFactory('unused-id-'));
eq(['server:origin-customer-example', 'backend:sni-customer.example'], $adopted['plan']['adopted_local_assignments'], 'legacy dual-node objects adopted only with explicit matching policies');
$adoptedServers = rows($adopted['config']['OPNsense']['HAProxy']['servers'], 'server');
$adoptedBackends = rows($adopted['config']['OPNsense']['HAProxy']['backends'], 'backend');
eq('legacy-server-uuid', $adoptedServers[0]['@attributes']['uuid'], 'adoption preserves receiver server UUID');
eq('legacy-server-id', $adoptedServers[0]['id'], 'adoption preserves receiver server id');
eq('legacy-backend-uuid', $adoptedBackends[0]['@attributes']['uuid'], 'adoption preserves receiver backend UUID');
eq('legacy-server-uuid', $adoptedBackends[0]['linkedServers'], 'adopted backend remains linked to receiver server UUID');
eq([], HAProxySync::assignments($adopted['config']), 'adopted local assignments removed');

$emptyPayload = $payload;
$emptyPayload['objects'] = [];
$pruned = HAProxySync::reconcile(
    $createdConfig,
    $emptyPayload,
    fn() => throw new RuntimeException('prune UUID factory should not run'),
    fn() => throw new RuntimeException('prune id factory should not run')
);
eq([], rows($pruned['config']['OPNsense']['HAProxy']['servers'], 'server'), 'stale peer-owned server pruned');
eq([], rows($pruned['config']['OPNsense']['HAProxy']['backends'], 'backend'), 'stale peer-owned backend pruned');
eq([], HAProxySync::replicas($pruned['config']), 'stale replica ownership pruned');
eq('nc-sni-tls', $pruned['config']['OPNsense']['HAProxy']['frontends']['frontend']['name'], 'local frontend survives prune');

$unsafePrune = $createdConfig;
$unsafePrune['OPNsense']['HAProxy']['backends']['backend'] = [
    $unsafePrune['OPNsense']['HAProxy']['backends']['backend'],
    [
        '@attributes' => ['uuid' => 'local-backend-uuid'],
        'id' => 'local-backend-id',
        'enabled' => '1',
        'name' => 'local-backend',
        'mode' => 'tcp',
        'algorithm' => 'roundrobin',
        'linkedServers' => 'receiver-uuid-1',
    ],
];
bad(fn() => HAProxySync::reconcile($unsafePrune, $emptyPayload), 'cannot prune server still referenced by local backend');

$receiverLocalPolicy = $createdConfig;
$receiverLocalPolicy['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['shared']['policies']['policy'][] = [
    '@attributes' => ['uuid' => 'p-rigi-local'],
    'id' => 'rigi_local',
    'description' => 'Rigi local HAProxy object',
    'synchronize' => '0',
];
$receiverLocalPolicy['OPNsense']['HAProxy']['servers']['server'] = [
    $receiverLocalPolicy['OPNsense']['HAProxy']['servers']['server'],
    [
        '@attributes' => ['uuid' => 'rigi-local-server-uuid'],
        'id' => 'rigi-local-server-id',
        'enabled' => '1',
        'name' => 'rigi-local-server',
        'address' => '127.0.0.1',
    ],
];
$receiverLocalPolicy['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'] = ['assignment' => [
    '@attributes' => ['uuid' => 'ha-rigi-local'],
    'object_type' => 'server',
    'object_name' => 'rigi-local-server',
    'policy_id' => 'p-rigi-local',
]];
bad(
    fn() => HAProxySync::reconcile(
        $receiverLocalPolicy,
        $payload,
        fn() => throw new RuntimeException('local-policy UUID factory should not run'),
        fn() => throw new RuntimeException('local-policy id factory should not run')
    ),
    'receiver-only policy definitions are rejected while referenced; policy definitions remain source-authoritative'
);

$nativeEmpty = receiverBase();
$nativeEmpty['OPNsense']['HAProxy']['servers'] = [];
$nativeEmpty['OPNsense']['HAProxy']['backends'] = '';
$nativeEmpty['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'] = '';
$nativeEmpty['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_replicas'] = '';
$nativeEmptyResult = HAProxySync::reconcile(
    $nativeEmpty,
    $emptyPayload,
    fn() => throw new RuntimeException('native-empty UUID factory should not run'),
    fn() => throw new RuntimeException('native-empty id factory should not run')
);
eq(false, $nativeEmptyResult['changed'], 'native empty HAProxy section shapes remain a true no-op');
eq([], $nativeEmptyResult['config']['OPNsense']['HAProxy']['servers'], 'native empty server array shape is preserved');
eq('', $nativeEmptyResult['config']['OPNsense']['HAProxy']['backends'], 'native empty backend string shape is preserved');

// A freshly installed peer can expose an empty ArrayField container as [].
// The first synchronized object must still be wrapped under its singular MVC
// item name; otherwise write_config() creates <servers uuid="..."> and native
// HAProxy ignores the object even though the custom inventory can parse it.
$emptyArrayCreate = receiverBase();
$emptyArrayCreate['OPNsense']['HAProxy']['servers'] = [];
$emptyArrayCreate['OPNsense']['HAProxy']['backends'] = [];
$emptyArrayResult = HAProxySync::reconcile(
    $emptyArrayCreate,
    $payload,
    nextFactory('empty-array-uuid-'),
    nextFactory('empty-array-id-')
);
eq(true, isset($emptyArrayResult['config']['OPNsense']['HAProxy']['servers']['server']), 'first server uses native MVC item container');
eq(true, isset($emptyArrayResult['config']['OPNsense']['HAProxy']['backends']['backend']), 'first backend uses native MVC item container');
eq(1, count(rows($emptyArrayResult['config']['OPNsense']['HAProxy']['servers'], 'server')), 'native MVC sees first synchronized server');
eq(1, count(rows($emptyArrayResult['config']['OPNsense']['HAProxy']['backends'], 'backend')), 'native MVC sees first synchronized backend');

$serializedEmpty = receiverBase();
$serializedEmpty['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_replicas'] = '';
$serializedCreate = HAProxySync::reconcile($serializedEmpty, $payload, nextFactory('serialized-uuid-'), nextFactory('serialized-id-'));
eq(2, count(HAProxySync::replicas($serializedCreate['config'])), 'empty serialized replica container accepts first objects');

fwrite(STDOUT, "HAProxy policy sync tests passed\n");

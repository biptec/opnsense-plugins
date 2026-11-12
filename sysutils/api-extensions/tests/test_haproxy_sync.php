<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\HAProxyTLSIdentitySync;
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
    $healthcheckName = 'hc-customer-example';
    $serverName = 'origin-customer-example';
    $backendName = 'sni-customer.example';
    return [
        'hasync' => ['syncitems' => 'virtualip,rules,staticroutes,interface_vlans,haproxy_objects'],
        'OPNsense' => [
            'ApiExtensions' => [
                'InterfaceSyncPolicy' => policyModel(policies(), [
                    ['object_type' => 'healthcheck', 'object_name' => $healthcheckName, 'policy_id' => 'endpoint'],
                    ['object_type' => 'server', 'object_name' => $serverName, 'policy_id' => 'endpoint'],
                    ['object_type' => 'backend', 'object_name' => $backendName, 'policy_id' => 'endpoint'],
                ]),
            ],
            'HAProxy' => [
                'general' => ['enabled' => '1'],
                'healthchecks' => ['healthcheck' => [
                    '@attributes' => ['uuid' => 'source-healthcheck-uuid'],
                    'id' => 'source-healthcheck-id',
                    'name' => $healthcheckName,
                    'description' => 'Customer TCP health monitor',
                    'type' => 'tcp',
                    'interval' => '2000',
                    'ssl' => 'nopref',
                    'sslSNI' => '',
                    'force_ssl' => '0',
                    'checkport' => '',
                    'http_method' => '',
                    'http_uri' => '',
                    'http_host' => '',
                    'tcp_sendValue' => '',
                    'tcp_matchType' => '',
                    'tcp_matchValue' => '',
                ]],
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
                    'ssl' => '1',
                    'sslSNI' => 'deneb.svc.sandbox.biptec.net',
                    'sslVerify' => '1',
                    'sslVerifyHost' => 'deneb.svc.sandbox.biptec.net',
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
                    'proxyProtocol' => 'v2',
                    'linkedServers' => 'source-server-uuid',
                    'linkedFcgi' => '',
                    'linkedResolver' => '',
                    'healthCheckEnabled' => '1',
                    'healthCheck' => 'source-healthcheck-uuid',
                    'healthCheckProxyProto' => 'backend',
                    'checkInterval' => '2000',
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
                'healthchecks' => '',
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
eq(3, count($wrappedPayload['objects']), 'list-wrapped singleton HAProxy server is normalized');
eq(['origin-customer-example'], $wrappedPayload['objects'][2]['linked_server_names'], 'list-wrapped singleton server UUID relation resolves by semantic name');

$payload = HAProxySync::buildPayload($source);
eq(true, HAProxySync::isEnabled($source), 'HAProxy custom sync service enabled');
eq(2, $payload['version'], 'payload version');
eq(3, count($payload['objects']), 'healthcheck, server and backend selected by explicit policy');
eq('healthcheck', $payload['objects'][0]['object_type'], 'healthcheck emitted first');
eq('hc-customer-example', $payload['objects'][0]['object_name'], 'healthcheck semantic name');
eq('server', $payload['objects'][1]['object_type'], 'server emitted before backend');
eq('origin-customer-example', $payload['objects'][1]['object_name'], 'server semantic name');
eq(false, array_key_exists('@attributes', $payload['objects'][0]['data']), 'source healthcheck MVC UUID stripped');
eq(false, array_key_exists('id', $payload['objects'][0]['data']), 'source healthcheck id stripped');
eq(['origin-customer-example'], $payload['objects'][2]['linked_server_names'], 'backend relation converted to semantic server name');
eq('hc-customer-example', $payload['objects'][2]['linked_healthcheck_name'], 'backend healthcheck relation converted to semantic name');
eq(false, array_key_exists('linkedServers', $payload['objects'][2]['data']), 'source linkedServers UUID stripped');
eq(false, array_key_exists('healthCheck', $payload['objects'][2]['data']), 'source healthCheck UUID stripped');
eq('v2', $payload['objects'][2]['data']['proxyProtocol'], 'backend PROXY v2 scalar copied');
eq('backend', $payload['objects'][2]['data']['healthCheckProxyProto'], 'health-check PROXY behavior copied');

$receiver = receiverBase();
$created = HAProxySync::reconcile($receiver, $payload, nextFactory('receiver-uuid-'), nextFactory('receiver-id-'));
eq(true, $created['changed'], 'create changes receiver');
eq(3, $created['count'], 'three managed objects');
$createdConfig = $created['config'];
$healthcheckRows = rows($createdConfig['OPNsense']['HAProxy']['healthchecks'], 'healthcheck');
$serverRows = rows($createdConfig['OPNsense']['HAProxy']['servers'], 'server');
$backendRows = rows($createdConfig['OPNsense']['HAProxy']['backends'], 'backend');
eq(1, count($healthcheckRows), 'one receiver healthcheck');
eq(1, count($serverRows), 'one receiver server');
eq(1, count($backendRows), 'one receiver backend');
eq('receiver-uuid-1', $healthcheckRows[0]['@attributes']['uuid'], 'receiver generates local healthcheck UUID');
eq('receiver-id-1', $healthcheckRows[0]['id'], 'receiver generates local healthcheck id');
eq('receiver-uuid-2', $serverRows[0]['@attributes']['uuid'], 'receiver generates local server UUID');
eq('receiver-id-2', $serverRows[0]['id'], 'receiver generates local server id');
eq('receiver-uuid-3', $backendRows[0]['@attributes']['uuid'], 'receiver generates local backend UUID');
eq('receiver-id-3', $backendRows[0]['id'], 'receiver generates local backend id');
eq('receiver-uuid-2', $backendRows[0]['linkedServers'], 'backend remapped to receiver-local server UUID');
eq('receiver-uuid-1', $backendRows[0]['healthCheck'], 'backend remapped to receiver-local healthcheck UUID');
eq('192.0.2.44', $serverRows[0]['address'], 'server scalar configuration copied');
eq('1', $serverRows[0]['ssl'], 'server TLS flag copied');
eq('deneb.svc.sandbox.biptec.net', $serverRows[0]['sslSNI'], 'server TLS SNI copied');
eq('1', $serverRows[0]['sslVerify'], 'server TLS chain verification copied');
eq('deneb.svc.sandbox.biptec.net', $serverRows[0]['sslVerifyHost'], 'server TLS hostname verification copied');
eq('receiver-independent-frontend', $createdConfig['OPNsense']['HAProxy']['frontends']['frontend']['@attributes']['uuid'], 'frontend baseline untouched');
eq('endpoint', HAProxySync::assignments($createdConfig)['healthcheck:hc-customer-example']['policy_id'], 'healthcheck assigned by HA policy');
eq('endpoint', HAProxySync::assignments($createdConfig)['server:origin-customer-example']['policy_id'], 'server assigned by HA policy');
eq('endpoint', HAProxySync::assignments($createdConfig)['backend:sni-customer.example']['policy_id'], 'backend assigned by HA policy');

$idempotent = HAProxySync::reconcile(
    $createdConfig,
    $payload,
    fn() => throw new RuntimeException('idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('idempotent id factory should not run')
);
eq(false, $idempotent['changed'], 'second sync is idempotent');

// A synchronized TLS frontend carries semantic certificate descriptions, never
// node-local certificate refids. The receiver must resolve the same description
// to its own locally-managed certificate, preserving local private-key ownership.
$frontendSource = $source;
$frontendSource['cert'] = [[
    'refid' => 'source-oidc-cert-ref',
    'descr' => 'oidc-ingress',
]];
$frontendSource['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment'][] = [
    '@attributes' => ['uuid' => 'ha-frontend-oidc-ingress'],
    'object_type' => 'frontend',
    'object_name' => 'oidc-ingress',
    'policy_id' => 'endpoint',
];
$sharedFrontend = $frontendSource['OPNsense']['HAProxy']['frontends']['frontend'];
$frontendSource['OPNsense']['HAProxy']['frontends']['frontend'] = [
    $sharedFrontend,
    [
        '@attributes' => ['uuid' => 'source-frontend-uuid'],
        'id' => 'source-frontend-id',
        'enabled' => '1',
        'name' => 'oidc-ingress',
        'description' => 'OIDC internal TLS ingress',
        'bind' => '10.0.16.81:443,[2a07:e580:a11:1050::1]:443',
        'mode' => 'http',
        'defaultBackend' => 'source-backend-uuid',
        'ssl_enabled' => '1',
        'ssl_certificates' => 'source-oidc-cert-ref',
        'ssl_default_certificate' => 'source-oidc-cert-ref',
        'linkedActions' => '',
    ],
];

$frontendPayload = HAProxySync::buildPayload($frontendSource);
eq(3, $frontendPayload['version'], 'managed frontend uses v3 until TLS identity sync is activated');
eq(4, count($frontendPayload['objects']), 'managed frontend is included after backend');
$frontendPayloadRow = $frontendPayload['objects'][3];
eq('frontend', $frontendPayloadRow['object_type'], 'frontend emitted after backend dependencies');
eq('sni-customer.example', $frontendPayloadRow['data']['sync_default_backend_name'], 'frontend backend relation is semantic');
eq('["oidc-ingress"]', $frontendPayloadRow['data']['sync_ssl_certificate_descriptions'], 'frontend certificate relation is semantic');
eq('oidc-ingress', $frontendPayloadRow['data']['sync_ssl_default_certificate_description'], 'frontend default certificate relation is semantic');
eq(false, array_key_exists('defaultBackend', $frontendPayloadRow['data']), 'source backend UUID stripped from frontend payload');
eq(false, array_key_exists('ssl_certificates', $frontendPayloadRow['data']), 'source certificate refids stripped from frontend payload');
eq(false, array_key_exists('ssl_default_certificate', $frontendPayloadRow['data']), 'source default certificate refid stripped from frontend payload');

$frontendReceiver = receiverBase();
$frontendReceiver['cert'] = [[
    'refid' => 'receiver-oidc-cert-ref',
    'descr' => 'oidc-ingress',
]];
$frontendCreated = HAProxySync::reconcile(
    $frontendReceiver,
    $frontendPayload,
    nextFactory('frontend-receiver-uuid-'),
    nextFactory('frontend-receiver-id-')
);
eq(true, $frontendCreated['changed'], 'frontend payload changes receiver');
eq(4, $frontendCreated['count'], 'frontend payload manages four objects');
$frontendCreatedConfig = $frontendCreated['config'];
$frontendRows = rows($frontendCreatedConfig['OPNsense']['HAProxy']['frontends'], 'frontend');
eq(2, count($frontendRows), 'local shared frontend and synchronized TLS frontend coexist');
$managedFrontend = null;
foreach ($frontendRows as $frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $managedFrontend = $frontendRow;
        break;
    }
}
eq(true, is_array($managedFrontend), 'synchronized TLS frontend created');
eq('frontend-receiver-uuid-3', $managedFrontend['defaultBackend'], 'frontend default backend remapped to receiver-local backend UUID');
eq('receiver-oidc-cert-ref', $managedFrontend['ssl_certificates'], 'frontend certificate remapped to receiver-local refid');
eq('receiver-oidc-cert-ref', $managedFrontend['ssl_default_certificate'], 'frontend default certificate remapped to receiver-local refid');
eq('receiver-independent-frontend', $frontendRows[0]['@attributes']['uuid'], 'unassigned shared frontend remains untouched');
eq('endpoint', HAProxySync::assignments($frontendCreatedConfig)['frontend:oidc-ingress']['policy_id'], 'frontend receives synchronized HA policy');

$frontendIdempotent = HAProxySync::reconcile(
    $frontendCreatedConfig,
    $frontendPayload,
    fn() => throw new RuntimeException('frontend idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('frontend idempotent id factory should not run')
);
eq(false, $frontendIdempotent['changed'], 'frontend second sync is idempotent');

// Version 3 remains accepted during the required peer-first plugin rollout.
// It contains no TLS identity metadata and therefore leaves receiver-local
// identity registrations untouched.
$legacyFrontendPayload = $frontendPayload;
$legacyFrontendPayload['version'] = 3;
unset($legacyFrontendPayload['tls_identities']);
$legacyFrontendReceiver = $frontendCreatedConfig;
$legacyFrontendReceiver['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'] = [
    'identities' => ['identity' => [[
        '@attributes' => ['uuid' => 'legacy-local-identity'],
        'frontend_name' => 'oidc-ingress',
        'dns_name' => 'legacy.example.invalid',
    ]]],
];
$legacyFrontendResult = HAProxySync::reconcile(
    $legacyFrontendReceiver,
    $legacyFrontendPayload,
    fn() => throw new RuntimeException('v3 compatibility UUID factory should not run'),
    fn() => throw new RuntimeException('v3 compatibility id factory should not run')
);
eq(
    $legacyFrontendReceiver['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'],
    $legacyFrontendResult['config']['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'],
    'v3 payload preserves receiver-local TLS identity metadata'
);


// Version 4 carries a consumer TLS identity independently of the shared
// frontend object. The consumer payload contains only its backend graph plus
// the additive identity; the Core-owned shared frontend remains local on each
// Router and is referenced only by semantic name.
$tlsIdentitySource = $source;
$sourceLocalFrontend = $tlsIdentitySource['OPNsense']['HAProxy']['frontends']['frontend'];
$tlsIdentitySource['OPNsense']['HAProxy']['frontends']['frontend'] = [
    $sourceLocalFrontend,
    [
        '@attributes' => ['uuid' => 'source-arcturus-frontend'],
        'id' => 'source-arcturus-id',
        'enabled' => '1',
        'name' => 'arcturus-shared-https',
        'description' => 'Core-owned Arcturus shared HTTPS frontend',
        'bind' => '10.0.16.80:443',
        'mode' => 'http',
        'defaultBackend' => '',
        'ssl_enabled' => '1',
        'ssl_certificates' => 'source-arcturus-cert-ref,source-router-cert-ref',
        'ssl_default_certificate' => 'source-arcturus-cert-ref',
        'customOptions' => 'use_backend nc-sni-%[req.hdr(host),lower,field(1,:)]',
        'linkedActions' => '',
    ],
];
$tlsIdentitySource['cert'] = [
    ['refid' => 'source-arcturus-cert-ref', 'descr' => 'arcturus-default'],
    ['refid' => 'source-router-cert-ref', 'descr' => 'HAProxy TLS router.example.invalid'],
];
$tlsIdentitySource['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'] = [
    'sync_marker' => ['enabled' => '1'],
    'identities' => ['identity' => [[
        '@attributes' => ['uuid' => 'source-router-tls-identity'],
        'frontend_name' => 'arcturus-shared-https',
        'dns_name' => 'router.example.invalid',
        'policy_id' => 'p-endpoint',
    ]]],
];

$tlsIdentityPayload = HAProxySync::buildPayload($tlsIdentitySource);
eq(4, $tlsIdentityPayload['version'], 'TLS identity enables v4 payload without synchronizing shared frontend');
eq(3, count($tlsIdentityPayload['objects']), 'consumer payload still contains only healthcheck/server/backend');
eq(false, in_array('frontend', array_column($tlsIdentityPayload['objects'], 'object_type'), true), 'Core-owned shared frontend is absent from consumer payload');
eq([[
    'frontend_name' => 'arcturus-shared-https',
    'dns_name' => 'router.example.invalid',
    'policy_id' => 'endpoint',
]], $tlsIdentityPayload['tls_identities'], 'TLS identity payload is semantic, policy-scoped and non-secret');

$tlsIdentityReceiver = receiverBase();
$receiverLocalFrontend = $tlsIdentityReceiver['OPNsense']['HAProxy']['frontends']['frontend'];
$tlsIdentityReceiver['OPNsense']['HAProxy']['frontends']['frontend'] = [
    $receiverLocalFrontend,
    [
        '@attributes' => ['uuid' => 'receiver-arcturus-frontend'],
        'id' => 'receiver-arcturus-id',
        'enabled' => '1',
        'name' => 'arcturus-shared-https',
        'description' => 'Core-owned Arcturus shared HTTPS frontend',
        'bind' => '10.0.16.80:443',
        'mode' => 'http',
        'defaultBackend' => '',
        'ssl_enabled' => '1',
        'ssl_certificates' => 'receiver-arcturus-cert-ref',
        'ssl_default_certificate' => 'receiver-arcturus-cert-ref',
        'customOptions' => 'use_backend nc-sni-%[req.hdr(host),lower,field(1,:)]',
        'linkedActions' => '',
    ],
];
$tlsIdentityReceiver['cert'] = [
    ['refid' => 'receiver-arcturus-cert-ref', 'descr' => 'arcturus-default'],
];

$tlsIdentityCreated = HAProxySync::reconcile(
    $tlsIdentityReceiver,
    $tlsIdentityPayload,
    nextFactory('tls-identity-receiver-uuid-'),
    nextFactory('tls-identity-receiver-id-')
);
eq(true, $tlsIdentityCreated['changed'], 'TLS identity payload changes receiver metadata and backend graph');
eq(1, $tlsIdentityCreated['plan']['tls_identities']['count'], 'TLS identity plan count');
eq(1, count($tlsIdentityCreated['plan']['tls_identities']['ensure']), 'new TLS identity requires receiver-local materialization');
$receiverIdentities = HAProxyTLSIdentitySync::identities($tlsIdentityCreated['config']);
eq(
    ['arcturus-shared-https|router.example.invalid'],
    array_keys($receiverIdentities),
    'receiver persists identity against local Core-owned shared frontend'
);
eq(
    'endpoint',
    $receiverIdentities['arcturus-shared-https|router.example.invalid']['policy_id'],
    'receiver maps HA policy to its local policy relation'
);
$tlsFrontendRows = rows($tlsIdentityCreated['config']['OPNsense']['HAProxy']['frontends'], 'frontend');
$tlsSharedFrontend = null;
foreach ($tlsFrontendRows as $frontendRow) {
    if (($frontendRow['name'] ?? '') === 'arcturus-shared-https') {
        $tlsSharedFrontend = $frontendRow;
        break;
    }
}
eq(true, is_array($tlsSharedFrontend), 'Core-owned shared frontend remains present locally');
eq('receiver-arcturus-frontend', $tlsSharedFrontend['@attributes']['uuid'], 'consumer sync does not replace shared frontend');
eq('receiver-arcturus-cert-ref', $tlsSharedFrontend['ssl_certificates'], 'pure metadata reconcile does not fabricate certificate membership before materialization');

$tlsIdentityIdempotent = HAProxySync::reconcile(
    $tlsIdentityCreated['config'],
    $tlsIdentityPayload,
    fn() => throw new RuntimeException('TLS identity idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('TLS identity idempotent id factory should not run')
);
eq(false, $tlsIdentityIdempotent['changed'], 'TLS identity second sync is idempotent');
eq([], $tlsIdentityIdempotent['plan']['tls_identities']['ensure'], 'converged TLS identity is not re-materialized');
eq([], $tlsIdentityIdempotent['plan']['tls_identities']['remove'], 'converged TLS identity is not removed');

// Deleting the last consumer remains v4-authoritative: an explicit empty
// tls_identities list removes the receiver registration instead of falling
// back to legacy "preserve local identities" behavior.
$tlsIdentityRemovedSource = $tlsIdentitySource;
$tlsIdentityRemovedSource['OPNsense']['ApiExtensions']['HAProxyTLSIdentity']['identities'] = '';
$tlsIdentityRemovedPayload = HAProxySync::buildPayload($tlsIdentityRemovedSource);
eq(4, $tlsIdentityRemovedPayload['version'], 'authoritative marker keeps v4 after last identity deletion');
eq([], $tlsIdentityRemovedPayload['tls_identities'], 'last identity deletion sends authoritative empty set');
$tlsIdentityRemoved = HAProxySync::reconcile(
    $tlsIdentityCreated['config'],
    $tlsIdentityRemovedPayload,
    fn() => throw new RuntimeException('identity removal must not allocate UUID'),
    fn() => throw new RuntimeException('identity removal must not allocate HAProxy id')
);
eq(1, count($tlsIdentityRemoved['plan']['tls_identities']['remove']), 'receiver schedules local certificate cleanup for deleted identity');
eq([], HAProxyTLSIdentitySync::buildPayload($tlsIdentityRemoved['config']), 'receiver converges to empty synchronized identity set');

// A shared fail-closed internal frontend intentionally has no default backend.
// It is accepted only with the exact dynamic SNI dispatch contract used by
// Core Router, and the receiver must preserve the empty relation.
$dynamicFrontendSource = $frontendSource;
foreach ($dynamicFrontendSource['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['defaultBackend'] = '';
        $frontendRow['customOptions'] = 'use_backend nc-sni-%[ssl_fc_sni,lower]';
    }
}
unset($frontendRow);
$dynamicFrontendPayload = HAProxySync::buildPayload($dynamicFrontendSource);
eq('', $dynamicFrontendPayload['objects'][3]['data']['sync_default_backend_name'], 'dynamic frontend carries no default backend');
eq(
    'use_backend nc-sni-%[ssl_fc_sni,lower]',
    $dynamicFrontendPayload['objects'][3]['data']['customOptions'],
    'dynamic frontend dispatch is preserved'
);
$dynamicFrontendReceiver = receiverBase();
$dynamicFrontendReceiver['cert'] = [[
    'refid' => 'receiver-oidc-cert-ref',
    'descr' => 'oidc-ingress',
]];
$dynamicFrontendCreated = HAProxySync::reconcile(
    $dynamicFrontendReceiver,
    $dynamicFrontendPayload,
    nextFactory('dynamic-frontend-receiver-uuid-'),
    nextFactory('dynamic-frontend-receiver-id-')
);
$dynamicFrontendRows = rows($dynamicFrontendCreated['config']['OPNsense']['HAProxy']['frontends'], 'frontend');
$dynamicManagedFrontend = null;
foreach ($dynamicFrontendRows as $frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $dynamicManagedFrontend = $frontendRow;
        break;
    }
}
eq(true, is_array($dynamicManagedFrontend), 'dynamic synchronized frontend created');
eq('', $dynamicManagedFrontend['defaultBackend'], 'dynamic frontend remains fail-closed without default backend');
eq(
    'use_backend nc-sni-%[ssl_fc_sni,lower]',
    $dynamicManagedFrontend['customOptions'],
    'dynamic frontend keeps exact SNI dispatch on receiver'
);
$dynamicFrontendIdempotent = HAProxySync::reconcile(
    $dynamicFrontendCreated['config'],
    $dynamicFrontendPayload,
    fn() => throw new RuntimeException('dynamic frontend idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('dynamic frontend idempotent id factory should not run')
);
eq(false, $dynamicFrontendIdempotent['changed'], 'dynamic frontend second sync is idempotent');

// The generic per-request Host-derived dispatch intentionally has zero explicit
// backend dependencies. It must synchronize safely even when this payload owns
// only the shared frontend and the selected nc-sni-* backend is owned by a
// different Terraform consumer state.
$genericHostFrontendSource = $frontendSource;
$genericHostFrontendSource['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment'] = [
    [
        '@attributes' => ['uuid' => 'ha-frontend-oidc-ingress'],
        'object_type' => 'frontend',
        'object_name' => 'oidc-ingress',
        'policy_id' => 'endpoint',
    ],
];
$genericHostFrontendSource['OPNsense']['HAProxy']['healthchecks'] = '';
$genericHostFrontendSource['OPNsense']['HAProxy']['servers'] = '';
$genericHostFrontendSource['OPNsense']['HAProxy']['backends'] = '';
$genericHostDispatch = 'use_backend nc-sni-%[req.hdr(host),lower,field(1,:)]';
foreach ($genericHostFrontendSource['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['defaultBackend'] = '';
        $frontendRow['customOptions'] = $genericHostDispatch;
    }
}
unset($frontendRow);
$genericHostFrontendPayload = HAProxySync::buildPayload($genericHostFrontendSource);
eq(3, $genericHostFrontendPayload['version'], 'generic Host frontend remains v3 before TLS identity sync activation');
eq(1, count($genericHostFrontendPayload['objects']), 'generic Host frontend payload has zero explicit backend dependencies');
eq('frontend', $genericHostFrontendPayload['objects'][0]['object_type'], 'generic Host payload contains only the shared frontend');
eq('', $genericHostFrontendPayload['objects'][0]['data']['sync_default_backend_name'], 'generic Host frontend carries no default backend');
eq($genericHostDispatch, $genericHostFrontendPayload['objects'][0]['data']['customOptions'], 'generic Host dispatch is preserved in payload');

$genericHostFrontendReceiver = receiverBase();
$genericHostFrontendReceiver['cert'] = [[
    'refid' => 'receiver-oidc-cert-ref',
    'descr' => 'oidc-ingress',
]];
$genericHostFrontendCreated = HAProxySync::reconcile(
    $genericHostFrontendReceiver,
    $genericHostFrontendPayload,
    nextFactory('generic-host-frontend-receiver-uuid-'),
    nextFactory('generic-host-frontend-receiver-id-')
);
$genericHostFrontendRows = rows($genericHostFrontendCreated['config']['OPNsense']['HAProxy']['frontends'], 'frontend');
$genericHostManagedFrontend = null;
foreach ($genericHostFrontendRows as $frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $genericHostManagedFrontend = $frontendRow;
        break;
    }
}
eq(true, is_array($genericHostManagedFrontend), 'generic Host synchronized frontend created without backend payload');
eq('', $genericHostManagedFrontend['defaultBackend'], 'generic Host frontend remains fail-closed without default backend');
eq($genericHostDispatch, $genericHostManagedFrontend['customOptions'], 'generic Host dispatch survives receiver reconciliation verbatim');

$unsafeGenericHostDispatch = $genericHostFrontendSource;
foreach ($unsafeGenericHostDispatch['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = 'use_backend nc-sni-%[req.hdr(host),lower]';
    }
}
unset($frontendRow);
bad(fn() => HAProxySync::buildPayload($unsafeGenericHostDispatch), 'non-approved generic Host expression is rejected');

$multilineGenericHostDispatch = $genericHostFrontendSource;
foreach ($multilineGenericHostDispatch['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = $genericHostDispatch . "\nhttp-request deny";
    }
}
unset($frontendRow);
bad(fn() => HAProxySync::buildPayload($multilineGenericHostDispatch), 'generic Host dispatch rejects arbitrary multiline directives');

// HTTP/2 clients may coalesce multiple certificate-covered hostnames onto one
// TLS connection. Per-request Host dispatch must therefore be accepted as a
// strict fail-closed dynamic contract and preserve the rules verbatim.
$hostFrontendSource = $frontendSource;
$hostDispatch = implode("\n", [
    'use_backend sni-customer.example if { hdr(host),lower,field(1,:) -m str id.example.invalid }',
    'use_backend sni-customer.example if { hdr(host),lower,field(1,:) -m str dc.example.invalid }',
]);
foreach ($hostFrontendSource['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['defaultBackend'] = '';
        $frontendRow['customOptions'] = $hostDispatch;
    }
}
unset($frontendRow);
$hostFrontendPayload = HAProxySync::buildPayload($hostFrontendSource);
eq('', $hostFrontendPayload['objects'][3]['data']['sync_default_backend_name'], 'Host frontend carries no default backend');
eq($hostDispatch, $hostFrontendPayload['objects'][3]['data']['customOptions'], 'Host dispatch is preserved in payload');
$hostFrontendReceiver = receiverBase();
$hostFrontendReceiver['cert'] = [[
    'refid' => 'receiver-oidc-cert-ref',
    'descr' => 'oidc-ingress',
]];
$hostFrontendCreated = HAProxySync::reconcile(
    $hostFrontendReceiver,
    $hostFrontendPayload,
    nextFactory('host-frontend-receiver-uuid-'),
    nextFactory('host-frontend-receiver-id-')
);
$hostFrontendRows = rows($hostFrontendCreated['config']['OPNsense']['HAProxy']['frontends'], 'frontend');
$hostManagedFrontend = null;
foreach ($hostFrontendRows as $frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $hostManagedFrontend = $frontendRow;
        break;
    }
}
eq(true, is_array($hostManagedFrontend), 'Host-dispatched synchronized frontend created');
eq('', $hostManagedFrontend['defaultBackend'], 'Host-dispatched frontend stays fail-closed without default backend');
eq($hostDispatch, $hostManagedFrontend['customOptions'], 'Host dispatch survives receiver reconciliation verbatim');
$hostFrontendIdempotent = HAProxySync::reconcile(
    $hostFrontendCreated['config'],
    $hostFrontendPayload,
    fn() => throw new RuntimeException('Host frontend idempotent UUID factory should not run'),
    fn() => throw new RuntimeException('Host frontend idempotent id factory should not run')
);
eq(false, $hostFrontendIdempotent['changed'], 'Host-dispatched frontend second sync is idempotent');

$missingHostBackend = $hostFrontendSource;
foreach ($missingHostBackend['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = 'use_backend missing-backend if { hdr(host),lower,field(1,:) -m str id.example.invalid }';
    }
}
unset($frontendRow);
bad(fn() => HAProxySync::buildPayload($missingHostBackend), 'Host dispatch backend must be selected for synchronization');

$duplicateHostDispatch = $hostFrontendSource;
foreach ($duplicateHostDispatch['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = implode("\n", [
            'use_backend sni-customer.example if { hdr(host),lower,field(1,:) -m str id.example.invalid }',
            'use_backend sni-customer.example if { hdr(host),lower,field(1,:) -m str id.example.invalid }',
        ]);
    }
}
unset($frontendRow);
bad(fn() => HAProxySync::buildPayload($duplicateHostDispatch), 'duplicate Host dispatch conditions are rejected');

$unsafeHostDispatch = $hostFrontendSource;
foreach ($unsafeHostDispatch['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = 'use_backend sni-customer.example if { hdr(host) -m end example.invalid }';
    }
}
unset($frontendRow);
bad(fn() => HAProxySync::buildPayload($unsafeHostDispatch), 'arbitrary HAProxy custom options are rejected for fail-closed frontend');

$invalidNoDefaultFrontend = $dynamicFrontendSource;
foreach ($invalidNoDefaultFrontend['OPNsense']['HAProxy']['frontends']['frontend'] as &$frontendRow) {
    if (($frontendRow['name'] ?? '') === 'oidc-ingress') {
        $frontendRow['customOptions'] = '';
    }
}
unset($frontendRow);
bad(
    fn() => HAProxySync::buildPayload($invalidNoDefaultFrontend),
    'frontend without default backend and supported fail-closed dynamic dispatch is rejected'
);

$reverseFrontendPayload = HAProxySync::buildPayload($frontendCreatedConfig);
eq(3, $reverseFrontendPayload['version'], 'receiver preserves v3 frontend payload before TLS identity sync activation');
eq('["oidc-ingress"]', $reverseFrontendPayload['objects'][3]['data']['sync_ssl_certificate_descriptions'], 'reverse payload remains certificate-ref independent');

$missingFrontendCert = receiverBase();
bad(
    fn() => HAProxySync::reconcile($missingFrontendCert, $frontendPayload),
    'frontend sync fails closed when receiver-local certificate description is missing'
);

$ambiguousFrontendCert = receiverBase();
$ambiguousFrontendCert['cert'] = [
    ['refid' => 'ambiguous-cert-a', 'descr' => 'oidc-ingress'],
    ['refid' => 'ambiguous-cert-b', 'descr' => 'oidc-ingress'],
];
bad(
    fn() => HAProxySync::reconcile($ambiguousFrontendCert, $frontendPayload),
    'frontend sync fails closed when receiver certificate description is ambiguous'
);

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
eq('receiver-uuid-2', $updatedServer['@attributes']['uuid'], 'update preserves local server UUID');
eq('receiver-id-2', $updatedServer['id'], 'update preserves local server id');
eq('192.0.2.55', $updatedServer['address'], 'update changes scalar data');

$localOnly = $source;
$localOnly['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment'][1]['policy_id'] = 'core';
bad(fn() => HAProxySync::buildPayload($localOnly), 'sync backend cannot depend on a local-only server');

$localOnlyHealthcheck = $source;
$localOnlyHealthcheck['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments']['assignment'][0]['policy_id'] = 'core';
bad(fn() => HAProxySync::buildPayload($localOnlyHealthcheck), 'sync backend cannot depend on a local-only healthcheck');

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
$legacy['OPNsense']['HAProxy']['healthchecks'] = $source['OPNsense']['HAProxy']['healthchecks'];
$legacy['OPNsense']['HAProxy']['servers'] = $source['OPNsense']['HAProxy']['servers'];
$legacy['OPNsense']['HAProxy']['backends'] = $source['OPNsense']['HAProxy']['backends'];
$legacy['OPNsense']['HAProxy']['healthchecks']['healthcheck']['@attributes']['uuid'] = 'legacy-healthcheck-uuid';
$legacy['OPNsense']['HAProxy']['healthchecks']['healthcheck']['id'] = 'legacy-healthcheck-id';
$legacy['OPNsense']['HAProxy']['servers']['server']['@attributes']['uuid'] = 'legacy-server-uuid';
$legacy['OPNsense']['HAProxy']['servers']['server']['id'] = 'legacy-server-id';
$legacy['OPNsense']['HAProxy']['backends']['backend']['@attributes']['uuid'] = 'legacy-backend-uuid';
$legacy['OPNsense']['HAProxy']['backends']['backend']['id'] = 'legacy-backend-id';
$legacy['OPNsense']['HAProxy']['backends']['backend']['linkedServers'] = 'legacy-server-uuid';
$legacy['OPNsense']['HAProxy']['backends']['backend']['healthCheck'] = 'legacy-healthcheck-uuid';
$legacy['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'] = $source['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'];
$adopted = HAProxySync::reconcile($legacy, $payload, nextFactory('adopt-meta-'), nextFactory('unused-id-'));
eq(3, count(HAProxySync::assignments($adopted['config'])), 'matching existing assignments remain directly synchronized');
$adoptedHealthchecks = rows($adopted['config']['OPNsense']['HAProxy']['healthchecks'], 'healthcheck');
$adoptedServers = rows($adopted['config']['OPNsense']['HAProxy']['servers'], 'server');
$adoptedBackends = rows($adopted['config']['OPNsense']['HAProxy']['backends'], 'backend');
eq('legacy-healthcheck-uuid', $adoptedHealthchecks[0]['@attributes']['uuid'], 'adoption preserves receiver healthcheck UUID');
eq('legacy-healthcheck-id', $adoptedHealthchecks[0]['id'], 'adoption preserves receiver healthcheck id');
eq('legacy-server-uuid', $adoptedServers[0]['@attributes']['uuid'], 'adoption preserves receiver server UUID');
eq('legacy-server-id', $adoptedServers[0]['id'], 'adoption preserves receiver server id');
eq('legacy-backend-uuid', $adoptedBackends[0]['@attributes']['uuid'], 'adoption preserves receiver backend UUID');
eq('legacy-server-uuid', $adoptedBackends[0]['linkedServers'], 'adopted backend remains linked to receiver server UUID');
eq('legacy-healthcheck-uuid', $adoptedBackends[0]['healthCheck'], 'adopted backend remains linked to receiver healthcheck UUID');
eq('endpoint', HAProxySync::assignments($adopted['config'])['server:origin-customer-example']['policy_id'], 'local assignment policy is retained');

$emptyPayload = $payload;
$emptyPayload['objects'] = [];
$pruned = HAProxySync::reconcile(
    $createdConfig,
    $emptyPayload,
    fn() => throw new RuntimeException('prune UUID factory should not run'),
    fn() => throw new RuntimeException('prune id factory should not run')
);
eq([], rows($pruned['config']['OPNsense']['HAProxy']['healthchecks'], 'healthcheck'), 'stale peer-owned healthcheck pruned');
eq([], rows($pruned['config']['OPNsense']['HAProxy']['servers'], 'server'), 'stale peer-owned server pruned');
eq([], rows($pruned['config']['OPNsense']['HAProxy']['backends'], 'backend'), 'stale peer-owned backend pruned');
eq([], HAProxySync::assignments($pruned['config']), 'stale synchronized policy assignments pruned');
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
        'linkedServers' => 'receiver-uuid-2',
    ],
];
bad(fn() => HAProxySync::reconcile($unsafePrune, $emptyPayload), 'cannot prune server still referenced by local backend');

$unsafeHealthcheckPrune = $createdConfig;
$unsafeHealthcheckPrune['OPNsense']['HAProxy']['backends']['backend'] = [
    $unsafeHealthcheckPrune['OPNsense']['HAProxy']['backends']['backend'],
    [
        '@attributes' => ['uuid' => 'local-health-backend-uuid'],
        'id' => 'local-health-backend-id',
        'enabled' => '1',
        'name' => 'local-health-backend',
        'mode' => 'tcp',
        'algorithm' => 'roundrobin',
        'linkedServers' => '',
        'healthCheck' => 'receiver-uuid-1',
    ],
];
bad(fn() => HAProxySync::reconcile($unsafeHealthcheckPrune, $emptyPayload), 'cannot prune healthcheck still referenced by local backend');

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
$nativeEmpty['OPNsense']['HAProxy']['healthchecks'] = [];
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
eq([], $nativeEmptyResult['config']['OPNsense']['HAProxy']['healthchecks'], 'native empty healthcheck array shape is preserved');
eq([], $nativeEmptyResult['config']['OPNsense']['HAProxy']['servers'], 'native empty server array shape is preserved');
eq('', $nativeEmptyResult['config']['OPNsense']['HAProxy']['backends'], 'native empty backend string shape is preserved');

// A freshly installed peer can expose an empty ArrayField container as [].
// The first synchronized object must still be wrapped under its singular MVC
// item name; otherwise write_config() creates <servers uuid="..."> and native
// HAProxy ignores the object even though the custom inventory can parse it.
$emptyArrayCreate = receiverBase();
$emptyArrayCreate['OPNsense']['HAProxy']['healthchecks'] = [];
$emptyArrayCreate['OPNsense']['HAProxy']['servers'] = [];
$emptyArrayCreate['OPNsense']['HAProxy']['backends'] = [];
$emptyArrayResult = HAProxySync::reconcile(
    $emptyArrayCreate,
    $payload,
    nextFactory('empty-array-uuid-'),
    nextFactory('empty-array-id-')
);
eq(true, isset($emptyArrayResult['config']['OPNsense']['HAProxy']['healthchecks']['healthcheck']), 'first healthcheck uses native MVC item container');
eq(true, isset($emptyArrayResult['config']['OPNsense']['HAProxy']['servers']['server']), 'first server uses native MVC item container');
eq(true, isset($emptyArrayResult['config']['OPNsense']['HAProxy']['backends']['backend']), 'first backend uses native MVC item container');
eq(1, count(rows($emptyArrayResult['config']['OPNsense']['HAProxy']['healthchecks'], 'healthcheck')), 'native MVC sees first synchronized healthcheck');
eq(1, count(rows($emptyArrayResult['config']['OPNsense']['HAProxy']['servers'], 'server')), 'native MVC sees first synchronized server');
eq(1, count(rows($emptyArrayResult['config']['OPNsense']['HAProxy']['backends'], 'backend')), 'native MVC sees first synchronized backend');

// The new Rigi accepts the old Etna v2 payload, stores normal policy
// assignments, and immediately becomes a valid source for the reverse sync.
$serializedEmpty = receiverBase();
$serializedEmpty['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']['haproxy_assignments'] = '';
$serializedCreate = HAProxySync::reconcile($serializedEmpty, $payload, nextFactory('serialized-uuid-'), nextFactory('serialized-id-'));
eq(3, count(HAProxySync::assignments($serializedCreate['config'])), 'empty assignment container accepts old v2 payload');
eq(HAProxySync::validatePayload($payload), HAProxySync::validatePayload(HAProxySync::buildPayload($createdConfig)), 'receiver emits original semantic payload in reverse');
$cycled = HAProxySync::reconcile($source, HAProxySync::buildPayload($createdConfig), nextFactory('cycle-uuid-'), nextFactory('cycle-id-'));
eq(HAProxySync::validatePayload($payload), HAProxySync::validatePayload(HAProxySync::buildPayload($cycled['config'])), 'reverse sync preserves semantic relations and policies');
eq('source-server-uuid', rows($cycled['config']['OPNsense']['HAProxy']['servers'], 'server')[0]['@attributes']['uuid'], 'reverse keeps source-local HAProxy UUID');

fwrite(STDOUT, "HAProxy policy sync tests passed\n");

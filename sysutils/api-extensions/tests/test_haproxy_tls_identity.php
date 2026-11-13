<?php
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxyTLSIdentitySync.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxyTLSIdentityMaterializer.php';

use OPNsense\ApiExtensions\HAProxyTLSIdentityMaterializer;
use OPNsense\ApiExtensions\HAProxyTLSIdentitySync;

function tlsEq($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "$message\nexpected=" . var_export($expected, true) . "\nactual=" . var_export($actual, true) . "\n");
        exit(1);
    }
}

function tlsBad(callable $fn, string $message): void
{
    try {
        $fn();
    } catch (InvalidArgumentException $error) {
        return;
    }
    fwrite(STDERR, "$message: expected InvalidArgumentException\n");
    exit(1);
}

function tlsPolicyModel(): array
{
    return [
        'shared' => ['policies' => ['policy' => [
            [
                '@attributes' => ['uuid' => 'policy-endpoint-uuid'],
                'id' => 'endpoint',
                'description' => 'Endpoint-owned synchronized objects',
                'synchronize' => '1',
            ],
            [
                '@attributes' => ['uuid' => 'policy-local-uuid'],
                'id' => 'local',
                'description' => 'Local-only objects',
                'synchronize' => '0',
            ],
        ]]],
        'assignments' => '',
        'replicas' => '',
        'haproxy_assignments' => '',
        'haproxy_replicas' => '',
    ];
}

function tlsIdentity(string $frontend, string $dns, string $policyUuid, string $uuid): array
{
    return [
        '@attributes' => ['uuid' => $uuid],
        'frontend_name' => $frontend,
        'dns_name' => $dns,
        'policy_id' => $policyUuid,
    ];
}

function tlsConfig(array $rows, bool $authoritative = false): array
{
    return [
        'OPNsense' => [
            'ApiExtensions' => [
                'InterfaceSyncPolicy' => tlsPolicyModel(),
                'HAProxyTLSIdentity' => [
                    'sync_marker' => ['enabled' => $authoritative ? '1' : '0'],
                    'identities' => ['identity' => $rows],
                ],
            ],
            'HAProxy' => [
                'frontends' => ['frontend' => [
                    [
                        '@attributes' => ['uuid' => 'shared-frontend-uuid'],
                        'id' => 'shared-frontend-id',
                        'name' => 'arcturus-shared-https',
                        'ssl_enabled' => '1',
                    ],
                    [
                        '@attributes' => ['uuid' => 'local-frontend-uuid'],
                        'id' => 'local-frontend-id',
                        'name' => 'local-only-https',
                        'ssl_enabled' => '1',
                    ],
                ]],
            ],
        ],
    ];
}

$shared = 'arcturus-shared-https';
$local = 'local-only-https';
$config = tlsConfig([
    tlsIdentity($shared, 'Router.Example.Invalid.', 'policy-endpoint-uuid', 'shared-router'),
    tlsIdentity($local, 'private.example.invalid', 'policy-local-uuid', 'local-private'),
]);

tlsEq(false, HAProxyTLSIdentitySync::isAuthoritative($config), 'fresh model is not authoritative before first v4 reconciliation');

$identities = HAProxyTLSIdentitySync::identities($config);
tlsEq(
    ['arcturus-shared-https|router.example.invalid', 'local-only-https|private.example.invalid'],
    array_keys($identities),
    'identity keys normalize and sort'
);
tlsEq('endpoint', $identities['arcturus-shared-https|router.example.invalid']['policy_id'], 'policy UUID resolves to semantic ID');
tlsEq(
    'HAProxy TLS router.example.invalid',
    HAProxyTLSIdentitySync::certificateDescription('Router.Example.Invalid.'),
    'certificate description is deterministic and Router-owned'
);

$payload = HAProxyTLSIdentitySync::buildPayload($config);
tlsEq(1, count($payload), 'payload includes only synchronized-policy identities');
tlsEq([
    'frontend_name' => $shared,
    'dns_name' => 'router.example.invalid',
    'policy_id' => 'endpoint',
], $payload[0], 'payload is semantic and non-secret');

$policies = OPNsense\ApiExtensions\InterfaceSync::policies($config);
tlsEq($payload, HAProxyTLSIdentitySync::validatePayload($payload, $policies), 'valid payload round trips');

$unknownField = $payload;
$unknownField[0]['private_key'] = 'must-never-exist';
tlsBad(
    fn() => HAProxyTLSIdentitySync::validatePayload($unknownField, $policies),
    'payload rejects secret/unknown fields'
);

$localOnlyPayload = $payload;
$localOnlyPayload[0]['policy_id'] = 'local';
tlsBad(
    fn() => HAProxyTLSIdentitySync::validatePayload($localOnlyPayload, $policies),
    'payload rejects local-only policy'
);

$missingFrontend = tlsConfig([]);
$desired = [[
    'frontend_name' => 'does-not-exist',
    'dns_name' => 'id.example.invalid',
    'policy_id' => 'endpoint',
]];
tlsBad(
    fn() => HAProxyTLSIdentitySync::reconcile($missingFrontend, $desired),
    'receiver rejects identity for missing Core-owned frontend'
);

$desired = [[
    'frontend_name' => $shared,
    'dns_name' => 'id.example.invalid',
    'policy_id' => 'endpoint',
]];
$uuidCounter = 0;
$result = HAProxyTLSIdentitySync::reconcile(
    $config,
    $desired,
    function () use (&$uuidCounter): string {
        $uuidCounter++;
        return 'generated-' . $uuidCounter;
    }
);

tlsEq(true, $result['changed'], 'reconcile changes synchronized identity set');
tlsEq(1, $result['count'], 'reconcile desired count');
tlsEq(1, count($result['ensure']), 'new synchronized identity requires materialization');
tlsEq('id.example.invalid', $result['ensure'][0]['dns_name'], 'ensure names new identity');
tlsEq(1, count($result['remove']), 'old synchronized identity requires cleanup');
tlsEq('router.example.invalid', $result['remove'][0]['dns_name'], 'remove names old identity');
tlsEq(true, HAProxyTLSIdentitySync::isAuthoritative($result['config']), 'v4 reconciliation permanently marks identity set authoritative');

$after = HAProxyTLSIdentitySync::identities($result['config']);
tlsEq(
    ['arcturus-shared-https|id.example.invalid', 'local-only-https|private.example.invalid'],
    array_keys($after),
    'reconcile prunes only synchronized identities and preserves local-only identities'
);
tlsEq('generated-1', $after['arcturus-shared-https|id.example.invalid']['@attributes']['uuid'], 'receiver creates local identity UUID');
tlsEq('local-private', $after['local-only-https|private.example.invalid']['@attributes']['uuid'], 'local-only UUID preserved');

$stable = HAProxyTLSIdentitySync::reconcile(
    $result['config'],
    $desired,
    fn(): string => 'must-not-be-used'
);
tlsEq(false, $stable['changed'], 'identical desired identity is converged');
tlsEq([], $stable['ensure'], 'converged identity does not re-materialize');
tlsEq([], $stable['remove'], 'converged identity does not remove material');

$pruned = HAProxyTLSIdentitySync::reconcile(
    $stable['config'],
    [],
    fn(): string => 'must-not-be-used'
);
tlsEq(true, $pruned['changed'], 'last synchronized identity can be removed');
tlsEq(1, count($pruned['remove']), 'last synchronized identity schedules cleanup');
tlsEq(
    ['local-only-https|private.example.invalid'],
    array_keys(HAProxyTLSIdentitySync::identities($pruned['config'])),
    'last synchronized identity removal preserves unrelated local-only identity'
);
tlsEq(true, HAProxyTLSIdentitySync::isAuthoritative($pruned['config']), 'authoritative marker survives empty synchronized set');
tlsEq([], HAProxyTLSIdentitySync::buildPayload($pruned['config']), 'authoritative empty set serializes as empty TLS identity payload');

$multiFrontend = tlsConfig([
    tlsIdentity($shared, 'router.example.invalid', 'policy-endpoint-uuid', 'shared-router'),
    tlsIdentity($local, 'router.example.invalid', 'policy-local-uuid', 'local-router'),
    tlsIdentity($shared, 'id.example.invalid', 'policy-endpoint-uuid', 'shared-id'),
], true);
$materialization = HAProxyTLSIdentityMaterializer::plan($multiFrontend, 'EXAMPLE.INVALID');
tlsEq(2, count($materialization), 'materializer groups registrations by DNS identity');
tlsEq('id.example.invalid', $materialization[0]['dns_name'], 'materializer plan is deterministic');
tlsEq('HAPROXY/id.example.invalid@EXAMPLE.INVALID', $materialization[0]['principal'], 'principal is derived from consumer DNS identity');
tlsEq('CN=id.example.invalid,O=EXAMPLE.INVALID', $materialization[0]['subject'], 'certificate subject is derived');
tlsEq('HAProxy TLS id.example.invalid', $materialization[0]['certificate_description'], 'Trust description is Router-derived');
tlsEq(13, strlen($materialization[0]['certificate_ref_id']), 'Trust refid is deterministic OPNsense-sized value');
tlsEq(['arcturus-shared-https'], $materialization[0]['frontends'], 'single frontend membership preserved');
tlsEq(
    ['arcturus-shared-https', 'local-only-https'],
    $materialization[1]['frontends'],
    'same DNS identity shares one node-local cert across multiple frontend memberships'
);
tlsEq(
    HAProxyTLSIdentityMaterializer::certificatePath('router.example.invalid'),
    $materialization[1]['certificate_path'],
    'certificate path is deterministic'
);
tlsEq(
    HAProxyTLSIdentityMaterializer::keyPath('router.example.invalid'),
    $materialization[1]['key_path'],
    'private-key path is deterministic and node-local'
);

$runtimeParity = [
    'frontend-a' => [
        'local_certs' => ['/tmp/b.pem', '/tmp/a.pem'],
        'remote_certs' => ['/tmp/a.pem', '/tmp/b.pem'],
        'local_default' => '/tmp/a.pem',
        'remote_default' => '/tmp/a.pem',
    ],
];
tlsEq(false, HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeParity), 'runtime certificate membership comparison is order-insensitive');

$runtimeMissing = $runtimeParity;
$runtimeMissing['frontend-a']['remote_certs'] = ['/tmp/a.pem'];
tlsEq(true, HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeMissing), 'runtime missing managed certificate requires HAProxy reload');

$runtimeDefault = $runtimeParity;
$runtimeDefault['frontend-a']['remote_default'] = '/tmp/b.pem';
tlsEq(true, HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeDefault), 'runtime default certificate mismatch requires HAProxy reload');

tlsBad(
    fn() => HAProxyTLSIdentityMaterializer::runtimeMembershipChanged([
        'frontend-a' => ['local_certs' => 'not-a-list', 'remote_certs' => []],
    ]),
    'runtime certificate diff rejects malformed membership lists'
);

echo "ok\n";

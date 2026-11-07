<?php
namespace OPNsense\ApiExtensions;

require_once __DIR__ . '/InterfaceSync.php';

final class HAProxySync
{
    public const VERSION = 3;
    public const LEGACY_VERSION = 2;
    public const HA_SYNC_ITEM = 'haproxy_objects';

    private const OBJECT_TYPES = ['healthcheck', 'server', 'backend', 'frontend'];
    private const OBJECT_NAME = '/^[0-9A-Za-z._-]{1,255}$/D';
    private const HOST_NAME = '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D';
    private const DYNAMIC_SNI_DISPATCH = 'use_backend nc-sni-%[ssl_fc_sni,lower]';
    private const DYNAMIC_HOST_DISPATCH = '/^use_backend ([0-9A-Za-z._-]{1,255}) if \\{ hdr\\(host\\),lower,field\\(1,:\\) -m str ([a-z0-9.-]{1,253}) \\}$/D';
    private const SERVER_UNSUPPORTED_REFERENCES = [
        'linkedResolver',
        'sslCA',
        'sslCRL',
        'sslClientCertificate',
        'unix_socket',
    ];
    private const BACKEND_UNSUPPORTED_REFERENCES = [
        'linkedFcgi',
        'linkedResolver',
        'linkedMailer',
        'basicAuthUsers',
        'basicAuthGroups',
        'linkedActions',
        'linkedErrorfiles',
    ];
    private const FRONTEND_UNSUPPORTED_REFERENCES = [
        'ssl_clientAuthCAs',
        'ssl_clientAuthCRLs',
        'basicAuthUsers',
        'basicAuthGroups',
        'linkedCpuAffinityRules',
        'linkedActions',
        'linkedErrorfiles',
    ];

    private static function fail(string $message): void
    {
        throw new \InvalidArgumentException($message);
    }

    private static function flag($value): bool
    {
        return in_array($value, [1, '1', true, 'yes', 'on'], true);
    }

    private static function rows($value, string $label): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (!is_array($value)) {
            self::fail($label . ' must be an array');
        }
        if (!array_is_list($value)) {
            return [$value];
        }
        return array_values($value);
    }

    private static function containerRows($container, string $item, string $label): array
    {
        if ($container === null || $container === '') {
            return [];
        }
        if (!is_array($container)) {
            self::fail($label . ' must be an object');
        }

        // OPNsense MVC config serialization has multiple equivalent 0/1/N
        // shapes. In particular HAProxy may serialize repeated model nodes as
        // a list of one-key wrappers (for example [{"server": {...}}]) while
        // another section is serialized as {"backend": {...}}. Accept all
        // canonical shapes here and normalize them to a flat record list.
        if (array_is_list($container)) {
            $out = [];
            foreach ($container as $index => $entry) {
                if (!is_array($entry)) {
                    self::fail(sprintf('%s.%d must be an object', $label, $index));
                }
                if (array_key_exists($item, $entry)) {
                    foreach (self::rows($entry[$item], $label . '.' . $item) as $row) {
                        $out[] = $row;
                    }
                } else {
                    // Also tolerate a direct list of records.
                    $out[] = $entry;
                }
            }
            return $out;
        }

        if (array_key_exists($item, $container)) {
            return self::rows($container[$item], $label . '.' . $item);
        }

        // A singleton may be represented directly without the item wrapper.
        return [$container];
    }

    private static function serializeRows(string $item, array $rows)
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return '';
        }
        return [$item => count($rows) === 1 ? $rows[0] : $rows];
    }

    private static function serializeRowsLike($current, string $item, array $rows)
    {
        $rows = array_values($rows);
        if ($rows === []) {
            // Empty HAProxy MVC sections legitimately persist as either an
            // empty string or an empty array. Preserve an already-empty shape
            // so save/reload normalization cannot manufacture perpetual
            // `changed=true` results on an empty authoritative payload.
            if ($current === '' || $current === null || $current === []) {
                return $current;
            }
            return '';
        }

        // Preserve the shape already used by config.xml. OPNsense's HAProxy
        // model can persist repeated nodes as [{"server": {...}}], while an
        // in-memory reconcile commonly starts with {"server": {...}}. Writing
        // the latter is normalized back to the former by OPNsense, so forcing a
        // single canonical shape here would make every subsequent sync appear
        // changed even though all object data and UUIDs are identical.
        if (is_array($current) && array_is_list($current)) {
            // An empty array carries no information about the persisted row
            // wrapper shape. Start from the canonical item container instead
            // of emitting raw rows. Raw rows would serialize a first server as
            // <servers uuid="..."> rather than <servers><server ...>, which the
            // native HAProxy MVC model does not recognize.
            if ($current === []) {
                return self::serializeRows($item, $rows);
            }
            $wrapped = true;
            foreach ($current as $entry) {
                if (!is_array($entry) || !array_key_exists($item, $entry)) {
                    $wrapped = false;
                    break;
                }
            }
            if ($wrapped) {
                return array_map(fn($row) => [$item => $row], $rows);
            }
            // A direct row list is accepted on read for defensive recovery, but
            // it is not a valid native MVC persistence shape. Canonicalize it
            // on the next reconciliation so an already malformed peer heals.
            return self::serializeRows($item, $rows);
        }

        if (is_array($current) && !array_is_list($current) && !array_key_exists($item, $current)) {
            return count($rows) === 1 ? $rows[0] : $rows;
        }

        return self::serializeRows($item, $rows);
    }

    private static function objectType($value): string
    {
        $value = trim((string)$value);
        if (!in_array($value, self::OBJECT_TYPES, true)) {
            self::fail('HAProxy sync object_type must be healthcheck, server, backend or frontend');
        }
        return $value;
    }

    private static function objectName($value): string
    {
        $value = trim((string)$value);
        if (!preg_match(self::OBJECT_NAME, $value)) {
            self::fail('invalid HAProxy sync object name');
        }
        return $value;
    }

    private static function objectKey(string $type, string $name): string
    {
        return $type . ':' . $name;
    }

    private static function policyRoot(array $config): array
    {
        $root = $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'] ?? [];
        if ($root === null || $root === '') {
            return [];
        }
        if (!is_array($root)) {
            self::fail('HA sync policy configuration must be an object');
        }
        return $root;
    }

    private static function &policyRootForWrite(array &$config): array
    {
        if (!isset($config['OPNsense']) || !is_array($config['OPNsense'])) {
            $config['OPNsense'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']) || !is_array($config['OPNsense']['ApiExtensions'])) {
            $config['OPNsense']['ApiExtensions'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy']) ||
            !is_array($config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'])) {
            $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'] = [];
        }
        return $config['OPNsense']['ApiExtensions']['InterfaceSyncPolicy'];
    }

    private static function haproxyRoot(array $config): array
    {
        $root = $config['OPNsense']['HAProxy'] ?? [];
        if ($root === null || $root === '') {
            return [];
        }
        if (!is_array($root)) {
            self::fail('OPNsense.HAProxy configuration must be an object');
        }
        return $root;
    }

    private static function &haproxyRootForWrite(array &$config): array
    {
        if (!isset($config['OPNsense']) || !is_array($config['OPNsense'])) {
            $config['OPNsense'] = [];
        }
        if (!isset($config['OPNsense']['HAProxy']) || !is_array($config['OPNsense']['HAProxy'])) {
            $config['OPNsense']['HAProxy'] = [];
        }
        return $config['OPNsense']['HAProxy'];
    }

    public static function isEnabled(array $config): bool
    {
        $items = preg_split('/[\s,]+/', trim((string)($config['hasync']['syncitems'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        return in_array(self::HA_SYNC_ITEM, $items ?: [], true);
    }

    public static function assignments(array $config): array
    {
        $root = self::policyRoot($config);
        $policies = InterfaceSync::policies($config);
        $policyByUuid = [];
        foreach ($policies as $policyId => $policy) {
            $policyByUuid[$policy['uuid']] = $policyId;
        }

        $out = [];
        foreach (self::containerRows(
            $root['haproxy_assignments'] ?? [],
            'assignment',
            'HAProxy sync assignments container'
        ) as $row) {
            if (!is_array($row)) {
                self::fail('invalid HAProxy policy assignment record');
            }
            $type = self::objectType($row['object_type'] ?? '');
            $name = self::objectName($row['object_name'] ?? '');
            $policyRef = trim((string)($row['policy_id'] ?? ''));
            if (isset($policies[$policyRef])) {
                $policyId = $policyRef;
            } elseif (isset($policyByUuid[$policyRef])) {
                $policyId = $policyByUuid[$policyRef];
            } else {
                self::fail(sprintf('HAProxy %s %s references unknown policy relation %s', $type, $name, $policyRef));
            }
            $key = self::objectKey($type, $name);
            if (isset($out[$key])) {
                self::fail('duplicate HAProxy policy assignment ' . $key);
            }
            $out[$key] = [
                'object_type' => $type,
                'object_name' => $name,
                'policy_id' => $policyId,
                'policy_uuid' => $policies[$policyId]['uuid'],
                '@attributes' => is_array($row['@attributes'] ?? null) ? $row['@attributes'] : [],
            ];
        }
        return $out;
    }

    private static function haProxyRows(array $config, string $type): array
    {
        $root = self::haproxyRoot($config);
        $section = match ($type) {
            'healthcheck' => 'healthchecks',
            'server' => 'servers',
            'backend' => 'backends',
            'frontend' => 'frontends',
            default => throw new \InvalidArgumentException('unsupported HAProxy object type'),
        };
        return self::containerRows($root[$section] ?? [], $type, 'OPNsense.HAProxy.' . $section);
    }

    public static function inventory(array $config): array
    {
        $objects = [];
        $serverUuidToName = [];
        $healthcheckUuidToName = [];
        $backendUuidToName = [];
        foreach (self::OBJECT_TYPES as $type) {
            foreach (self::haProxyRows($config, $type) as $row) {
                if (!is_array($row)) {
                    self::fail('invalid HAProxy ' . $type . ' record');
                }
                $name = self::objectName($row['name'] ?? '');
                $key = self::objectKey($type, $name);
                if (isset($objects[$key])) {
                    self::fail('duplicate HAProxy semantic name ' . $key);
                }
                $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
                $id = trim((string)($row['id'] ?? ''));
                $objects[$key] = [
                    'object_type' => $type,
                    'object_name' => $name,
                    'uuid' => $uuid,
                    'id' => $id,
                    'row' => $row,
                ];
                if (in_array($type, ['server', 'healthcheck', 'backend', 'frontend'], true)) {
                    if ($uuid === '') {
                        self::fail('HAProxy ' . $type . ' ' . $name . ' is missing its MVC UUID');
                    }
                    if ($type === 'server') {
                        if (isset($serverUuidToName[$uuid])) {
                            self::fail('duplicate HAProxy server MVC UUID');
                        }
                        $serverUuidToName[$uuid] = $name;
                    } elseif ($type === 'healthcheck') {
                        if (isset($healthcheckUuidToName[$uuid])) {
                            self::fail('duplicate HAProxy healthcheck MVC UUID');
                        }
                        $healthcheckUuidToName[$uuid] = $name;
                    } elseif ($type === 'backend') {
                        if (isset($backendUuidToName[$uuid])) {
                            self::fail('duplicate HAProxy backend MVC UUID');
                        }
                        $backendUuidToName[$uuid] = $name;
                    }
                }
            }
        }
        ksort($objects);
        return [
            'objects' => $objects,
            'server_uuid_to_name' => $serverUuidToName,
            'healthcheck_uuid_to_name' => $healthcheckUuidToName,
            'backend_uuid_to_name' => $backendUuidToName,
        ];
    }

    private static function relationValues($value): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (is_array($value)) {
            $values = [];
            foreach ($value as $item) {
                if (is_array($item)) {
                    if (self::flag($item['selected'] ?? null)) {
                        $candidate = trim((string)($item['value'] ?? ''));
                        if ($candidate !== '') {
                            $values[] = $candidate;
                        }
                    }
                } else {
                    $candidate = trim((string)$item);
                    if ($candidate !== '') {
                        $values[] = $candidate;
                    }
                }
            }
            return array_values(array_unique($values));
        }
        $values = preg_split('/[\s,]+/', trim((string)$value), -1, PREG_SPLIT_NO_EMPTY);
        return array_values(array_unique($values ?: []));
    }

    private static function hasValue($value): bool
    {
        if ($value === null || $value === '' || $value === [] || $value === false || $value === 0 || $value === '0') {
            return false;
        }
        if (is_array($value)) {
            return self::relationValues($value) !== [];
        }
        return trim((string)$value) !== '';
    }

    /**
     * Return the semantic backend names referenced by a supported fail-closed
     * dynamic frontend. An empty list denotes the legacy SNI-derived dispatch;
     * null means the custom options are not a supported dynamic contract.
     *
     * Host dispatch is deliberately strict: each line may only select one
     * named backend from the normalized HTTP Host value. This keeps HTTP/2
     * connection coalescing safe without turning synchronized customOptions
     * into an arbitrary HAProxy configuration channel.
     */
    private static function dynamicFrontendBackendNames(array $data): ?array
    {
        $customOptions = trim((string)($data['customOptions'] ?? ''));
        if ($customOptions === self::DYNAMIC_SNI_DISPATCH) {
            return [];
        }
        if ($customOptions === '') {
            return null;
        }

        $backends = [];
        $hosts = [];
        foreach (preg_split('/\\R/', $customOptions) ?: [] as $line) {
            if ($line === '' || !preg_match(self::DYNAMIC_HOST_DISPATCH, $line, $matches)) {
                return null;
            }
            $backend = self::objectName($matches[1]);
            $host = $matches[2];
            if (!preg_match(self::HOST_NAME, $host) || isset($hosts[$host])) {
                return null;
            }
            $hosts[$host] = true;
            $backends[$backend] = true;
        }
        return $hosts === [] ? null : array_keys($backends);
    }

    private static function isDynamicFrontend(array $data): bool
    {
        return self::dynamicFrontendBackendNames($data) !== null;
    }

    private static function certificateIndexes(array $config): array
    {
        $byRef = [];
        $byDescription = [];
        foreach (self::containerRows($config['cert'] ?? [], 'cert', 'system certificate container') as $row) {
            if (!is_array($row)) {
                self::fail('invalid system certificate record');
            }
            $ref = trim((string)($row['refid'] ?? ''));
            $description = trim((string)($row['descr'] ?? ''));
            if ($ref === '') {
                continue;
            }
            if (isset($byRef[$ref])) {
                self::fail('duplicate system certificate refid ' . $ref);
            }
            $byRef[$ref] = $description;
            if ($description !== '') {
                $byDescription[$description] ??= [];
                $byDescription[$description][] = $ref;
            }
        }
        return [
            'ref_to_description' => $byRef,
            'description_to_refs' => $byDescription,
        ];
    }

    private static function certificateDescription(array $index, string $ref): string
    {
        $description = trim((string)($index['ref_to_description'][$ref] ?? ''));
        if ($description === '') {
            self::fail('HAProxy frontend references certificate refid without a stable description: ' . $ref);
        }
        return $description;
    }

    private static function certificateRef(array $index, string $description): string
    {
        $refs = array_values(array_unique($index['description_to_refs'][$description] ?? []));
        if ($refs === []) {
            self::fail('HAProxy frontend certificate description is not installed locally: ' . $description);
        }
        if (count($refs) !== 1) {
            self::fail('HAProxy frontend certificate description is ambiguous locally: ' . $description);
        }
        return $refs[0];
    }

    private static function decodeCertificateDescriptions(string $encoded): array
    {
        try {
            $value = json_decode($encoded, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            self::fail('invalid HAProxy frontend certificate description payload');
        }
        if (!is_array($value) || !array_is_list($value)) {
            self::fail('HAProxy frontend certificate descriptions must be a JSON list');
        }
        $out = [];
        foreach ($value as $description) {
            if (!is_scalar($description)) {
                self::fail('HAProxy frontend certificate description must be a string');
            }
            $description = trim((string)$description);
            if ($description === '') {
                self::fail('HAProxy frontend certificate description must not be empty');
            }
            $out[] = $description;
        }
        return array_values(array_unique($out));
    }

    private static function payloadData(
        array $row,
        string $type,
        array $serverUuidToName,
        array $healthcheckUuidToName,
        array $backendUuidToName,
        array $certificateIndex
    ): array {
        $unsupported = match ($type) {
            'server' => self::SERVER_UNSUPPORTED_REFERENCES,
            'backend' => self::BACKEND_UNSUPPORTED_REFERENCES,
            'frontend' => self::FRONTEND_UNSUPPORTED_REFERENCES,
            'healthcheck' => [],
            default => throw new InvalidArgumentException('unsupported HAProxy object type'),
        };
        foreach ($unsupported as $field) {
            if (self::hasValue($row[$field] ?? null)) {
                self::fail(sprintf(
                    'HAProxy %s %s uses unsupported node-local reference %s',
                    $type,
                    (string)($row['name'] ?? ''),
                    $field
                ));
            }
        }

        $data = $row;
        unset($data['@attributes'], $data['id']);
        $linkedServerNames = [];
        $linkedHealthcheckName = '';
        if ($type === 'backend') {
            foreach (self::relationValues($data['linkedServers'] ?? null) as $serverUuid) {
                if (!isset($serverUuidToName[$serverUuid])) {
                    self::fail(sprintf(
                        'HAProxy backend %s references unknown server UUID %s',
                        (string)($row['name'] ?? ''),
                        $serverUuid
                    ));
                }
                $linkedServerNames[] = $serverUuidToName[$serverUuid];
            }
            $healthchecks = self::relationValues($data['healthCheck'] ?? null);
            if (count($healthchecks) > 1) {
                self::fail('HAProxy backend healthCheck must reference at most one Health Monitor');
            }
            if ($healthchecks !== []) {
                $healthcheckUuid = $healthchecks[0];
                if (!isset($healthcheckUuidToName[$healthcheckUuid])) {
                    self::fail(sprintf(
                        'HAProxy backend %s references unknown healthcheck UUID %s',
                        (string)($row['name'] ?? ''),
                        $healthcheckUuid
                    ));
                }
                $linkedHealthcheckName = $healthcheckUuidToName[$healthcheckUuid];
            }
            unset($data['linkedServers'], $data['healthCheck']);
        } elseif ($type === 'frontend') {
            $backends = self::relationValues($data['defaultBackend'] ?? null);
            if (count($backends) > 1) {
                self::fail('Policy-managed HAProxy frontend must reference at most one default backend');
            }
            $backendName = '';
            if ($backends !== []) {
                $backendUuid = $backends[0];
                if (!isset($backendUuidToName[$backendUuid])) {
                    self::fail(sprintf(
                        'HAProxy frontend %s references unknown backend UUID %s',
                        (string)($row['name'] ?? ''),
                        $backendUuid
                    ));
                }
                $backendName = $backendUuidToName[$backendUuid];
            } elseif (!self::isDynamicFrontend($data)) {
                self::fail('Policy-managed HAProxy frontend without a default backend must use a supported fail-closed dynamic dispatch');
            }

            $certificateDescriptions = [];
            foreach (self::relationValues($data['ssl_certificates'] ?? null) as $certificateRef) {
                $certificateDescriptions[] = self::certificateDescription($certificateIndex, $certificateRef);
            }
            $certificateDescriptions = array_values(array_unique($certificateDescriptions));

            $defaultCertificateRefs = self::relationValues($data['ssl_default_certificate'] ?? null);
            if (count($defaultCertificateRefs) > 1) {
                self::fail('HAProxy frontend default certificate must reference at most one certificate');
            }
            $defaultCertificateDescription = $defaultCertificateRefs === []
                ? ''
                : self::certificateDescription($certificateIndex, $defaultCertificateRefs[0]);

            if (self::flag($data['ssl_enabled'] ?? null) && $certificateDescriptions === []) {
                self::fail('TLS-enabled policy-managed HAProxy frontend requires at least one installed certificate');
            }
            if ($defaultCertificateDescription !== '' &&
                !in_array($defaultCertificateDescription, $certificateDescriptions, true)) {
                self::fail('HAProxy frontend default certificate must also be present in its certificate list');
            }

            if (is_array($data['bind'] ?? null)) {
                $data['bind'] = implode(',', self::relationValues($data['bind']));
            }
            unset($data['defaultBackend'], $data['ssl_certificates'], $data['ssl_default_certificate']);
            $data['sync_default_backend_name'] = $backendName;
            $data['sync_ssl_certificate_descriptions'] = json_encode(
                $certificateDescriptions,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
            );
            $data['sync_ssl_default_certificate_description'] = $defaultCertificateDescription;
        }

        foreach ($data as $field => $value) {
            if (!is_scalar($value) && $value !== null) {
                self::fail(sprintf(
                    'HAProxy %s %s field %s has unsupported structured data',
                    $type,
                    (string)($row['name'] ?? ''),
                    $field
                ));
            }
            $data[$field] = $value === null ? '' : (string)$value;
        }
        return [$data, $linkedServerNames, $linkedHealthcheckName];
    }

    public static function buildPayload(array $config): array
    {
        if (!self::isEnabled($config)) {
            self::fail('Policy-managed HAProxy Objects is not enabled in High Availability synchronization');
        }

        $policies = InterfaceSync::policies($config);
        $assignments = self::assignments($config);
        $inventory = self::inventory($config);
        $objects = $inventory['objects'];
        $certificateIndex = self::certificateIndexes($config);

        foreach ($objects as $key => $object) {
            if (!isset($assignments[$key]) && $object['object_type'] !== 'frontend') {
                self::fail(sprintf(
                    'HAProxy %s %s has no mandatory HA policy assignment',
                    $object['object_type'],
                    $object['object_name']
                ));
            }
        }
        foreach ($assignments as $key => $assignment) {
            if (!isset($objects[$key])) {
                self::fail(sprintf(
                    'HAProxy policy assignment references missing %s %s',
                    $assignment['object_type'],
                    $assignment['object_name']
                ));
            }
        }

        $selected = [];
        foreach ($assignments as $key => $assignment) {
            if ($policies[$assignment['policy_id']]['synchronize']) {
                $selected[$key] = true;
            }
        }

        $payloadObjects = [];
        foreach (self::OBJECT_TYPES as $type) {
            foreach ($objects as $key => $object) {
                if ($object['object_type'] !== $type || !isset($selected[$key])) {
                    continue;
                }
                [$data, $linkedServerNames, $linkedHealthcheckName] = self::payloadData(
                    $object['row'],
                    $type,
                    $inventory['server_uuid_to_name'],
                    $inventory['healthcheck_uuid_to_name'],
                    $inventory['backend_uuid_to_name'],
                    $certificateIndex
                );
                if ($type === 'backend') {
                    foreach ($linkedServerNames as $serverName) {
                        $serverKey = self::objectKey('server', $serverName);
                        if (!isset($selected[$serverKey])) {
                            self::fail(sprintf(
                                'HAProxy backend %s links server %s that is not selected for synchronization',
                                $object['object_name'],
                                $serverName
                            ));
                        }
                    }
                    if ($linkedHealthcheckName !== '' &&
                        !isset($selected[self::objectKey('healthcheck', $linkedHealthcheckName)])) {
                        self::fail(sprintf(
                            'HAProxy backend %s links healthcheck %s that is not selected for synchronization',
                            $object['object_name'],
                            $linkedHealthcheckName
                        ));
                    }
                } elseif ($type === 'frontend') {
                    $backendName = trim((string)($data['sync_default_backend_name'] ?? ''));
                    if ($backendName !== '' && !isset($selected[self::objectKey('backend', $backendName)])) {
                        self::fail(sprintf(
                            'HAProxy frontend %s default backend %s is not selected for synchronization',
                            $object['object_name'],
                            $backendName
                        ));
                    }
                    foreach (self::dynamicFrontendBackendNames($data) ?? [] as $dispatchBackendName) {
                        if (!isset($selected[self::objectKey('backend', $dispatchBackendName)])) {
                            self::fail(sprintf(
                                'HAProxy frontend %s dynamic backend %s is not selected for synchronization',
                                $object['object_name'],
                                $dispatchBackendName
                            ));
                        }
                    }
                }
                $payloadObjects[] = [
                    'object_type' => $type,
                    'object_name' => $object['object_name'],
                    'policy_id' => $assignments[$key]['policy_id'],
                    'data' => $data,
                    'linked_server_names' => $linkedServerNames,
                    'linked_healthcheck_name' => $linkedHealthcheckName,
                ];
            }
        }

        $payloadPolicies = [];
        foreach ($policies as $policy) {
            $payloadPolicies[] = [
                'id' => $policy['id'],
                'description' => $policy['description'],
                'synchronize' => $policy['synchronize'],
            ];
        }

        $payloadVersion = self::LEGACY_VERSION;
        foreach ($payloadObjects as $row) {
            if ($row['object_type'] === 'frontend') {
                $payloadVersion = self::VERSION;
                break;
            }
        }

        return [
            'version' => $payloadVersion,
            'policies' => $payloadPolicies,
            'objects' => $payloadObjects,
        ];
    }

    public static function validatePayload($payload): array
    {
        if (!is_array($payload) ||
            array_diff(array_keys($payload), ['version', 'policies', 'objects']) ||
            !array_key_exists('version', $payload) ||
            !array_key_exists('policies', $payload) ||
            !array_key_exists('objects', $payload)) {
            self::fail('invalid HAProxy sync payload');
        }
        $payloadVersion = $payload['version'];
        if (!in_array($payloadVersion, [self::LEGACY_VERSION, self::VERSION], true) ||
            !is_array($payload['policies']) ||
            !is_array($payload['objects'])) {
            self::fail('unsupported HAProxy sync payload');
        }

        $validatedPolicies = InterfaceSync::validatePayload([
            'version' => InterfaceSync::VERSION,
            'policies' => $payload['policies'],
            'interfaces' => [],
            'prune' => true,
        ]);
        $policyMap = [];
        foreach ($validatedPolicies['policies'] as $policy) {
            $policyMap[$policy['id']] = $policy;
        }

        $objects = [];
        $keys = [];
        foreach (array_values($payload['objects']) as $row) {
            if (!is_array($row) ||
                array_diff(array_keys($row), ['object_type', 'object_name', 'policy_id', 'data', 'linked_server_names', 'linked_healthcheck_name']) ||
                count($row) !== 6 ||
                !is_array($row['data']) ||
                !is_array($row['linked_server_names']) ||
                !is_scalar($row['linked_healthcheck_name'])) {
                self::fail('invalid HAProxy sync object record');
            }
            $type = self::objectType($row['object_type']);
            if ($payloadVersion === self::LEGACY_VERSION && $type === 'frontend') {
                self::fail('HAProxy frontend synchronization requires payload version 3');
            }
            $name = self::objectName($row['object_name']);
            $policyId = trim((string)$row['policy_id']);
            if (!isset($policyMap[$policyId])) {
                self::fail(sprintf('HAProxy %s %s references policy %s missing from payload', $type, $name, $policyId));
            }
            if (!$policyMap[$policyId]['synchronize']) {
                self::fail(sprintf('HAProxy %s %s references a local-only policy', $type, $name));
            }
            $key = self::objectKey($type, $name);
            if (isset($keys[$key])) {
                self::fail('duplicate HAProxy sync object ' . $key);
            }
            $keys[$key] = true;

            $data = [];
            foreach ($row['data'] as $field => $value) {
                if (!is_string($field) || $field === '' ||
                    in_array($field, ['@attributes', 'id', 'linkedServers', 'healthCheck'], true) ||
                    (!is_scalar($value) && $value !== null)) {
                    self::fail('invalid HAProxy sync object data');
                }
                $data[$field] = $value === null ? '' : (string)$value;
            }
            if (($data['name'] ?? '') !== $name) {
                self::fail(sprintf('HAProxy %s payload name mismatch for %s', $type, $name));
            }

            if ($type === 'frontend') {
                foreach (['defaultBackend', 'ssl_certificates', 'ssl_default_certificate'] as $rawRelation) {
                    if (array_key_exists($rawRelation, $data)) {
                        self::fail('HAProxy frontend payload must not contain node-local relation ' . $rawRelation);
                    }
                }
                $backendName = trim((string)($data['sync_default_backend_name'] ?? ''));
                if ($backendName !== '') {
                    $backendName = self::objectName($backendName);
                } elseif (!self::isDynamicFrontend($data)) {
                    self::fail('HAProxy frontend without a default backend must use a supported fail-closed dynamic dispatch');
                }
                $certificateDescriptions = self::decodeCertificateDescriptions(
                    (string)($data['sync_ssl_certificate_descriptions'] ?? '')
                );
                $defaultCertificateDescription = trim((string)($data['sync_ssl_default_certificate_description'] ?? ''));
                if (self::flag($data['ssl_enabled'] ?? null) && $certificateDescriptions === []) {
                    self::fail('TLS-enabled HAProxy frontend payload requires certificate descriptions');
                }
                if ($defaultCertificateDescription !== '' &&
                    !in_array($defaultCertificateDescription, $certificateDescriptions, true)) {
                    self::fail('HAProxy frontend default certificate description must be in the certificate list');
                }
                $data['sync_default_backend_name'] = $backendName;
                $data['sync_ssl_certificate_descriptions'] = json_encode(
                    $certificateDescriptions,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
                );
                $data['sync_ssl_default_certificate_description'] = $defaultCertificateDescription;
            } else {
                foreach (array_keys($data) as $field) {
                    if (str_starts_with($field, 'sync_')) {
                        self::fail('Only HAProxy frontend payloads may contain semantic sync fields');
                    }
                }
            }

            $linkedServerNames = [];
            foreach (array_values($row['linked_server_names']) as $serverName) {
                $linkedServerNames[] = self::objectName($serverName);
            }
            $linkedHealthcheckName = trim((string)$row['linked_healthcheck_name']);
            if ($linkedHealthcheckName !== '') {
                $linkedHealthcheckName = self::objectName($linkedHealthcheckName);
            }
            if ($type !== 'backend' && ($linkedServerNames !== [] || $linkedHealthcheckName !== '')) {
                self::fail('Only HAProxy backend records may contain semantic relations');
            }
            $objects[] = [
                'object_type' => $type,
                'object_name' => $name,
                'policy_id' => $policyId,
                'data' => $data,
                'linked_server_names' => array_values(array_unique($linkedServerNames)),
                'linked_healthcheck_name' => $linkedHealthcheckName,
            ];
        }

        $selected = array_fill_keys(array_map(
            fn($row) => self::objectKey($row['object_type'], $row['object_name']),
            $objects
        ), true);
        foreach ($objects as $row) {
            if ($row['object_type'] === 'backend') {
                foreach ($row['linked_server_names'] as $serverName) {
                    if (!isset($selected[self::objectKey('server', $serverName)])) {
                        self::fail(sprintf(
                            'HAProxy backend %s links server %s missing from payload',
                            $row['object_name'],
                            $serverName
                        ));
                    }
                }
                if ($row['linked_healthcheck_name'] !== '' &&
                    !isset($selected[self::objectKey('healthcheck', $row['linked_healthcheck_name'])])) {
                    self::fail(sprintf(
                        'HAProxy backend %s links healthcheck %s missing from payload',
                        $row['object_name'],
                        $row['linked_healthcheck_name']
                    ));
                }
            } elseif ($row['object_type'] === 'frontend') {
                $backendName = $row['data']['sync_default_backend_name'];
                if ($backendName !== '' && !isset($selected[self::objectKey('backend', $backendName)])) {
                    self::fail(sprintf(
                        'HAProxy frontend %s links backend %s missing from payload',
                        $row['object_name'],
                        $backendName
                    ));
                }
                foreach (self::dynamicFrontendBackendNames($row['data']) ?? [] as $dispatchBackendName) {
                    if (!isset($selected[self::objectKey('backend', $dispatchBackendName)])) {
                        self::fail(sprintf(
                            'HAProxy frontend %s dynamic backend %s missing from payload',
                            $row['object_name'],
                            $dispatchBackendName
                        ));
                    }
                }
            }
        }

        usort($objects, function ($a, $b) {
            $typeOrder = ['healthcheck' => 0, 'server' => 1, 'backend' => 2, 'frontend' => 3];
            return [$typeOrder[$a['object_type']], $a['object_name']] <=> [$typeOrder[$b['object_type']], $b['object_name']];
        });
        return [
            'version' => $payloadVersion,
            'policies' => $validatedPolicies['policies'],
            'objects' => $objects,
        ];
    }

    private static function assignmentRowsRaw(array $config): array
    {
        $root = self::policyRoot($config);
        return self::containerRows(
            $root['haproxy_assignments'] ?? [],
            'assignment',
            'HAProxy sync assignments container'
        );
    }

    private static function setAssignmentRows(array &$config, array $rows): void
    {
        $root =& self::policyRootForWrite($config);
        $root['haproxy_assignments'] = self::serializeRows('assignment', $rows);
    }

    private static function setHAProxyRows(array &$config, string $type, array $rows): void
    {
        $root =& self::haproxyRootForWrite($config);
        $section = match ($type) {
            'healthcheck' => 'healthchecks',
            'server' => 'servers',
            'backend' => 'backends',
            'frontend' => 'frontends',
            default => throw new \InvalidArgumentException('unsupported HAProxy object type'),
        };
        $root[$section] = self::serializeRowsLike($root[$section] ?? '', $type, $rows);
    }

    private static function localIdentity(
        ?array $current,
        callable $uuidFactory,
        callable $idFactory
    ): array {
        $uuid = is_array($current)
            ? trim((string)($current['@attributes']['uuid'] ?? ''))
            : '';
        if ($uuid === '') {
            $uuid = trim((string)$uuidFactory());
            if ($uuid === '') {
                throw new \RuntimeException('UUID factory returned empty value');
            }
        }
        $id = is_array($current) ? trim((string)($current['id'] ?? '')) : '';
        if ($id === '') {
            $id = trim((string)$idFactory());
            if ($id === '') {
                throw new \RuntimeException('HAProxy id factory returned empty value');
            }
        }
        return [$uuid, $id];
    }

    public static function reconcile(
        array $config,
        $payload,
        ?callable $uuidFactory = null,
        ?callable $idFactory = null
    ): array {
        $payload = self::validatePayload($payload);
        $uuidFactory ??= fn() => bin2hex(random_bytes(16));
        $idFactory ??= fn() => uniqid('', true);

        $inventory = self::inventory($config);
        $currentObjects = $inventory['objects'];
        $assignments = self::assignments($config);
        $policies = InterfaceSync::policies($config);

        $desired = [];
        foreach ($payload['objects'] as $row) {
            $key = self::objectKey($row['object_type'], $row['object_name']);
            $desired[$key] = $row;
            if (isset($assignments[$key]) && $assignments[$key]['policy_id'] !== $row['policy_id']) {
                self::fail(sprintf(
                    'HAProxy %s policy conflict: target %s, source %s',
                    $key,
                    $assignments[$key]['policy_id'],
                    $row['policy_id']
                ));
            }
        }

        // Symmetric HA: a synchronized policy defines the mutable scope;
        // objects are never permanently tagged as local owners or replicas.
        $managed = [];
        foreach ($assignments as $key => $assignment) {
            if ($policies[$assignment['policy_id']]['synchronize']) {
                $managed[$key] = $assignment;
            }
        }
        foreach ($desired as $key => $row) {
            if (isset($currentObjects[$key]) && !isset($managed[$key])) {
                self::fail(sprintf('HAProxy %s collides with a local-only object', $key));
            }
        }

        $next = $config;
        $healthcheckRows = [];
        foreach (self::haProxyRows($config, 'healthcheck') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $key = self::objectKey('healthcheck', $name);
            if (!isset($managed[$key])) {
                $healthcheckRows[] = $row;
            }
        }
        foreach ($desired as $key => $row) {
            if ($row['object_type'] !== 'healthcheck') {
                continue;
            }
            $current = isset($managed[$key]) ? ($currentObjects[$key]['row'] ?? null) : null;
            [$uuid, $id] = self::localIdentity($current, $uuidFactory, $idFactory);
            $healthcheckRows[] = ['@attributes' => ['uuid' => $uuid], 'id' => $id] + $row['data'];
        }
        self::setHAProxyRows($next, 'healthcheck', $healthcheckRows);

        $finalHealthcheckUuidByName = [];
        $finalHealthcheckByUuid = [];
        foreach (self::haProxyRows($next, 'healthcheck') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
            if ($uuid === '') {
                self::fail('final HAProxy healthcheck ' . $name . ' is missing its MVC UUID');
            }
            $finalHealthcheckUuidByName[$name] = $uuid;
            $finalHealthcheckByUuid[$uuid] = $name;
        }

        $serverRows = [];
        foreach (self::haProxyRows($config, 'server') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $key = self::objectKey('server', $name);
            if (!isset($managed[$key])) {
                $serverRows[] = $row;
            }
        }

        foreach ($desired as $key => $row) {
            if ($row['object_type'] !== 'server') {
                continue;
            }
            $current = isset($managed[$key]) ? ($currentObjects[$key]['row'] ?? null) : null;
            [$uuid, $id] = self::localIdentity($current, $uuidFactory, $idFactory);
            $newRow = ['@attributes' => ['uuid' => $uuid], 'id' => $id] + $row['data'];
            $serverRows[] = $newRow;
        }
        self::setHAProxyRows($next, 'server', $serverRows);

        $finalServerUuidByName = [];
        $finalServerByUuid = [];
        foreach (self::haProxyRows($next, 'server') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
            if ($uuid === '') {
                self::fail('final HAProxy server ' . $name . ' is missing its MVC UUID');
            }
            $finalServerUuidByName[$name] = $uuid;
            $finalServerByUuid[$uuid] = $name;
        }

        $backendRows = [];
        foreach (self::haProxyRows($config, 'backend') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $key = self::objectKey('backend', $name);
            if (!isset($managed[$key])) {
                $backendRows[] = $row;
            }
        }
        foreach ($desired as $key => $row) {
            if ($row['object_type'] !== 'backend') {
                continue;
            }
            $current = isset($managed[$key]) ? ($currentObjects[$key]['row'] ?? null) : null;
            [$uuid, $id] = self::localIdentity($current, $uuidFactory, $idFactory);
            $linked = [];
            foreach ($row['linked_server_names'] as $serverName) {
                if (!isset($finalServerUuidByName[$serverName])) {
                    self::fail(sprintf(
                        'HAProxy backend %s cannot resolve local server %s',
                        $row['object_name'],
                        $serverName
                    ));
                }
                $linked[] = $finalServerUuidByName[$serverName];
            }
            $newRow = ['@attributes' => ['uuid' => $uuid], 'id' => $id] + $row['data'];
            $newRow['linkedServers'] = implode(',', $linked);
            if ($row['linked_healthcheck_name'] !== '') {
                if (!isset($finalHealthcheckUuidByName[$row['linked_healthcheck_name']])) {
                    self::fail(sprintf(
                        'HAProxy backend %s cannot resolve local healthcheck %s',
                        $row['object_name'],
                        $row['linked_healthcheck_name']
                    ));
                }
                $newRow['healthCheck'] = $finalHealthcheckUuidByName[$row['linked_healthcheck_name']];
            } else {
                $newRow['healthCheck'] = '';
            }
            $backendRows[] = $newRow;
        }

        foreach ($backendRows as $row) {
            foreach (self::relationValues($row['linkedServers'] ?? null) as $serverUuid) {
                if (!isset($finalServerByUuid[$serverUuid])) {
                    self::fail(sprintf(
                        'final HAProxy backend %s references server UUID %s that would be removed',
                        (string)($row['name'] ?? ''),
                        $serverUuid
                    ));
                }
            }
            foreach (self::relationValues($row['healthCheck'] ?? null) as $healthcheckUuid) {
                if (!isset($finalHealthcheckByUuid[$healthcheckUuid])) {
                    self::fail(sprintf(
                        'final HAProxy backend %s references healthcheck UUID %s that would be removed',
                        (string)($row['name'] ?? ''),
                        $healthcheckUuid
                    ));
                }
            }
        }
        self::setHAProxyRows($next, 'backend', $backendRows);

        $finalBackendUuidByName = [];
        $finalBackendByUuid = [];
        foreach (self::haProxyRows($next, 'backend') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
            if ($uuid === '') {
                self::fail('final HAProxy backend ' . $name . ' is missing its MVC UUID');
            }
            $finalBackendUuidByName[$name] = $uuid;
            $finalBackendByUuid[$uuid] = $name;
        }

        $certificateIndex = self::certificateIndexes($next);
        $frontendRows = [];
        foreach (self::haProxyRows($config, 'frontend') as $row) {
            $name = self::objectName($row['name'] ?? '');
            $key = self::objectKey('frontend', $name);
            if (!isset($managed[$key])) {
                $frontendRows[] = $row;
            }
        }
        foreach ($desired as $key => $row) {
            if ($row['object_type'] !== 'frontend') {
                continue;
            }
            $current = isset($managed[$key]) ? ($currentObjects[$key]['row'] ?? null) : null;
            [$uuid, $id] = self::localIdentity($current, $uuidFactory, $idFactory);
            $data = $row['data'];

            $backendName = trim((string)($data['sync_default_backend_name'] ?? ''));
            $defaultBackendUuid = '';
            if ($backendName !== '') {
                if (!isset($finalBackendUuidByName[$backendName])) {
                    self::fail(sprintf(
                        'HAProxy frontend %s cannot resolve local backend %s',
                        $row['object_name'],
                        $backendName
                    ));
                }
                $defaultBackendUuid = $finalBackendUuidByName[$backendName];
            } elseif (!self::isDynamicFrontend($data)) {
                self::fail('HAProxy frontend without a default backend must use a supported fail-closed dynamic dispatch');
            }

            $certificateRefs = [];
            foreach (self::decodeCertificateDescriptions(
                (string)($data['sync_ssl_certificate_descriptions'] ?? '')
            ) as $description) {
                $certificateRefs[] = self::certificateRef($certificateIndex, $description);
            }
            $defaultCertificateDescription = trim(
                (string)($data['sync_ssl_default_certificate_description'] ?? '')
            );
            $defaultCertificateRef = $defaultCertificateDescription === ''
                ? ''
                : self::certificateRef($certificateIndex, $defaultCertificateDescription);

            unset(
                $data['sync_default_backend_name'],
                $data['sync_ssl_certificate_descriptions'],
                $data['sync_ssl_default_certificate_description']
            );
            $data['defaultBackend'] = $defaultBackendUuid;
            $data['ssl_certificates'] = implode(',', $certificateRefs);
            $data['ssl_default_certificate'] = $defaultCertificateRef;
            $frontendRows[] = ['@attributes' => ['uuid' => $uuid], 'id' => $id] + $data;
        }

        foreach ($frontendRows as $row) {
            foreach (self::relationValues($row['defaultBackend'] ?? null) as $backendUuid) {
                if (!isset($finalBackendByUuid[$backendUuid])) {
                    self::fail(sprintf(
                        'final HAProxy frontend %s references backend UUID %s that would be removed',
                        (string)($row['name'] ?? ''),
                        $backendUuid
                    ));
                }
            }
        }
        self::setHAProxyRows($next, 'frontend', $frontendRows);

        // Preserve local-only assignments; prune no-longer-selected synchronized
        // objects. The remaining assignments and policy references are the same
        // on source and receiver, so the next peer can immediately send back.
        $assignmentRows = [];
        foreach (self::assignmentRowsRaw($config) as $row) {
            $key = self::objectKey(
                self::objectType($row['object_type'] ?? ''),
                self::objectName($row['object_name'] ?? '')
            );
            if (!isset($managed[$key])) {
                $assignmentRows[] = $row;
            }
        }
        self::setAssignmentRows($next, $assignmentRows);

        $policyPlan = InterfaceSync::reconcilePolicies(
            $next,
            ['policies' => $payload['policies'], 'prune' => true],
            $uuidFactory
        );
        $finalPolicies = InterfaceSync::policies($next);
        foreach ($desired as $key => $row) {
            $policy = $finalPolicies[$row['policy_id']] ?? null;
            if ($policy === null || !$policy['synchronize']) {
                self::fail('incoming HAProxy object has unknown or disabled policy ' . $row['policy_id']);
            }
            $attributes = $assignments[$key]['@attributes'] ?? [];
            if (empty($attributes['uuid'])) {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
                $attributes = ['uuid' => $uuid];
            }
            $assignmentRows[] = [
                '@attributes' => $attributes,
                'object_type' => $row['object_type'],
                'object_name' => $row['object_name'],
                'policy_id' => $policy['uuid'],
            ];
        }
        self::setAssignmentRows($next, $assignmentRows);

        return [
            'config' => $next,
            'changed' => $next !== $config,
            'count' => count($desired),
            'plan' => [
                'policies' => $policyPlan,
            ],
        ];
    }
}

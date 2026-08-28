<?php
namespace OPNsense\ApiExtensions;

require_once __DIR__ . '/InterfaceSync.php';

final class HAProxySync
{
    public const VERSION = 1;
    public const HA_SYNC_ITEM = 'haproxy_objects';

    private const OBJECT_TYPES = ['server', 'backend'];
    private const OBJECT_NAME = '/^[0-9A-Za-z._-]{1,255}$/D';
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
        'healthCheck',
        'linkedMailer',
        'basicAuthUsers',
        'basicAuthGroups',
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
            self::fail('HAProxy sync object_type must be server or backend');
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

    public static function replicas(array $config): array
    {
        $root = self::policyRoot($config);
        $out = [];
        foreach (self::containerRows(
            $root['haproxy_replicas'] ?? [],
            'replica',
            'HAProxy sync replicas container'
        ) as $row) {
            if (!is_array($row)) {
                self::fail('invalid HAProxy replica ownership record');
            }
            $type = self::objectType($row['object_type'] ?? '');
            $name = self::objectName($row['object_name'] ?? '');
            $policyId = trim((string)($row['policy_id'] ?? ''));
            if (!preg_match('/^[a-z][a-z0-9_-]{0,31}$/D', $policyId)) {
                self::fail('invalid HAProxy replica policy id');
            }
            $key = self::objectKey($type, $name);
            if (isset($out[$key])) {
                self::fail('duplicate HAProxy replica ownership record ' . $key);
            }
            $out[$key] = [
                'object_type' => $type,
                'object_name' => $name,
                'policy_id' => $policyId,
                '@attributes' => is_array($row['@attributes'] ?? null) ? $row['@attributes'] : [],
            ];
        }
        return $out;
    }

    private static function haProxyRows(array $config, string $type): array
    {
        $root = self::haproxyRoot($config);
        $section = $type === 'server' ? 'servers' : 'backends';
        return self::containerRows($root[$section] ?? [], $type, 'OPNsense.HAProxy.' . $section);
    }

    public static function inventory(array $config): array
    {
        $objects = [];
        $serverUuidToName = [];
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
                if ($type === 'server') {
                    if ($uuid === '') {
                        self::fail('HAProxy server ' . $name . ' is missing its MVC UUID');
                    }
                    if (isset($serverUuidToName[$uuid])) {
                        self::fail('duplicate HAProxy server MVC UUID');
                    }
                    $serverUuidToName[$uuid] = $name;
                }
            }
        }
        ksort($objects);
        return ['objects' => $objects, 'server_uuid_to_name' => $serverUuidToName];
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

    private static function payloadData(array $row, string $type, array $serverUuidToName): array
    {
        $unsupported = $type === 'server'
            ? self::SERVER_UNSUPPORTED_REFERENCES
            : self::BACKEND_UNSUPPORTED_REFERENCES;
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
            unset($data['linkedServers']);
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
        return [$data, $linkedServerNames];
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

        foreach ($objects as $key => $object) {
            if (!isset($assignments[$key])) {
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
                [$data, $linkedServerNames] = self::payloadData(
                    $object['row'],
                    $type,
                    $inventory['server_uuid_to_name']
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
                }
                $payloadObjects[] = [
                    'object_type' => $type,
                    'object_name' => $object['object_name'],
                    'policy_id' => $assignments[$key]['policy_id'],
                    'data' => $data,
                    'linked_server_names' => $linkedServerNames,
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

        return [
            'version' => self::VERSION,
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
        if ($payload['version'] !== self::VERSION ||
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
                array_diff(array_keys($row), ['object_type', 'object_name', 'policy_id', 'data', 'linked_server_names']) ||
                count($row) !== 5 ||
                !is_array($row['data']) ||
                !is_array($row['linked_server_names'])) {
                self::fail('invalid HAProxy sync object record');
            }
            $type = self::objectType($row['object_type']);
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
                    in_array($field, ['@attributes', 'id', 'linkedServers'], true) ||
                    (!is_scalar($value) && $value !== null)) {
                    self::fail('invalid HAProxy sync object data');
                }
                $data[$field] = $value === null ? '' : (string)$value;
            }
            if (($data['name'] ?? '') !== $name) {
                self::fail(sprintf('HAProxy %s payload name mismatch for %s', $type, $name));
            }

            $linkedServerNames = [];
            foreach (array_values($row['linked_server_names']) as $serverName) {
                $linkedServerNames[] = self::objectName($serverName);
            }
            if ($type === 'server' && $linkedServerNames !== []) {
                self::fail('HAProxy server records cannot contain linked_server_names');
            }
            $objects[] = [
                'object_type' => $type,
                'object_name' => $name,
                'policy_id' => $policyId,
                'data' => $data,
                'linked_server_names' => array_values(array_unique($linkedServerNames)),
            ];
        }

        $selected = array_fill_keys(array_map(
            fn($row) => self::objectKey($row['object_type'], $row['object_name']),
            $objects
        ), true);
        foreach ($objects as $row) {
            if ($row['object_type'] !== 'backend') {
                continue;
            }
            foreach ($row['linked_server_names'] as $serverName) {
                if (!isset($selected[self::objectKey('server', $serverName)])) {
                    self::fail(sprintf(
                        'HAProxy backend %s links server %s missing from payload',
                        $row['object_name'],
                        $serverName
                    ));
                }
            }
        }

        usort($objects, function ($a, $b) {
            $typeOrder = ['server' => 0, 'backend' => 1];
            return [$typeOrder[$a['object_type']], $a['object_name']] <=> [$typeOrder[$b['object_type']], $b['object_name']];
        });
        return [
            'version' => self::VERSION,
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

    private static function setReplicaRows(array &$config, array $rows): void
    {
        $root =& self::policyRootForWrite($config);
        $root['haproxy_replicas'] = self::serializeRows('replica', $rows);
    }

    private static function setHAProxyRows(array &$config, string $type, array $rows): void
    {
        $root =& self::haproxyRootForWrite($config);
        $section = $type === 'server' ? 'servers' : 'backends';
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
        $localAssignments = self::assignments($config);
        $replicas = self::replicas($config);

        $desired = [];
        foreach ($payload['objects'] as $row) {
            $desired[self::objectKey($row['object_type'], $row['object_name'])] = $row;
        }

        $adoptedLocal = [];
        foreach ($desired as $key => $row) {
            if (isset($replicas[$key])) {
                continue;
            }
            if (isset($localAssignments[$key])) {
                if ($localAssignments[$key]['policy_id'] !== $row['policy_id']) {
                    self::fail(sprintf(
                        'cannot adopt HAProxy %s %s: local policy %s differs from peer policy %s',
                        $row['object_type'],
                        $row['object_name'],
                        $localAssignments[$key]['policy_id'],
                        $row['policy_id']
                    ));
                }
                $adoptedLocal[$key] = $localAssignments[$key];
            }
        }

        $managed = $replicas + $adoptedLocal;
        foreach ($desired as $key => $row) {
            if (isset($currentObjects[$key]) && !isset($managed[$key])) {
                self::fail(sprintf(
                    'policy-managed HAProxy %s %s is already owned locally',
                    $row['object_type'],
                    $row['object_name']
                ));
            }
        }

        $next = $config;
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
        }
        self::setHAProxyRows($next, 'backend', $backendRows);

        if ($adoptedLocal !== []) {
            $remainingAssignments = [];
            foreach (self::assignmentRowsRaw($next) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $key = self::objectKey(
                    self::objectType($row['object_type'] ?? ''),
                    self::objectName($row['object_name'] ?? '')
                );
                if (!isset($adoptedLocal[$key])) {
                    $remainingAssignments[] = $row;
                }
            }
            self::setAssignmentRows($next, $remainingAssignments);
        }

        $replicaRows = [];
        foreach ($desired as $key => $row) {
            $attributes = $replicas[$key]['@attributes'] ?? [];
            if (empty($attributes['uuid'])) {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
                $attributes = ['uuid' => $uuid];
            }
            $replicaRows[] = [
                '@attributes' => $attributes,
                'object_type' => $row['object_type'],
                'object_name' => $row['object_name'],
                'policy_id' => $row['policy_id'],
            ];
        }
        self::setReplicaRows($next, $replicaRows);

        $policyPlan = InterfaceSync::reconcilePolicies(
            $next,
            ['policies' => $payload['policies'], 'prune' => true],
            $uuidFactory
        );

        return [
            'config' => $next,
            'changed' => $next !== $config,
            'count' => count($desired),
            'plan' => [
                'adopted_local_assignments' => array_keys($adoptedLocal),
                'policies' => $policyPlan,
            ],
        ];
    }
}

<?php
namespace OPNsense\ApiExtensions;

require_once __DIR__ . '/InterfaceSync.php';
require_once __DIR__ . '/HAProxySync.php';

final class ReplacementHandoff
{
    public const VERSION = 1;
    public const NATIVE_ITEMS = ['virtualip', 'rules', 'staticroutes', 'aliases', 'users'];
    public const REQUIRED_ITEMS = [
        'virtualip',
        'rules',
        'staticroutes',
        'aliases',
        'users',
        'interface_vlans',
        'haproxy_objects',
    ];

    private const NATIVE_REFERENCES = [
        'rules' => ['filter', 'OPNsense.Firewall.Filter.rules'],
        'staticroutes' => ['staticroutes', 'gateways', 'OPNsense.Gateways'],
        'aliases' => ['aliases', 'OPNsense.Firewall.Alias'],
        'users' => ['system.user', 'system.group'],
    ];

    private static function fail(string $message): void
    {
        throw new \InvalidArgumentException($message);
    }

    private static function items(array $config): array
    {
        $raw = trim((string)($config['hasync']['syncitems'] ?? ''));
        return $raw === '' ? [] : array_values(array_unique(
            array_filter(preg_split('/[\s,]+/', $raw) ?: [])
        ));
    }

    private static function requireItems(array $config): void
    {
        $missing = array_values(array_diff(self::REQUIRED_ITEMS, self::items($config)));
        if ($missing !== []) {
            self::fail('replacement handoff requires the complete HA set: ' . implode(', ', $missing));
        }
    }

    public static function assertReplicaSource(array $config): void
    {
        self::requireItems($config);
        $target = trim((string)($config['hasync']['synchronizetoip'] ?? ''));
        if ($target !== '') {
            self::fail('replacement handoff source must be the replica with no configuration sync target');
        }
    }

    public static function assertPrimaryTarget(array $config): void
    {
        self::requireItems($config);
        $target = trim((string)($config['hasync']['synchronizetoip'] ?? ''));
        if ($target === '') {
            self::fail('replacement handoff target must be the primary with the normal configuration sync target');
        }
    }

    private static function copyPath(array $source, array &$target, string $reference): void
    {
        $path = explode('.', $reference);
        $src = $source;
        $dst =& $target;
        foreach ($path as $index => $section) {
            $isLast = $index === count($path) - 1;
            if (array_key_exists($section, $src)) {
                if ($isLast) {
                    $dst[$section] = $src[$section];
                    return;
                }
                if (!is_array($src[$section])) {
                    self::fail('invalid native handoff config path ' . $reference);
                }
                $src = $src[$section];
            } else {
                $src = [];
            }
            if (!isset($dst[$section]) || !is_array($dst[$section])) {
                $dst[$section] = [];
            }
            $dst =& $dst[$section];
        }
    }

    private static function removeNoSync(array &$value): void
    {
        foreach ($value as $key => &$row) {
            if (is_array($row) && !empty($row['nosync'])) {
                unset($value[$key]);
                continue;
            }
            if (is_array($row)) {
                self::removeNoSync($row);
            }
        }
        unset($row);
    }

    private static function virtualIpSection(array $config): array
    {
        $vips = $config['virtualip']['vip'] ?? [];
        if (!is_array($vips)) {
            self::fail('invalid virtualip section during replacement handoff');
        }
        $out = [];
        foreach ($vips as $row) {
            if (!is_array($row) || empty($row['vhid']) || !empty($row['nosync'])) {
                continue;
            }
            $out[] = $row;
        }
        return ['vip' => $out];
    }

    private static function normalizeExcludedUuids(array $uuids): array
    {
        $out = [];
        foreach ($uuids as $uuid) {
            $uuid = trim((string)$uuid);
            if ($uuid === '') {
                continue;
            }
            if (!preg_match('/^[0-9A-Fa-f-]{16,64}$/D', $uuid)) {
                self::fail('invalid Router-owned UUID exclusion in replacement handoff');
            }
            $out[$uuid] = true;
        }
        ksort($out);
        return array_keys($out);
    }

    private static function removeExcludedUuids(array &$value, array $excluded): void
    {
        if ($excluded === []) {
            return;
        }
        $set = array_fill_keys($excluded, true);
        foreach ($value as $key => &$row) {
            if (is_array($row)) {
                $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
                if ($uuid !== '' && isset($set[$uuid])) {
                    unset($value[$key]);
                    continue;
                }
                self::removeExcludedUuids($row, $excluded);
            }
        }
        unset($row);
    }

    private static function buildNative(array $config, array $excludedUuids): array
    {
        $out = [];
        $out['virtualip'] = self::virtualIpSection($config);
        foreach (self::NATIVE_REFERENCES as $references) {
            foreach ($references as $reference) {
                self::copyPath($config, $out, $reference);
            }
        }
        self::removeNoSync($out);
        self::removeExcludedUuids($out, $excludedUuids);
        return $out;
    }

    public static function buildReplicaBundle(
        array $config,
        string $policyId,
        array $excludedUuids = []
    ): array {

        self::assertReplicaSource($config);
        $policyId = trim($policyId);
        if ($policyId === '') {
            self::fail('replacement handoff policy id is required');
        }
        $excludedUuids = self::normalizeExcludedUuids($excludedUuids);
        return [
            'version' => self::VERSION,
            'policy_id' => $policyId,
            'native_items' => self::NATIVE_ITEMS,
            'excluded_uuids' => $excludedUuids,
            'native' => self::buildNative($config, $excludedUuids),
            'interfaces' => InterfaceSync::buildReplicaPayload($config, $policyId, true),
            'haproxy' => HAProxySync::buildReplicaPayload($config, $policyId),
        ];
    }

    private static function validateBundle($bundle, string $policyId): array
    {
        if (!is_array($bundle) ||
            array_diff(array_keys($bundle), ['version', 'policy_id', 'native_items', 'excluded_uuids', 'native', 'interfaces', 'haproxy']) ||
            count($bundle) !== 7) {
            self::fail('invalid replacement handoff bundle');
        }
        if ($bundle['version'] !== self::VERSION) {
            self::fail('unsupported replacement handoff bundle version');
        }
        if (trim((string)$bundle['policy_id']) !== $policyId) {
            self::fail('replacement handoff bundle policy mismatch');
        }
        $nativeItems = $bundle['native_items'];
        if (!is_array($nativeItems) || array_values($nativeItems) !== self::NATIVE_ITEMS) {
            self::fail('replacement handoff native allowlist mismatch');
        }
        if (!is_array($bundle['excluded_uuids'])) {
            self::fail('invalid replacement handoff Router-owned UUID exclusion list');
        }
        $bundle['excluded_uuids'] = self::normalizeExcludedUuids($bundle['excluded_uuids']);
        if (!is_array($bundle['native'])) {
            self::fail('invalid replacement handoff native payload');
        }
        $bundle['interfaces'] = InterfaceSync::validatePayload($bundle['interfaces']);
        $bundle['haproxy'] = HAProxySync::validatePayload($bundle['haproxy']);
        return $bundle;
    }

    private static function validateIdentity(
        $identity,
        string $policyId,
        array $interfacePayload,
        array $haproxyPayload
    ): array {
        if (!is_array($identity) ||
            array_diff(array_keys($identity), ['version', 'policy_id', 'interfaces', 'haproxy', 'carp_advskew']) ||
            count($identity) !== 5) {
            self::fail('invalid replacement identity manifest');
        }
        if ($identity['version'] !== self::VERSION) {
            self::fail('unsupported replacement identity manifest version');
        }
        if (trim((string)$identity['policy_id']) !== $policyId) {
            self::fail('replacement identity manifest policy mismatch');
        }
        foreach (['interfaces', 'haproxy', 'carp_advskew'] as $field) {
            if (!is_array($identity[$field])) {
                self::fail('replacement identity manifest field must be an object: ' . $field);
            }
        }

        $interfaceKeys = array_map(fn($row) => $row['identifier'], $interfacePayload['interfaces']);
        $haproxyKeys = array_map(
            fn($row) => $row['object_type'] . ':' . $row['object_name'],
            $haproxyPayload['objects']
        );
        if (array_diff($interfaceKeys, array_keys($identity['interfaces'])) ||
            array_diff(array_keys($identity['interfaces']), $interfaceKeys)) {
            self::fail('replacement identity interface set does not match Rigi replica payload');
        }
        if (array_diff($haproxyKeys, array_keys($identity['haproxy'])) ||
            array_diff(array_keys($identity['haproxy']), $haproxyKeys)) {
            self::fail('replacement identity HAProxy set does not match Rigi replica payload');
        }
        foreach ($identity['carp_advskew'] as $uuid => $skew) {
            if (!is_string($uuid) || $uuid === '' || !is_numeric($skew)) {
                self::fail('invalid replacement CARP identity record');
            }
            $value = (int)$skew;
            if ($value < 0 || $value > 254) {
                self::fail('replacement CARP advskew must be in range 0..254');
            }
        }
        return $identity;
    }

    private static function restoreCarpSkew(array &$native, array $advSkewByUuid): void
    {
        $vips = $native['virtualip']['vip'] ?? [];
        if (!is_array($vips)) {
            self::fail('invalid replacement virtualip payload');
        }
        $seen = [];
        foreach ($vips as &$row) {
            if (!is_array($row) || trim((string)($row['mode'] ?? '')) !== 'carp') {
                continue;
            }
            $uuid = trim((string)($row['@attributes']['uuid'] ?? ''));
            if ($uuid === '' || !array_key_exists($uuid, $advSkewByUuid)) {
                self::fail('replacement CARP identity manifest is missing VIP UUID ' . $uuid);
            }
            $row['advskew'] = (string)((int)$advSkewByUuid[$uuid]);
            $seen[$uuid] = true;
        }
        unset($row);
        if (array_diff(array_keys($advSkewByUuid), array_keys($seen))) {
            self::fail('replacement CARP identity manifest references VIPs not present on Rigi');
        }
        $native['virtualip']['vip'] = array_values($vips);
    }

    private const ADDITIVE_RECORD_PATHS = [
        'virtualip.vip',
        'filter.rule',
        'OPNsense.Firewall.Filter.rules.rule',
        'staticroutes.route',
        'gateways.gateway_item',
        'OPNsense.Gateways.gateway_item',
        'aliases.alias',
        'OPNsense.Firewall.Alias.aliases.alias',
    ];

    private static function pathValue(array $config, string $path)
    {
        $value = $config;
        foreach (explode('.', $path) as $section) {
            if (!is_array($value) || !array_key_exists($section, $value)) {
                return null;
            }
            $value = $value[$section];
        }
        return $value;
    }

    private static function setPathValue(array &$config, string $path, $value): void
    {
        $sections = explode('.', $path);
        $cursor = &$config;
        foreach ($sections as $index => $section) {
            if ($index === count($sections) - 1) {
                $cursor[$section] = $value;
                return;
            }
            if (!isset($cursor[$section]) || !is_array($cursor[$section])) {
                $cursor[$section] = [];
            }
            $cursor = &$cursor[$section];
        }
    }

    private static function records($value, string $path): array
    {
        if ($value === null || $value === '' || $value === []) {
            return [];
        }
        if (!is_array($value)) {
            self::fail('replacement native record container must be an array: ' . $path);
        }
        if (array_is_list($value)) {
            foreach ($value as $record) {
                if (!is_array($record)) {
                    self::fail('replacement native record must be an object: ' . $path);
                }
            }
            return array_values($value);
        }
        return [$value];
    }

    private static function recordIdentity(string $path, array $record): string
    {
        $uuid = trim((string)($record['@attributes']['uuid'] ?? ''));
        if ($uuid !== '') {
            return 'uuid:' . strtolower($uuid);
        }
        return match ($path) {
            'virtualip.vip' => 'vip:' . implode('|', [
                trim((string)($record['mode'] ?? '')),
                trim((string)($record['interface'] ?? '')),
                trim((string)($record['vhid'] ?? '')),
                trim((string)($record['subnet'] ?? '')),
                trim((string)($record['subnet_bits'] ?? '')),
            ]),
            'staticroutes.route' => 'route:' . implode('|', [
                trim((string)($record['network'] ?? '')),
                trim((string)($record['gateway'] ?? '')),
            ]),
            'gateways.gateway_item', 'OPNsense.Gateways.gateway_item' =>
                'gateway:' . trim((string)($record['name'] ?? '')),
            'aliases.alias', 'OPNsense.Firewall.Alias.aliases.alias' =>
                'alias:' . trim((string)($record['name'] ?? '')),
            default => self::fail('replacement native record is missing UUID: ' . $path),
        };
    }

    private static function appendRecordPath(array &$target, array $source, string $path): int
    {
        $incoming = self::records(self::pathValue($source, $path), $path);
        if ($incoming === []) {
            return 0;
        }
        $current = self::records(self::pathValue($target, $path), $path);
        $identities = [];
        foreach ($current as $record) {
            $identity = self::recordIdentity($path, $record);
            if (isset($identities[$identity])) {
                self::fail('duplicate native target identity before replacement handoff: ' . $identity);
            }
            $identities[$identity] = true;
        }
        foreach ($incoming as $record) {
            $identity = self::recordIdentity($path, $record);
            if (isset($identities[$identity])) {
                self::fail('replacement native handoff is not create-only; target already contains ' . $identity);
            }
            $identities[$identity] = true;
            $current[] = $record;
        }
        self::setPathValue($target, $path, array_values($current));
        return count($incoming);
    }

    private static function mergeNativeRecovery(array $source, array $target): array
    {
        foreach (self::ADDITIVE_RECORD_PATHS as $path) {
            self::appendRecordPath($target, $source, $path);
        }

        // Users and groups are intentionally authoritative during ownership handoff.
        // The accepted Rigi contains the shared sysops/API/SSH identity that normal
        // users synchronization copied from old Etna. Fresh Bootstrap-only credentials
        // must not survive as a second independent control-plane identity.
        foreach (['system.user', 'system.group'] as $path) {
            $value = self::pathValue($source, $path);
            if ($value === null) {
                self::fail('replacement handoff source is missing shared authentication section ' . $path);
            }
            self::setPathValue($target, $path, $value);
        }
        return $target;
    }

    public static function reconcileAsPrimaryOwner(
        array $config,
        $bundle,
        $identity,
        string $policyId,
        ?callable $uuidFactory = null,
        ?callable $idFactory = null
    ): array {
        self::assertPrimaryTarget($config);
        $policyId = trim($policyId);
        $bundle = self::validateBundle($bundle, $policyId);
        $identity = self::validateIdentity(
            $identity,
            $policyId,
            $bundle['interfaces'],
            $bundle['haproxy']
        );

        $interface = InterfaceSync::reconcileAsOwner(
            $config,
            $bundle['interfaces'],
            $identity['interfaces'],
            $uuidFactory
        );
        $haproxy = HAProxySync::reconcileAsOwner(
            $interface['config'],
            $bundle['haproxy'],
            $identity['haproxy'],
            $uuidFactory,
            $idFactory
        );

        $native = $bundle['native'];
        self::restoreCarpSkew($native, $identity['carp_advskew']);
        $next = self::mergeNativeRecovery($native, $haproxy['config']);

        return [
            'config' => $next,
            'changed' => $next !== $config,
            'counts' => [
                'interfaces' => $interface['count'],
                'haproxy' => $haproxy['count'],
            ],
            'interface_plan' => $interface['plan'],
            'haproxy_plan' => $haproxy['plan'],
        ];
    }
}

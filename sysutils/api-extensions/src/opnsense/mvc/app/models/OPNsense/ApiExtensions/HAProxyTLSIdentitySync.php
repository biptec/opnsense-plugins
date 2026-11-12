<?php

namespace OPNsense\ApiExtensions;

require_once __DIR__ . '/InterfaceSync.php';

/**
 * Pure synchronization helper for non-secret HAProxy TLS identity metadata.
 *
 * An identity owns only the additive relation:
 *   existing local frontend name + consumer DNS name + HA policy
 *
 * Certificate/key material is never serialized here. The Router-local
 * materializer derives certificate principal, paths, Trust description/refid,
 * and frontend membership from this metadata.
 */
final class HAProxyTLSIdentitySync
{
    private const OBJECT_NAME = '/^[0-9A-Za-z._-]{1,255}$/D';
    private const HOST_NAME = '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D';

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
                    $out[] = $entry;
                }
            }
            return $out;
        }
        if (array_key_exists($item, $container)) {
            return self::rows($container[$item], $label . '.' . $item);
        }
        return [$container];
    }

    private static function serializeRowsLike($current, string $item, array $rows)
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return ($current === '' || $current === null || $current === []) ? $current : '';
        }
        if (is_array($current) && array_is_list($current)) {
            if ($current === []) {
                return [$item => count($rows) === 1 ? $rows[0] : $rows];
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
            return [$item => count($rows) === 1 ? $rows[0] : $rows];
        }
        if (is_array($current) && !array_is_list($current) && !array_key_exists($item, $current)) {
            return count($rows) === 1 ? $rows[0] : $rows;
        }
        return [$item => count($rows) === 1 ? $rows[0] : $rows];
    }

    private static function root(array $config): array
    {
        $root = $config['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'] ?? [];
        if ($root === null || $root === '') {
            return [];
        }
        if (!is_array($root)) {
            self::fail('HAProxy TLS identity configuration must be an object');
        }
        return $root;
    }

    private static function &rootForWrite(array &$config): array
    {
        if (!isset($config['OPNsense']) || !is_array($config['OPNsense'])) {
            $config['OPNsense'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']) || !is_array($config['OPNsense']['ApiExtensions'])) {
            $config['OPNsense']['ApiExtensions'] = [];
        }
        if (!isset($config['OPNsense']['ApiExtensions']['HAProxyTLSIdentity']) ||
            !is_array($config['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'])) {
            $config['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'] = [];
        }
        return $config['OPNsense']['ApiExtensions']['HAProxyTLSIdentity'];
    }

    private static function objectName($value): string
    {
        $value = trim((string)$value);
        if (!preg_match(self::OBJECT_NAME, $value)) {
            self::fail('invalid HAProxy TLS identity frontend name');
        }
        return $value;
    }

    private static function hostName($value): string
    {
        $value = strtolower(rtrim(trim((string)$value), '.'));
        if (!preg_match(self::HOST_NAME, $value)) {
            self::fail('invalid HAProxy TLS identity DNS name');
        }
        return $value;
    }

    private static function policyByReference(array $policies, $reference): array
    {
        $reference = trim((string)$reference);
        if ($reference === '') {
            self::fail('HAProxy TLS identity policy relation is empty');
        }
        if (isset($policies[$reference])) {
            return $policies[$reference];
        }
        foreach ($policies as $policy) {
            if (($policy['uuid'] ?? '') === $reference) {
                return $policy;
            }
        }
        self::fail('HAProxy TLS identity references unknown HA policy ' . $reference);
    }

    private static function identityKey(array $identity): string
    {
        return $identity['frontend_name'] . '|' . $identity['dns_name'];
    }

    private static function frontendInventory(array $config): array
    {
        $container = $config['OPNsense']['HAProxy']['frontends'] ?? [];
        $out = [];
        foreach (self::containerRows($container, 'frontend', 'HAProxy frontends') as $row) {
            if (!is_array($row)) {
                self::fail('invalid HAProxy frontend record');
            }
            $name = self::objectName($row['name'] ?? '');
            if (isset($out[$name])) {
                self::fail('duplicate HAProxy frontend name ' . $name);
            }
            $out[$name] = $row;
        }
        return $out;
    }

    private static function requireTLSFrontend(array $frontends, string $name): void
    {
        if (!isset($frontends[$name])) {
            self::fail('HAProxy TLS identity references missing local frontend ' . $name);
        }
        if (!self::flag($frontends[$name]['ssl_enabled'] ?? null)) {
            self::fail('HAProxy TLS identity references a frontend that does not terminate TLS: ' . $name);
        }
    }

    public static function isAuthoritative(array $config): bool
    {
        return self::flag(self::root($config)['sync_marker']['enabled'] ?? null);
    }

    public static function certificateDescription($dnsName): string
    {
        return 'HAProxy TLS ' . self::hostName($dnsName);
    }

    public static function validateLocalRegistration(
        array $config,
        $frontendName,
        $dnsName,
        $policyReference
    ): array {
        $policies = InterfaceSync::policies($config);
        $frontends = self::frontendInventory($config);
        $frontendName = self::objectName($frontendName);
        $dnsName = self::hostName($dnsName);
        self::requireTLSFrontend($frontends, $frontendName);
        $policy = self::policyByReference($policies, $policyReference);

        return [
            'frontend_name' => $frontendName,
            'dns_name' => $dnsName,
            'policy_id' => $policy['id'],
            'policy_uuid' => $policy['uuid'],
            'synchronize' => $policy['synchronize'],
        ];
    }

    public static function identities(array $config): array
    {
        $root = self::root($config);
        $policies = InterfaceSync::policies($config);
        $frontends = self::frontendInventory($config);
        $out = [];
        foreach (self::containerRows($root['identities'] ?? [], 'identity', 'HAProxy TLS identities') as $row) {
            if (!is_array($row)) {
                self::fail('invalid HAProxy TLS identity record');
            }
            $frontendName = self::objectName($row['frontend_name'] ?? '');
            $dnsName = self::hostName($row['dns_name'] ?? '');
            self::requireTLSFrontend($frontends, $frontendName);
            $policy = self::policyByReference($policies, $row['policy_id'] ?? '');
            $identity = [
                'frontend_name' => $frontendName,
                'dns_name' => $dnsName,
                'policy_id' => $policy['id'],
                'policy_uuid' => $policy['uuid'],
                '@attributes' => is_array($row['@attributes'] ?? null) ? $row['@attributes'] : [],
            ];
            $key = self::identityKey($identity);
            if (isset($out[$key])) {
                self::fail('duplicate HAProxy TLS identity ' . $key);
            }
            $out[$key] = $identity;
        }
        ksort($out);
        return $out;
    }

    public static function buildPayload(array $config): array
    {
        $policies = InterfaceSync::policies($config);
        $out = [];
        foreach (self::identities($config) as $identity) {
            $policy = $policies[$identity['policy_id']] ?? null;
            if ($policy === null || !$policy['synchronize']) {
                continue;
            }
            $out[] = [
                'frontend_name' => $identity['frontend_name'],
                'dns_name' => $identity['dns_name'],
                'policy_id' => $identity['policy_id'],
            ];
        }
        usort($out, fn($a, $b) => self::identityKey($a) <=> self::identityKey($b));
        return $out;
    }

    public static function validatePayload($payload, array $policies): array
    {
        if (!is_array($payload) || !array_is_list($payload)) {
            self::fail('HAProxy TLS identity payload must be a list');
        }
        $out = [];
        foreach ($payload as $row) {
            if (!is_array($row) ||
                array_diff(array_keys($row), ['frontend_name', 'dns_name', 'policy_id']) ||
                count($row) !== 3) {
                self::fail('invalid HAProxy TLS identity payload record');
            }
            $frontendName = self::objectName($row['frontend_name']);
            $dnsName = self::hostName($row['dns_name']);
            $policy = self::policyByReference($policies, $row['policy_id']);
            if (!$policy['synchronize']) {
                self::fail('HAProxy TLS identity payload references a local-only HA policy');
            }
            $identity = [
                'frontend_name' => $frontendName,
                'dns_name' => $dnsName,
                'policy_id' => $policy['id'],
            ];
            $key = self::identityKey($identity);
            if (isset($out[$key])) {
                self::fail('duplicate HAProxy TLS identity payload ' . $key);
            }
            $out[$key] = $identity;
        }
        ksort($out);
        return array_values($out);
    }

    public static function reconcile(
        array $config,
        array $desired,
        ?callable $uuidFactory = null
    ): array {
        $uuidFactory ??= fn() => bin2hex(random_bytes(16));
        $policies = InterfaceSync::policies($config);
        $frontends = self::frontendInventory($config);
        $validated = self::validatePayload($desired, $policies);
        foreach ($validated as $identity) {
            self::requireTLSFrontend($frontends, $identity['frontend_name']);
        }
        $current = self::identities($config);

        $desiredByKey = [];
        foreach ($validated as $identity) {
            $desiredByKey[self::identityKey($identity)] = $identity;
        }

        $nextRows = [];
        $ensure = [];
        $remove = [];

        foreach ($current as $key => $identity) {
            $policy = $policies[$identity['policy_id']] ?? null;
            if ($policy === null) {
                self::fail('HAProxy TLS identity references missing HA policy ' . $identity['policy_id']);
            }
            if (!$policy['synchronize']) {
                $nextRows[] = [
                    'frontend_name' => $identity['frontend_name'],
                    'dns_name' => $identity['dns_name'],
                    'policy_id' => $identity['policy_uuid'],
                    '@attributes' => $identity['@attributes'],
                ];
                continue;
            }
            if (!isset($desiredByKey[$key])) {
                $remove[] = $identity;
            }
        }

        foreach ($desiredByKey as $key => $identity) {
            $existing = $current[$key] ?? null;
            $policy = $policies[$identity['policy_id']];
            $uuid = is_array($existing)
                ? trim((string)($existing['@attributes']['uuid'] ?? ''))
                : '';
            if ($uuid === '') {
                $uuid = trim((string)$uuidFactory());
                if ($uuid === '') {
                    throw new \RuntimeException('UUID factory returned empty value');
                }
            }
            $row = [
                'frontend_name' => $identity['frontend_name'],
                'dns_name' => $identity['dns_name'],
                'policy_id' => $policy['uuid'],
                '@attributes' => ['uuid' => $uuid],
            ];
            $nextRows[] = $row;

            if ($existing === null || $existing['policy_id'] !== $identity['policy_id']) {
                $ensure[] = [
                    'frontend_name' => $identity['frontend_name'],
                    'dns_name' => $identity['dns_name'],
                    'policy_id' => $identity['policy_id'],
                ];
            }
        }

        usort($nextRows, function ($a, $b) use ($policies) {
            $leftPolicy = self::policyByReference($policies, $a['policy_id']);
            $rightPolicy = self::policyByReference($policies, $b['policy_id']);
            $left = ['frontend_name' => $a['frontend_name'], 'dns_name' => $a['dns_name']];
            $right = ['frontend_name' => $b['frontend_name'], 'dns_name' => $b['dns_name']];
            return self::identityKey($left) <=> self::identityKey($right)
                ?: $leftPolicy['id'] <=> $rightPolicy['id'];
        });

        $next = $config;
        $root =& self::rootForWrite($next);
        $root['sync_marker'] = ['enabled' => '1'];
        $currentContainer = $root['identities'] ?? [];
        $root['identities'] = self::serializeRowsLike($currentContainer, 'identity', $nextRows);

        return [
            'config' => $next,
            'changed' => $next != $config,
            'count' => count($desiredByKey),
            'ensure' => $ensure,
            'remove' => $remove,
        ];
    }
}

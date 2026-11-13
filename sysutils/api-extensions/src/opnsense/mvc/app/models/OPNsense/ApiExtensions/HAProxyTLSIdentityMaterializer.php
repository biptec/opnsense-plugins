<?php

namespace OPNsense\ApiExtensions;

require_once __DIR__ . '/HAProxyTLSIdentitySync.php';

/**
 * Deterministic Router-local plan for HAProxy TLS identity materialization.
 *
 * The plan contains no private key or certificate body. Multiple frontend
 * registrations for the same DNS identity intentionally share one node-local
 * certificate/key while retaining independent frontend memberships.
 */
final class HAProxyTLSIdentityMaterializer
{
    private const CERT_DIR = '/usr/local/etc/api-extensions/haproxy-tls';

    private static function realm($value): string
    {
        $value = strtoupper(trim((string)$value));
        if ($value === '' || !preg_match('/^[A-Z0-9][A-Z0-9.-]{0,253}$/D', $value)) {
            throw new \InvalidArgumentException('invalid FreeIPA realm for HAProxy TLS identity materialization');
        }
        return $value;
    }

    public static function refID(string $dnsName): string
    {
        $description = HAProxyTLSIdentitySync::certificateDescription($dnsName);
        return substr(hash('sha256', 'api-extensions-haproxy-tls:' . $description), 0, 13);
    }

    public static function fileToken(string $dnsName): string
    {
        $description = HAProxyTLSIdentitySync::certificateDescription($dnsName);
        return substr(hash('sha256', 'api-extensions-haproxy-tls-files:' . $description), 0, 20);
    }

    public static function requestID(string $dnsName): string
    {
        return 'haproxy-tls-' . self::fileToken($dnsName);
    }

    public static function certificatePath(string $dnsName): string
    {
        return self::CERT_DIR . '/' . self::fileToken($dnsName) . '.crt';
    }

    public static function keyPath(string $dnsName): string
    {
        return self::CERT_DIR . '/' . self::fileToken($dnsName) . '.key';
    }

    private static function runtimeCertificatePaths($value, string $field): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new \InvalidArgumentException('invalid HAProxy runtime certificate ' . $field . ' list');
        }
        $paths = [];
        foreach ($value as $path) {
            if (!is_scalar($path) || trim((string)$path) === '') {
                throw new \InvalidArgumentException('invalid HAProxy runtime certificate path in ' . $field);
            }
            $paths[] = trim((string)$path);
        }
        $paths = array_values(array_unique($paths));
        sort($paths);
        return $paths;
    }

    public static function runtimeMembershipChanged(array $diff): bool
    {
        foreach ($diff as $frontend => $row) {
            if (!is_array($row)) {
                throw new \InvalidArgumentException('invalid HAProxy runtime certificate diff for ' . (string)$frontend);
            }
            $local = self::runtimeCertificatePaths($row['local_certs'] ?? [], 'local');
            $remote = self::runtimeCertificatePaths($row['remote_certs'] ?? [], 'remote');
            if ($local !== $remote) {
                return true;
            }
            if (trim((string)($row['local_default'] ?? '')) !==
                trim((string)($row['remote_default'] ?? ''))) {
                return true;
            }
        }
        return false;
    }

    private static function runtimeCertificateMetadata($value, string $field): array
    {
        if (!is_array($value)) {
            throw new \InvalidArgumentException('invalid HAProxy runtime certificate ' . $field . ' metadata');
        }
        $result = [];
        foreach (['Serial', 'Subject', 'Issuer'] as $name) {
            if (!array_key_exists($name, $value) || !is_scalar($value[$name]) || trim((string)$value[$name]) === '') {
                throw new \InvalidArgumentException('invalid HAProxy runtime certificate ' . $field . ' ' . $name);
            }
            $result[$name] = trim((string)$value[$name]);
        }
        return $result;
    }

    public static function runtimeContentChanged(array $diff): bool
    {
        foreach ($diff as $frontend => $row) {
            if (!is_array($row)) {
                throw new \InvalidArgumentException('invalid HAProxy runtime certificate diff for ' . (string)$frontend);
            }
            $certs = $row['certs'] ?? [];
            if (!is_array($certs)) {
                throw new \InvalidArgumentException('invalid HAProxy runtime certificate content map for ' . (string)$frontend);
            }
            foreach ($certs as $certificate => $state) {
                if (!is_array($state)) {
                    throw new \InvalidArgumentException('invalid HAProxy runtime certificate state for ' . (string)$certificate);
                }
                $remote = $state['remote'] ?? null;
                if (is_array($remote) && ($remote['Status'] ?? null) === 'Empty') {
                    return true;
                }
                if (is_array($remote) && array_key_exists('error', $remote)) {
                    if (!is_scalar($remote['error']) || trim((string)$remote['error']) === '') {
                        throw new \InvalidArgumentException('invalid HAProxy runtime certificate remote error');
                    }
                    return true;
                }
                $localMetadata = self::runtimeCertificateMetadata($state['local'] ?? null, 'local');
                $remoteMetadata = self::runtimeCertificateMetadata($remote, 'remote');
                if ($localMetadata !== $remoteMetadata) {
                    return true;
                }
            }
        }
        return false;
    }

    public static function plan(array $config, string $realm): array
    {
        $realm = self::realm($realm);
        $byDNS = [];
        foreach (HAProxyTLSIdentitySync::identities($config) as $identity) {
            $dns = $identity['dns_name'];
            if (!isset($byDNS[$dns])) {
                $byDNS[$dns] = [
                    'dns_name' => $dns,
                    'principal' => 'HAPROXY/' . $dns . '@' . $realm,
                    'subject' => 'CN=' . $dns . ',O=' . $realm,
                    'certificate_description' => HAProxyTLSIdentitySync::certificateDescription($dns),
                    'certificate_ref_id' => self::refID($dns),
                    'request_id' => self::requestID($dns),
                    'certificate_path' => self::certificatePath($dns),
                    'key_path' => self::keyPath($dns),
                    'frontends' => [],
                ];
            }
            $byDNS[$dns]['frontends'][] = $identity['frontend_name'];
        }

        foreach ($byDNS as &$entry) {
            $entry['frontends'] = array_values(array_unique($entry['frontends']));
            sort($entry['frontends']);
        }
        unset($entry);
        ksort($byDNS);

        return array_values($byDNS);
    }
}

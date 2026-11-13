#!/usr/local/bin/php
<?php

require_once 'config.inc';
require_once 'util.inc';
require_once 'script/load_phalcon.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxyTLSIdentitySync.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxyTLSIdentityMaterializer.php';

use OPNsense\ApiExtensions\HAProxyTLSIdentityMaterializer;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

const IPA_CONFIG = '/usr/local/etc/ipa/default.conf';
const IPA_CA = '/usr/local/etc/ipa/ca.crt';
const SYSTEM_CA = '/usr/local/etc/ssl/cert.pem';
const CERT_DIR = '/usr/local/etc/api-extensions/haproxy-tls';
const MANAGED_DESCRIPTION_PREFIX = 'HAProxy TLS ';

function fail(string $message): never
{
    throw new RuntimeException($message);
}

function run_command(array $argv, bool $allowFailure = false): array
{
    $spec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($argv, $spec, $pipes);
    if (!is_resource($process)) {
        fail('unable to start command: ' . implode(' ', $argv));
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($process);
    if ($code !== 0 && !$allowFailure) {
        $detail = trim((string)$stderr);
        fail(sprintf(
            'command failed (%d): %s%s',
            $code,
            implode(' ', $argv),
            $detail !== '' ? ': ' . $detail : ''
        ));
    }
    return ['code' => $code, 'stdout' => (string)$stdout, 'stderr' => (string)$stderr];
}

function ipa_realm(): string
{
    if (!is_file(IPA_CONFIG)) {
        fail('FreeIPA client configuration is missing');
    }
    foreach (file(IPA_CONFIG, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^\s*realm\s*=\s*(\S+)\s*$/', $line, $match)) {
            return strtoupper($match[1]);
        }
    }
    fail('FreeIPA realm is missing from client configuration');
}

function certificate_names(string $pem): array
{
    $parsed = openssl_x509_parse($pem);
    if (!is_array($parsed)) {
        return [];
    }
    $names = [];
    $san = (string)($parsed['extensions']['subjectAltName'] ?? '');
    foreach (explode(',', $san) as $entry) {
        $entry = trim($entry);
        if (str_starts_with($entry, 'DNS:')) {
            $names[] = strtolower(rtrim(substr($entry, 4), '.'));
        }
    }
    $names = array_values(array_unique(array_filter($names)));
    sort($names);
    return $names;
}

function certificate_server_auth(string $pem): bool
{
    $parsed = openssl_x509_parse($pem);
    if (!is_array($parsed)) {
        return false;
    }
    $eku = (string)($parsed['extensions']['extendedKeyUsage'] ?? '');
    return in_array('TLS Web Server Authentication', array_map('trim', explode(',', $eku)), true);
}

function certificate_not_expiring(string $pem): bool
{
    $parsed = openssl_x509_parse($pem);
    if (!is_array($parsed)) {
        return false;
    }
    return (int)($parsed['validTo_time_t'] ?? 0) > time() + 2592000;
}

function ocsp_status(string $certPath): string
{
    if (!is_file($certPath) || !is_file(IPA_CA)) {
        return 'unknown';
    }
    $uri = run_command(['openssl', 'x509', '-in', $certPath, '-noout', '-ocsp_uri'], true);
    $url = trim($uri['stdout']);
    if ($uri['code'] !== 0 || $url === '') {
        return 'unknown';
    }
    $result = run_command([
        'openssl', 'ocsp',
        '-issuer', IPA_CA,
        '-cert', $certPath,
        '-url', $url,
        '-CAfile', IPA_CA,
        '-no_nonce',
        '-timeout', '10',
    ], true);
    $output = $result['stdout'] . "\n" . $result['stderr'];
    if (str_contains($output, $certPath . ': good')) {
        return 'good';
    }
    if (str_contains($output, $certPath . ': revoked')) {
        return 'revoked';
    }
    return 'unknown';
}

function request_output(string $requestID): ?string
{
    $result = run_command(['getcert', 'list', '-i', $requestID], true);
    return $result['code'] === 0 ? $result['stdout'] : null;
}

function tracking_matches(array $item): bool
{
    $output = request_output($item['request_id']);
    if ($output === null) {
        return false;
    }
    if (!str_contains($output, "\tCA: IPA") ||
        !str_contains($output, "\tstatus: MONITORING") ||
        !str_contains($output, "\tprincipal name: " . $item['principal'])) {
        return false;
    }

    $trackingNames = [];
    if (preg_match('/^\s*dns:\s*(.+)$/mi', $output, $match)) {
        foreach (explode(',', $match[1]) as $name) {
            $name = strtolower(rtrim(trim($name), '.'));
            if ($name !== '') {
                $trackingNames[] = $name;
            }
        }
    }
    $trackingNames = array_values(array_unique($trackingNames));
    sort($trackingNames);
    return $trackingNames === [$item['dns_name']];
}

function tracking_postsave_matches(array $item, string $postsave): bool
{
    $output = request_output($item['request_id']);
    if ($output === null) {
        return false;
    }
    if (!preg_match('/^\s*post-save command:\s*(.*)$/mi', $output, $match)) {
        return false;
    }
    return trim((string)$match[1]) === $postsave;
}

function ensure_postsave_tracking(array $item, string $postsave): bool
{
    if (tracking_postsave_matches($item, $postsave)) {
        return false;
    }
    run_command([
        'getcert', 'start-tracking',
        '-i', $item['request_id'],
        '-C', $postsave,
    ]);
    if (!tracking_postsave_matches($item, $postsave)) {
        fail('unable to configure HAProxy TLS renewal post-save hook for ' . $item['dns_name']);
    }
    return true;
}

function source_matches(array $item): bool
{
    $certPath = $item['certificate_path'];
    $keyPath = $item['key_path'];
    if (!is_file($certPath) || !is_file($keyPath) ||
        filesize($certPath) === 0 || filesize($keyPath) === 0) {
        return false;
    }
    $certPem = trim((string)file_get_contents($certPath));
    $keyPem = trim((string)file_get_contents($keyPath));
    $cert = openssl_x509_read($certPem);
    $key = openssl_pkey_get_private($keyPem);
    if ($cert === false || $key === false || !openssl_x509_check_private_key($cert, $key)) {
        return false;
    }
    $parsed = openssl_x509_parse($certPem);
    if (!is_array($parsed) ||
        strtolower(rtrim((string)($parsed['subject']['CN'] ?? ''), '.')) !== $item['dns_name'] ||
        certificate_names($certPem) !== [$item['dns_name']] ||
        !certificate_server_auth($certPem) ||
        !certificate_not_expiring($certPem)) {
        return false;
    }

    foreach ([IPA_CA, SYSTEM_CA] as $caFile) {
        $verify = run_command([
            'openssl', 'verify', '-purpose', 'sslserver',
            '-CAfile', $caFile, $certPath,
        ], true);
        if ($verify['code'] !== 0) {
            return false;
        }
    }
    return ocsp_status($certPath) === 'good' && tracking_matches($item);
}

function ensure_private_key(string $path): void
{
    if (is_file($path) && filesize($path) > 0) {
        return;
    }
    if (file_exists($path)) {
        fail('HAProxy TLS private-key path exists but is empty: ' . $path);
    }
    run_command([
        'openssl', 'genpkey',
        '-algorithm', 'RSA',
        '-pkeyopt', 'rsa_keygen_bits:3072',
        '-out', $path,
    ]);
    chmod($path, 0600);
    @chown($path, 'root');
    @chgrp($path, 'wheel');
}

function ensure_source(array $item, string $postsave): bool
{
    $certPath = $item['certificate_path'];
    if (is_file($certPath) && filesize($certPath) > 0) {
        $ocsp = ocsp_status($certPath);
        if ($ocsp === 'unknown') {
            fail('unable to determine revocation status for ' . $item['dns_name'] . '; refusing certificate churn');
        }
    }
    if (source_matches($item)) {
        return ensure_postsave_tracking($item, $postsave);
    }

    if (!is_dir(CERT_DIR) && !mkdir(CERT_DIR, 0700, true) && !is_dir(CERT_DIR)) {
        fail('unable to create HAProxy TLS certificate directory');
    }
    chmod(CERT_DIR, 0700);
    ensure_private_key($item['key_path']);

    // Explicit issuance/resubmit is already synchronously reconciled by
    // this process. Do not let certmonger's after-save hook re-enter the same
    // HAProxy reconciliation while getcert -w is still in flight. A no-op
    // command is used explicitly because omitting -C on resubmit preserves the
    // previously configured after-save command. Once certificate convergence
    // is proven below, restore the real post-save hook for future automatic
    // renewals.
    $common = [
        '-c', 'IPA',
        '-N', $item['subject'],
        '-K', $item['principal'],
        '-D', $item['dns_name'],
        '-C', '/usr/bin/true',
    ];
    if (request_output($item['request_id']) !== null) {
        run_command(array_merge(
            ['getcert', 'resubmit', '-i', $item['request_id']],
            $common,
            ['-w', '--wait-timeout', '180']
        ));
    } else {
        run_command(array_merge(
            [
                'getcert', 'request',
                '-I', $item['request_id'],
                '-f', $item['certificate_path'],
                '-k', $item['key_path'],
            ],
            $common,
            [
                '-G', 'RSA',
                '-g', '3072',
                '-o', 'root',
                '-m', '0600',
                '-O', 'root',
                '-M', '0644',
                '-w', '--wait-timeout', '180',
            ]
        ));
    }

    if (!source_matches($item)) {
        fail('FreeIPA certificate did not converge for ' . $item['dns_name']);
    }
    ensure_postsave_tracking($item, $postsave);
    return true;
}

function comma_values($value): array
{
    $items = preg_split('/[\s,]+/', trim((string)$value), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $items = array_values(array_unique(array_map('trim', $items)));
    sort($items);
    return $items;
}

function find_frontend($cfg, string $name)
{
    $found = null;
    if (!isset($cfg->OPNsense->HAProxy->frontends)) {
        fail('HAProxy frontend configuration is missing');
    }
    foreach ($cfg->OPNsense->HAProxy->frontends->frontend as $candidate) {
        if ((string)$candidate->name !== $name) {
            continue;
        }
        if ($found !== null) {
            fail('multiple HAProxy frontends match ' . $name);
        }
        $found = $candidate;
    }
    if ($found === null) {
        fail('HAProxy TLS identity references missing frontend ' . $name);
    }
    if (!in_array((string)($found->ssl_enabled ?? ''), ['1', 'yes', 'on'], true)) {
        fail('HAProxy TLS identity frontend does not terminate TLS: ' . $name);
    }
    return $found;
}

function managed_certificate_dns($candidate): ?string
{
    $description = trim((string)($candidate->descr ?? ''));
    if (!str_starts_with($description, MANAGED_DESCRIPTION_PREFIX)) {
        return null;
    }
    $dns = strtolower(rtrim(trim(substr($description, strlen(MANAGED_DESCRIPTION_PREFIX))), '.'));
    if ($dns === '' || (string)($candidate->refid ?? '') !== HAProxyTLSIdentityMaterializer::refID($dns)) {
        return null;
    }
    return $dns;
}

function freeipa_ca_refid(): string
{
    return substr(hash('sha256', 'core-router-freeipa-ca'), 0, 13);
}

function import_and_bind(array $plan, array $ready): array
{
    $config = Config::getInstance();
    $config->lock();
    try {
        $cfg = $config->object();
        $beforeXml = (string)$config;
        $caRefID = freeipa_ca_refid();

        $caPresent = false;
        foreach ($cfg->ca as $candidate) {
            if ((string)$candidate->refid === $caRefID) {
                $caPresent = true;
                break;
            }
        }
        if (!$caPresent) {
            fail('managed FreeIPA CA is absent from OPNsense Trust');
        }

        $desiredByDNS = [];
        foreach ($plan as $item) {
            $desiredByDNS[$item['dns_name']] = $item;
        }

        // Import only material that is locally ready. Desired-but-not-ready
        // identities retain any existing Trust object/binding during postsave.
        foreach ($ready as $item) {
            $certPem = trim((string)file_get_contents($item['certificate_path'])) . "\n";
            $keyPem = trim((string)file_get_contents($item['key_path'])) . "\n";
            $cert = openssl_x509_read($certPem);
            $key = openssl_pkey_get_private($keyPem);
            if ($cert === false || $key === false || !openssl_x509_check_private_key($cert, $key) ||
                certificate_names($certPem) !== [$item['dns_name']] ||
                !certificate_server_auth($certPem)) {
                fail('refusing to import invalid HAProxy TLS material for ' . $item['dns_name']);
            }

            $matches = [];
            foreach ($cfg->cert as $candidate) {
                if ((string)$candidate->refid === $item['certificate_ref_id'] ||
                    (string)$candidate->descr === $item['certificate_description']) {
                    $matches[] = $candidate;
                }
            }
            if (count($matches) > 1) {
                fail('ambiguous managed Trust certificate for ' . $item['dns_name']);
            }
            $certificate = $matches[0] ?? $cfg->addChild('cert');
            foreach ([
                'refid' => $item['certificate_ref_id'],
                'descr' => $item['certificate_description'],
                'caref' => $caRefID,
                'crt' => base64_encode($certPem),
                'prv' => base64_encode($keyPem),
            ] as $field => $value) {
                $certificate->{$field} = $value;
            }
        }

        $managedRefs = [];
        foreach ($cfg->cert as $candidate) {
            $dns = managed_certificate_dns($candidate);
            if ($dns !== null) {
                $managedRefs[(string)$candidate->refid] = $dns;
            }
        }

        // Only locally present managed certs may be bound. A desired identity
        // whose renewal is not ready preserves its previous Trust object/ref.
        $desiredRefsByFrontend = [];
        foreach ($plan as $item) {
            $ref = $item['certificate_ref_id'];
            if (($managedRefs[$ref] ?? null) !== $item['dns_name']) {
                continue;
            }
            foreach ($item['frontends'] as $frontendName) {
                $desiredRefsByFrontend[$frontendName] ??= [];
                $desiredRefsByFrontend[$frontendName][] = $ref;
            }
        }

        $membershipChanged = false;
        foreach ($cfg->OPNsense->HAProxy->frontends->frontend as $frontend) {
            $name = (string)$frontend->name;
            $defaultRef = trim((string)($frontend->ssl_default_certificate ?? ''));
            $current = comma_values($frontend->ssl_certificates ?? '');
            $wantedManaged = array_values(array_unique($desiredRefsByFrontend[$name] ?? []));
            sort($wantedManaged);

            $unmanaged = array_values(array_filter(
                $current,
                fn($ref) => !isset($managedRefs[$ref])
            ));
            $next = array_values(array_unique(array_merge($unmanaged, $wantedManaged)));
            sort($next);

            if ($defaultRef !== '') {
                if (isset($managedRefs[$defaultRef]) && !in_array($defaultRef, $wantedManaged, true)) {
                    fail('refusing to remove managed certificate that is still the frontend default: ' . $name);
                }
                if (!in_array($defaultRef, $next, true)) {
                    array_unshift($next, $defaultRef);
                    $next = array_values(array_unique($next));
                }
            }
            $nextValue = implode(',', $next);
            if ((string)($frontend->ssl_certificates ?? '') !== $nextValue) {
                $membershipChanged = true;
            }
            $frontend->ssl_certificates = $nextValue;
        }

        $removeIndexes = [];
        foreach ($cfg->cert as $index => $candidate) {
            $dns = managed_certificate_dns($candidate);
            if ($dns !== null && !isset($desiredByDNS[$dns])) {
                $removeIndexes[] = (int)$index;
            }
        }
        rsort($removeIndexes);
        foreach ($removeIndexes as $index) {
            unset($cfg->cert[$index]);
        }

        $changed = (string)$config !== $beforeXml;
        $backup = null;
        if ($changed) {
            $backup = $config->backup();
            $config->save(
                ['description' => 'Reconcile Router-local HAProxy TLS identities'],
                false
            );
        }
        return [
            'changed' => $changed,
            'membership_changed' => $membershipChanged,
            'backup' => $backup,
        ];
    } finally {
        $config->unlock();
    }
}

function cleanup_orphans(array $plan): void
{
    $desired = array_fill_keys(array_column($plan, 'dns_name'), true);
    if (is_dir(CERT_DIR)) {
        foreach (glob(CERT_DIR . '/*.crt') ?: [] as $certPath) {
            $token = basename($certPath, '.crt');
            $matched = false;
            foreach ($plan as $item) {
                if ($item['certificate_path'] === $certPath) {
                    $matched = true;
                    break;
                }
            }
            if ($matched) {
                continue;
            }
            $keyPath = CERT_DIR . '/' . $token . '.key';
            @unlink($certPath);
            @unlink($keyPath);
        }
    }

    // Stop only deterministic requests that are no longer represented by a
    // desired identity. A request ID alone never identifies arbitrary certs.
    $all = run_command(['getcert', 'list'], true);
    if ($all['code'] === 0 &&
        preg_match_all("/^Request ID '([^']+)'/m", $all['stdout'], $matches)) {
        foreach ($matches[1] as $requestID) {
            if (!str_starts_with($requestID, 'haproxy-tls-')) {
                continue;
            }
            $wanted = false;
            foreach ($plan as $item) {
                if ($item['request_id'] === $requestID) {
                    $wanted = true;
                    break;
                }
            }
            if (!$wanted) {
                run_command(['getcert', 'stop-tracking', '-i', $requestID], true);
            }
        }
    }
}

function haproxy_runtime_diff(Backend $backend): array
{
    $rawDiff = trim($backend->configdRun('haproxy cert_diff_bulk'));
    try {
        $runtimeDiff = json_decode($rawDiff, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $error) {
        fail('HAProxy runtime certificate diff returned invalid JSON: ' . $error->getMessage());
    }
    if (!is_array($runtimeDiff)) {
        fail('HAProxy runtime certificate diff returned an invalid payload');
    }
    return $runtimeDiff;
}

function haproxy_runtime_changed(array $runtimeDiff): bool
{
    return HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeDiff) ||
        HAProxyTLSIdentityMaterializer::runtimeContentChanged($runtimeDiff);
}

function reload_haproxy_runtime(Backend $backend): void
{
    $config = Config::getInstance();
    $config->forceReload();
    $enabled = in_array(
        (string)($config->object()->OPNsense->HAProxy->general->enabled ?? ''),
        ['1', 'yes', 'on'],
        true
    );
    $backend->configdRun($enabled ? 'haproxy reload' : 'haproxy deploy');
}

function require_haproxy_runtime_parity(Backend $backend): void
{
    if (haproxy_runtime_changed(haproxy_runtime_diff($backend))) {
        fail('HAProxy runtime certificate state remains stale after TLS identity reconciliation');
    }
}

function apply_haproxy_runtime(bool $membershipChanged): void
{
    $backend = new Backend();
    $backend->configdRun('template reload OPNsense/HAProxy');
    $test = trim($backend->configdRun('haproxy configtest'));
    if (stripos($test, 'ALERT') !== false) {
        fail('HAProxy configuration failed validation after TLS identity reconciliation: ' . preg_replace('/\s+/', ' ', $test));
    }

    $runtimeDiff = haproxy_runtime_diff($backend);
    $membershipChanged = $membershipChanged ||
        HAProxyTLSIdentityMaterializer::runtimeMembershipChanged($runtimeDiff);
    $contentChanged = HAProxyTLSIdentityMaterializer::runtimeContentChanged($runtimeDiff);

    // HAProxy's runtime certificate API can replace certificate contents that
    // are already loaded, but it cannot add or remove crt-list membership. A
    // membership/default change therefore needs a normal reload. Pure renewal
    // first uses the zero-downtime Runtime API path, but command completion is
    // not accepted as proof: cert_sync_bulk can return successfully while the
    // running certificate serial remains stale. Verify the actual runtime
    // postcondition and fall back to a normal graceful reload only when the hot
    // sync did not converge.
    if ($membershipChanged) {
        reload_haproxy_runtime($backend);
        require_haproxy_runtime_parity($backend);
        return;
    }

    if (!$contentChanged) {
        return;
    }

    $backend->configdRun('haproxy cert_sync_bulk');
    if (!haproxy_runtime_changed(haproxy_runtime_diff($backend))) {
        return;
    }

    reload_haproxy_runtime($backend);
    require_haproxy_runtime_parity($backend);
}

function rollback_haproxy_config(?string $backup): void
{
    if ($backup === null || $backup === '') {
        return;
    }
    $config = Config::getInstance();
    if (!$config->restoreBackup($backup)) {
        fail('unable to restore HAProxy TLS identity configuration backup');
    }
    $config->forceReload();

    $backend = new Backend();
    $backend->configdRun('template reload OPNsense/HAProxy');
    $enabled = in_array(
        (string)($config->object()->OPNsense->HAProxy->general->enabled ?? ''),
        ['1', 'yes', 'on'],
        true
    );
    $backend->configdRun($enabled ? 'haproxy reload' : 'haproxy deploy');
}

function reconcile(bool $issue): array
{
    foreach ([IPA_CONFIG, IPA_CA, SYSTEM_CA] as $path) {
        if (!is_file($path) || filesize($path) === 0) {
            fail('required HAProxy TLS identity dependency is missing: ' . $path);
        }
    }

    $config = Config::getInstance();
    $config->forceReload();
    $realm = ipa_realm();
    $plan = HAProxyTLSIdentityMaterializer::plan($config->toArray(), $realm);
    $changedSource = false;
    if ($issue) {
        $postsave = '/usr/local/opnsense/scripts/OPNsense/ApiExtensions/haproxy_tls_identity_reconcile.php postsave';
        foreach ($plan as $item) {
            $changedSource = ensure_source($item, $postsave) || $changedSource;
        }
    } else {
        foreach ($plan as $item) {
            if (!is_file($item['certificate_path']) || !is_file($item['key_path'])) {
                continue;
            }
        }
    }

    $ready = [];
    foreach ($plan as $item) {
        if (is_file($item['certificate_path']) && is_file($item['key_path'])) {
            $certPem = trim((string)file_get_contents($item['certificate_path']));
            $keyPem = trim((string)file_get_contents($item['key_path']));
            $cert = openssl_x509_read($certPem);
            $key = openssl_pkey_get_private($keyPem);
            if ($cert !== false && $key !== false &&
                openssl_x509_check_private_key($cert, $key) &&
                certificate_names($certPem) === [$item['dns_name']] &&
                certificate_server_auth($certPem)) {
                $ready[] = $item;
            }
        }
    }
    if ($issue && count($ready) !== count($plan)) {
        fail('not all HAProxy TLS identities have valid local certificate material');
    }

    $configResult = import_and_bind($plan, $ready);
    try {
        // Reconcile runtime state even when persistent config and source
        // material are already converged. A previous interrupted reload can
        // leave the generated crt-list correct while the running HAProxy
        // process still lacks a managed certificate membership.
        apply_haproxy_runtime($configResult['membership_changed']);
    } catch (Throwable $runtimeError) {
        rollback_haproxy_config($configResult['backup']);
        throw $runtimeError;
    }

    // Destructive local cleanup is intentionally last. A failed HAProxy
    // runtime update therefore rolls back config without losing old files or
    // certmonger tracking that the restored config may still depend on.
    cleanup_orphans($plan);

    return [
        'status' => 'ok',
        'count' => count($plan),
        'changed' => $configResult['changed'] || $changedSource,
    ];
}

$mode = $argv[1] ?? 'reconcile';
try {
    if (!in_array($mode, ['reconcile', 'postsave'], true)) {
        fail('usage: haproxy_tls_identity_reconcile.php [reconcile|postsave]');
    }
    $result = reconcile($mode === 'reconcile');
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    exit(0);
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    echo json_encode(['status' => 'failed', 'message' => $error->getMessage()], JSON_UNESCAPED_SLASHES) . "\n";
    exit(1);
}

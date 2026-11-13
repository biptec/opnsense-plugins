<?php
require_once 'config.inc';
require_once 'filter.inc';
require_once 'interfaces.inc';
require_once 'util.inc';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/InterfaceSync.php';
require_once '/usr/local/opnsense/mvc/app/models/OPNsense/ApiExtensions/HAProxySync.php';

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\HAProxyTLSIdentitySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

function xmlrpc_publishable_api_extensions()
{
    return [
        'api_extensions_sync_interfaces_xmlrpc',
        'api_extensions_sync_haproxy_xmlrpc',
    ];
}

function api_extensions_sync_interfaces_xmlrpc($payload)
{
    global $config;

    try {
        Config::getInstance()->lock();
        $result = InterfaceSync::reconcile($config, $payload, fn() => generate_uuid());
        if (!$result['changed']) {
            return ['status' => 'ok', 'changed' => false, 'count' => $result['count']];
        }

        foreach ($result['plan']['reset_interfaces'] as $identifier) {
            interface_reset($identifier);
        }

        $config = $result['config'];
        $saved = write_config('Synchronize endpoint interface scaffold from HA primary');
        if ($saved === false || $saved === -1) {
            throw new \RuntimeException('unable to save synchronized policy-managed interface scaffold');
        }

        foreach ($result['plan']['destroy_vlans'] as $device) {
            legacy_interface_destroy($device);
        }
        foreach ($result['plan']['configure_vlans'] as $device) {
            interfaces_vlan_configure($device);
        }
        foreach ($result['plan']['configure_interfaces'] as $identifier) {
            interface_configure(false, $identifier, true);
        }

        return [
            'status' => 'ok',
            'changed' => true,
            'count' => $result['count'],
        ];
    } catch (\Throwable $error) {
        log_msg('Policy-managed interface HA synchronization failed: ' . $error->getMessage(), LOG_ERR);
        return ['status' => 'failed', 'message' => $error->getMessage()];
    }
}

function api_extensions_sync_haproxy_xmlrpc($payload)
{
    global $config;

    $previous = $config;
    $savedNewConfig = false;
    $configLocked = false;
    $materializerChanged = false;
    $metadataChanged = false;
    $bootstrapGraphChanged = false;
    $graphChanged = false;

    try {
        $validatedPayload = HAProxySync::validatePayload($payload);
        $configHandle = Config::getInstance();

        if ($validatedPayload['version'] === HAProxySync::VERSION) {
            // A fresh secondary may receive the Core-owned TLS frontend and a
            // synchronized identity referencing it in the same v4 payload.
            // Stage that graph first using only pre-existing receiver-local
            // certificate descriptions. Identity-managed certificates remain
            // excluded until the local materializer issues/imports them.
            $bootstrapPayload = HAProxySync::bootstrapPayloadForMissingTLSIdentityFrontends(
                $config,
                $validatedPayload
            );
            if ($bootstrapPayload !== null) {
                $configHandle->lock();
                $configLocked = true;

                $bootstrapResult = HAProxySync::reconcile(
                    $config,
                    $bootstrapPayload,
                    fn() => generate_uuid(),
                    fn() => uniqid('', true)
                );
                $bootstrapGraphChanged = $bootstrapResult['changed'];
                if ($bootstrapGraphChanged) {
                    $config = $bootstrapResult['config'];
                    $saved = write_config(
                        'Stage synchronized HAProxy frontend before TLS identity materialization'
                    );
                    if ($saved === false || $saved === -1) {
                        throw new \RuntimeException(
                            'unable to save staged HAProxy frontend synchronization'
                        );
                    }
                    $savedNewConfig = true;
                }

                $configHandle->unlock();
                $configLocked = false;
                $configHandle->forceReload();
                $config = $configHandle->toArray();
            }

            // Phase 1: persist only non-secret receiver-local policy/identity
            // metadata. Do not hold the OPNsense config lock while invoking
            // configd: the child materializer needs the same lock.
            $configHandle->lock();
            $configLocked = true;

            $metadataConfig = $config;
            InterfaceSync::reconcilePolicies(
                $metadataConfig,
                ['policies' => $validatedPayload['policies'], 'prune' => false],
                fn() => generate_uuid()
            );
            $tlsPlan = HAProxyTLSIdentitySync::reconcile(
                $metadataConfig,
                $validatedPayload['tls_identities'],
                fn() => generate_uuid()
            );
            $metadataConfig = $tlsPlan['config'];
            $metadataChanged = $metadataConfig !== $config;

            if ($metadataChanged) {
                $config = $metadataConfig;
                $saved = write_config('Synchronize HAProxy TLS identity metadata from HA primary');
                if ($saved === false || $saved === -1) {
                    throw new \RuntimeException('unable to save synchronized HAProxy TLS identity metadata');
                }
                $savedNewConfig = true;
            }

            $configHandle->unlock();
            $configLocked = false;

            $materializer = api_extensions_haproxy_tls_identity_reconcile_local();
            $materializerChanged = !empty($materializer['changed']);
            $savedNewConfig = $savedNewConfig || $materializerChanged;

            // The materializer updates Trust/frontend membership through a
            // separate process. Reload before semantic description -> local
            // refid resolution in the full HAProxy graph reconciliation.
            $configHandle->forceReload();
            $config = $configHandle->toArray();
        }

        // Phase 2: apply the ordinary policy-managed HAProxy graph. For v4 the
        // TLS identity step above is now idempotent and all receiver-local cert
        // refs needed by any synchronized frontend are already materialized.
        $configHandle->lock();
        $configLocked = true;
        $result = HAProxySync::reconcile(
            $config,
            $validatedPayload,
            fn() => generate_uuid(),
            fn() => uniqid('', true)
        );
        $finalGraphChanged = $result['changed'];
        $graphChanged = $bootstrapGraphChanged || $finalGraphChanged;

        if ($finalGraphChanged) {
            $config = $result['config'];
            $saved = write_config('Synchronize policy-managed HAProxy objects from HA primary');
            if ($saved === false || $saved === -1) {
                throw new \RuntimeException('unable to save synchronized HAProxy objects');
            }
            $savedNewConfig = true;
        }

        $configHandle->unlock();
        $configLocked = false;

        if ($graphChanged) {
            $backend = new Backend();
            // HAProxy's configtest action validates haproxy.conf.staging, so
            // templates must be rendered after write_config() first.
            $backend->configdRun('template reload OPNsense/HAProxy');
            $configTest = trim($backend->configdRun('haproxy configtest'));
            if (stripos($configTest, 'ALERT') !== false) {
                throw new \RuntimeException(
                    'synchronized HAProxy configuration failed validation: ' .
                    api_extensions_haproxy_test_summary($configTest)
                );
            }

            $enabled = api_extensions_haproxy_enabled($config);
            $backend->configdRun($enabled ? 'haproxy reload' : 'haproxy deploy');
        }

        return [
            'status' => 'ok',
            'changed' => $metadataChanged || $materializerChanged || $graphChanged,
            'count' => $result['count'],
        ];
    } catch (\Throwable $error) {
        if ($configLocked) {
            try {
                Config::getInstance()->unlock();
            } catch (\Throwable $unlockError) {
                log_msg('Policy-managed HAProxy synchronization unlock failed: ' . $unlockError->getMessage(), LOG_ERR);
            }
            $configLocked = false;
        }

        if ($savedNewConfig) {
            $config = $previous;
            try {
                $rolledBack = write_config('Rollback failed policy-managed HAProxy synchronization');
                if ($rolledBack === false || $rolledBack === -1) {
                    throw new \RuntimeException('unable to save HAProxy synchronization rollback');
                }

                Config::getInstance()->forceReload();

                // Best-effort local secret/material cleanup against the
                // restored declarative identity contract. This never copies
                // private material between peers.
                try {
                    api_extensions_haproxy_tls_identity_reconcile_local();
                } catch (\Throwable $cleanupError) {
                    log_msg(
                        'HAProxy TLS identity rollback cleanup failed: ' . $cleanupError->getMessage(),
                        LOG_ERR
                    );
                }

                $backend = new Backend();
                $backend->configdRun('template reload OPNsense/HAProxy');
                $backend->configdRun(
                    api_extensions_haproxy_enabled($previous) ? 'haproxy reload' : 'haproxy deploy'
                );
            } catch (\Throwable $rollbackError) {
                log_msg(
                    'Policy-managed HAProxy synchronization rollback failed: ' . $rollbackError->getMessage(),
                    LOG_ERR
                );
            }
        }

        log_msg('Policy-managed HAProxy synchronization failed: ' . $error->getMessage(), LOG_ERR);
        return ['status' => 'failed', 'message' => $error->getMessage()];
    }
}

function api_extensions_haproxy_tls_identity_reconcile_local(): array
{
    $raw = trim((new Backend())->configdRun('api_extensions haproxy_tls_identity_reconcile'));
    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || ($decoded['status'] ?? '') !== 'ok') {
        $message = is_array($decoded)
            ? trim((string)($decoded['message'] ?? ''))
            : '';
        throw new \RuntimeException(
            'Router-local HAProxy TLS identity reconciliation failed' .
            ($message !== '' ? ': ' . $message : ($raw !== '' ? ': ' . $raw : ''))
        );
    }
    return $decoded;
}

function api_extensions_haproxy_enabled($candidate)
{
    return in_array(
        $candidate['OPNsense']['HAProxy']['general']['enabled'] ?? null,
        [1, '1', true, 'yes', 'on'],
        true
    );
}

function api_extensions_haproxy_test_summary($output)
{
    $summary = trim(preg_replace('/\s+/', ' ', (string)$output));
    if ($summary === '') {
        return 'empty configtest response';
    }
    if (strlen($summary) > 400) {
        return substr($summary, 0, 400) . '...';
    }
    return $summary;
}

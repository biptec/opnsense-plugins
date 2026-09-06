<?php

namespace OPNsense\ApiExtensions\Api;

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\ApiExtensions\ReplacementHandoff;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class ReplacementHandoffController extends ApiControllerBase
{
    private function postObject(): array
    {
        if (!$this->request->isPost() || !$this->request->hasPost('handoff')) {
            throw new \InvalidArgumentException('handoff POST object is required');
        }
        $value = $this->request->getPost('handoff');
        if (!is_array($value)) {
            throw new \InvalidArgumentException('handoff must be an object');
        }
        return $value;
    }

    private function policyId(array $request): string
    {
        $policyId = trim((string)($request['policy_id'] ?? ''));
        if ($policyId === '') {
            throw new \InvalidArgumentException('handoff.policy_id is required');
        }
        return $policyId;
    }

    private function excludedUuids(array $request): array
    {
        $value = $request['excluded_uuids'] ?? [];
        if (!is_array($value)) {
            throw new \InvalidArgumentException('handoff.excluded_uuids must be a list');
        }
        return array_values($value);
    }

    private function haproxyEnabled(array $candidate): bool
    {
        return in_array(
            $candidate['OPNsense']['HAProxy']['general']['enabled'] ?? null,
            [1, '1', true, 'yes', 'on'],
            true
        );
    }

    private function runtimeApply(array $candidate, array $interfacePlan): void
    {
        if (($interfacePlan['reset_interfaces'] ?? []) !== [] ||
            ($interfacePlan['destroy_vlans'] ?? []) !== []) {
            throw new \RuntimeException(
                'replacement ownership handoff must be create-only for policy-managed interfaces'
            );
        }

        $backend = new Backend();
        $backend->configdRun('interface vlan configure');
        foreach (($interfacePlan['configure_interfaces'] ?? []) as $identifier) {
            $backend->configdpRun('interface reconfigure', [$identifier]);
        }
        $backend->configdRun('interface vip configure');
        $backend->configdRun('interface routes configure');
        $backend->configdRun('filter reload');

        // Normal OPNsense users synchronization also restarts the login service.
        // Do it before the API request returns so the shared Rigi credential is
        // already authoritative when the operator switches local credential files.
        $backend->configdpRun('service restart', ['login']);

        $backend->configdRun('template reload OPNsense/HAProxy');
        $configTest = trim($backend->configdRun('haproxy configtest'));
        if (stripos($configTest, 'ALERT') !== false) {
            $summary = trim(preg_replace('/\s+/', ' ', $configTest));
            if (strlen($summary) > 400) {
                $summary = substr($summary, 0, 400) . '...';
            }
            throw new \RuntimeException(
                'replacement HAProxy configuration failed validation: ' .
                ($summary === '' ? 'empty configtest response' : $summary)
            );
        }
        $backend->configdRun($this->haproxyEnabled($candidate) ? 'haproxy reload' : 'haproxy deploy');
    }

    private function saveConfig(Config $config, array $candidate, string $revision): void
    {
        $config->fromArray($candidate);
        $config->save($revision);
    }

    public function exportAction(): array
    {
        try {
            $request = $this->postObject();
            $bundle = ReplacementHandoff::buildReplicaBundle(
                Config::getInstance()->toArray(),
                $this->policyId($request),
                $this->excludedUuids($request)
            );
            $encoded = json_encode($bundle, JSON_UNESCAPED_SLASHES);
            if ($encoded === false) {
                throw new \RuntimeException('unable to encode replacement handoff bundle');
            }
            return [
                'status' => 'ok',
                'bundle' => $bundle,
                'sha256' => hash('sha256', $encoded),
            ];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function statusAction(): array
    {
        try {
            $request = $this->postObject();
            $policyId = $this->policyId($request);
            $config = Config::getInstance()->toArray();
            $interfaceOwners = array_filter(
                InterfaceSync::assignments($config),
                fn($row) => ($row['policy_id'] ?? '') === $policyId
            );
            $interfaceReplicas = array_filter(
                InterfaceSync::replicas($config),
                fn($row) => ($row['policy_id'] ?? '') === $policyId
            );
            $haproxyOwners = array_filter(
                HAProxySync::assignments($config),
                fn($row) => ($row['policy_id'] ?? '') === $policyId
            );
            $haproxyReplicas = array_filter(
                HAProxySync::replicas($config),
                fn($row) => ($row['policy_id'] ?? '') === $policyId
            );
            return [
                'status' => 'ok',
                'role' => trim((string)($config['hasync']['synchronizetoip'] ?? '')) === '' ? 'replica' : 'primary',
                'policy_id' => $policyId,
                'interface_owners' => count($interfaceOwners),
                'interface_replicas' => count($interfaceReplicas),
                'haproxy_owners' => count($haproxyOwners),
                'haproxy_replicas' => count($haproxyReplicas),
            ];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function previewAction(): array
    {
        try {
            $request = $this->postObject();
            $policyId = $this->policyId($request);
            if (!isset($request['bundle']) || !is_array($request['bundle'])) {
                throw new \InvalidArgumentException('handoff.bundle must be an object');
            }
            if (!isset($request['identity']) || !is_array($request['identity'])) {
                throw new \InvalidArgumentException('handoff.identity must be an object');
            }
            $result = ReplacementHandoff::reconcileAsPrimaryOwner(
                Config::getInstance()->toArray(),
                $request['bundle'],
                $request['identity'],
                $policyId,
                fn() => bin2hex(random_bytes(16)),
                fn() => uniqid('', true)
            );
            return [
                'status' => 'ok',
                'changed' => $result['changed'],
                'counts' => $result['counts'],
                'interface_plan' => $result['interface_plan'],
                'haproxy_plan' => $result['haproxy_plan'],
            ];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function importAction(): array
    {
        $config = Config::getInstance();
        $previous = null;
        $savedNewConfig = false;

        try {
            $request = $this->postObject();
            $policyId = $this->policyId($request);
            if (!isset($request['bundle']) || !is_array($request['bundle'])) {
                throw new \InvalidArgumentException('handoff.bundle must be an object');
            }
            if (!isset($request['identity']) || !is_array($request['identity'])) {
                throw new \InvalidArgumentException('handoff.identity must be an object');
            }

            $config->lock();
            $previous = $config->toArray();

            // Compute the complete candidate in memory first. Nothing has been
            // persisted yet, so every ownership/collision/identity guard is
            // evaluated before the destructive boundary.
            $result = ReplacementHandoff::reconcileAsPrimaryOwner(
                $previous,
                $request['bundle'],
                $request['identity'],
                $policyId,
                fn() => bin2hex(random_bytes(16)),
                fn() => uniqid('', true)
            );
            if (!$result['changed']) {
                throw new \RuntimeException(
                    'replacement ownership handoff produced no change; refusing ambiguous import'
                );
            }
            if (($result['interface_plan']['reset_interfaces'] ?? []) !== [] ||
                ($result['interface_plan']['destroy_vlans'] ?? []) !== []) {
                throw new \RuntimeException(
                    'replacement ownership handoff would reset an interface or destroy a VLAN'
                );
            }

            $this->saveConfig(
                $config,
                $result['config'],
                'Promote accepted HA replica objects to replacement primary ownership'
            );
            $savedNewConfig = true;
            $this->runtimeApply($result['config'], $result['interface_plan']);

            return [
                'status' => 'ok',
                'changed' => true,
                'counts' => $result['counts'],
                'interface_plan' => $result['interface_plan'],
                'haproxy_plan' => $result['haproxy_plan'],
            ];
        } catch (\Throwable $error) {
            if ($savedNewConfig && is_array($previous)) {
                try {
                    $this->saveConfig(
                        $config,
                        $previous,
                        'Rollback failed replacement ownership handoff'
                    );
                    // Reconcile runtime with the restored config. This is
                    // intentionally broad: rollback correctness is more
                    // important than minimizing service restarts.
                    $this->runtimeApply($previous, [
                        'reset_interfaces' => [],
                        'destroy_vlans' => [],
                        'configure_interfaces' => [],
                    ]);
                } catch (\Throwable $rollbackError) {
                    error_log(
                        'Replacement ownership handoff rollback failed: ' .
                        $rollbackError->getMessage()
                    );
                }
            }
            return ['status' => 'failed', 'message' => $error->getMessage()];
        } finally {
            $config->unlock();
        }
    }
}

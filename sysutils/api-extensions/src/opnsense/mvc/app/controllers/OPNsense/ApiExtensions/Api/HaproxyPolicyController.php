<?php

namespace OPNsense\ApiExtensions\Api;

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class HaproxyPolicyController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\\OPNsense\\ApiExtensions\\InterfaceSyncPolicy';
    protected static $internalModelName = 'interface_sync_policy';

    private function resolvePolicyUuid(string $reference, array $policies): ?string
    {
        $reference = trim($reference);
        if (isset($policies[$reference])) {
            return $policies[$reference]['uuid'];
        }
        foreach ($policies as $policy) {
            if (($policy['uuid'] ?? '') === $reference) {
                return $reference;
            }
        }
        return null;
    }

    private function objectKey(string $type, string $name): string
    {
        return trim($type) . ':' . trim($name);
    }

    private function splitObjectKey(string $key): ?array
    {
        $parts = explode(':', trim($key), 2);
        if (count($parts) !== 2 || !in_array($parts[0], ['server', 'backend'], true) || trim($parts[1]) === '') {
            return null;
        }
        return [$parts[0], trim($parts[1])];
    }

    private function objectExists(array $inventory, string $type, string $name): bool
    {
        return isset($inventory['objects'][$this->objectKey($type, $name)]);
    }

    public function searchAssignmentAction(): array
    {
        try {
            $config = Config::getInstance()->toArray();
            $records = [];
            foreach (HAProxySync::assignments($config) as $assignment) {
                $records[] = [
                    'uuid' => (string)($assignment['@attributes']['uuid'] ?? ''),
                    'object_type' => $assignment['object_type'],
                    'object_name' => $assignment['object_name'],
                    'policy_id' => $assignment['policy_id'],
                ];
            }
            return $this->searchRecordsetBase(
                $records,
                ['object_type', 'object_name', 'policy_id'],
                'object_name'
            );
        } catch (\Throwable $error) {
            return ['total' => 0, 'rowCount' => 0, 'current' => 1, 'rows' => [], 'message' => $error->getMessage()];
        }
    }

    public function getAssignmentAction($uuid = null): array
    {
        if ($uuid === null) {
            return ['assignment' => ['object_type' => '', 'object_name' => '', 'policy_id' => '']];
        }
        $node = $this->getModel()->getNodeByReference('haproxy_assignments.assignment.' . $uuid);
        if ($node === null) {
            return [];
        }
        $type = trim((string)$node->object_type->getValue());
        $name = trim((string)$node->object_name->getValue());
        $assignment = HAProxySync::assignments(Config::getInstance()->toArray())[$this->objectKey($type, $name)] ?? null;
        if ($assignment === null) {
            return [];
        }
        return ['assignment' => [
            'object_type' => $assignment['object_type'],
            'object_name' => $assignment['object_name'],
            'policy_id' => $assignment['policy_id'],
        ]];
    }

    public function addAssignmentAction(): array
    {
        if (!$this->request->isPost() || !$this->request->hasPost('assignment')) {
            return ['result' => 'failed'];
        }
        $posted = $this->request->getPost('assignment');
        if (!is_array($posted)) {
            return ['result' => 'failed', 'message' => 'assignment must be an object'];
        }
        $type = trim((string)($posted['object_type'] ?? ''));
        $name = trim((string)($posted['object_name'] ?? ''));
        $config = Config::getInstance()->toArray();
        $inventory = HAProxySync::inventory($config);
        $replicas = HAProxySync::replicas($config);
        $key = $this->objectKey($type, $name);
        if (!$this->objectExists($inventory, $type, $name)) {
            return ['result' => 'failed', 'message' => sprintf('HAProxy %s %s does not exist.', $type, $name)];
        }
        if (isset($replicas[$key])) {
            return ['result' => 'failed', 'message' => sprintf('HA peer replica %s is read-only on this node.', $key)];
        }
        $policies = InterfaceSync::policies($config);
        $policyUuid = $this->resolvePolicyUuid((string)($posted['policy_id'] ?? ''), $policies);
        if ($policyUuid === null) {
            return ['result' => 'failed', 'message' => 'The selected HA sync policy does not exist.'];
        }
        return $this->addBase('assignment', 'haproxy_assignments.assignment', [
            'object_type' => $type,
            'object_name' => $name,
            'policy_id' => $policyUuid,
        ]);
    }

    public function setAssignmentAction($uuid): array
    {
        if (!$this->request->isPost() || !$this->request->hasPost('assignment')) {
            return ['result' => 'failed'];
        }
        $node = $this->getModel()->getNodeByReference('haproxy_assignments.assignment.' . $uuid);
        if ($node === null) {
            return ['result' => 'failed', 'message' => 'HAProxy policy assignment does not exist.'];
        }
        $type = trim((string)$node->object_type->getValue());
        $name = trim((string)$node->object_name->getValue());
        $posted = $this->request->getPost('assignment');
        if (!is_array($posted) ||
            (isset($posted['object_type']) && trim((string)$posted['object_type']) !== $type) ||
            (isset($posted['object_name']) && trim((string)$posted['object_name']) !== $name)) {
            return ['result' => 'failed', 'message' => 'HAProxy assignment object identity is immutable.'];
        }
        $policies = InterfaceSync::policies(Config::getInstance()->toArray());
        $policyUuid = $this->resolvePolicyUuid((string)($posted['policy_id'] ?? ''), $policies);
        if ($policyUuid === null) {
            return ['result' => 'failed', 'message' => 'The selected HA sync policy does not exist.'];
        }
        return $this->setBase('assignment', 'haproxy_assignments.assignment', $uuid, [
            'object_type' => $type,
            'object_name' => $name,
            'policy_id' => $policyUuid,
        ]);
    }

    public function delAssignmentAction($uuid): array
    {
        // API deletion is kept for Terraform teardown. The WebUI only exposes reassignment.
        return $this->delBase('haproxy_assignments.assignment', $uuid);
    }

    private function applyAssignments(array $requested): array
    {
        if (empty($requested)) {
            return ['result' => 'failed', 'message' => 'At least one HAProxy object assignment is required.'];
        }

        Config::getInstance()->lock();
        $config = Config::getInstance()->toArray();
        $policies = InterfaceSync::policies($config);
        $inventory = HAProxySync::inventory($config);
        $replicas = HAProxySync::replicas($config);
        $normalized = [];
        foreach ($requested as $key => $policyId) {
            $parts = $this->splitObjectKey((string)$key);
            $policyId = trim((string)$policyId);
            if ($parts === null || $policyId === '') {
                return ['result' => 'failed', 'message' => 'Every selected HAProxy object must have a policy.'];
            }
            [$type, $name] = $parts;
            $objectKey = $this->objectKey($type, $name);
            if (!$this->objectExists($inventory, $type, $name)) {
                return ['result' => 'failed', 'message' => sprintf('HAProxy %s %s does not exist.', $type, $name)];
            }
            if (isset($replicas[$objectKey])) {
                return ['result' => 'failed', 'message' => sprintf('HA peer replica %s is read-only on this node.', $objectKey)];
            }
            if (!isset($policies[$policyId])) {
                return ['result' => 'failed', 'message' => sprintf('Policy %s does not exist.', $policyId)];
            }
            $normalized[$objectKey] = ['object_type' => $type, 'object_name' => $name, 'policy_id' => $policyId];
        }

        $model = $this->getModel();
        $existing = [];
        foreach ($model->haproxy_assignments->assignment->iterateItems() as $candidate) {
            $key = $this->objectKey(
                (string)$candidate->object_type->getValue(),
                (string)$candidate->object_name->getValue()
            );
            $existing[$key] = $candidate;
        }
        foreach ($normalized as $key => $assignment) {
            $node = $existing[$key] ?? $model->haproxy_assignments->assignment->Add();
            $node->setNodes([
                'object_type' => $assignment['object_type'],
                'object_name' => $assignment['object_name'],
                'policy_id' => $policies[$assignment['policy_id']]['uuid'],
            ]);
        }

        $result = $this->validate(null, null, true);
        if (!empty($result['validations'])) {
            $result['result'] = 'failed';
            return $result;
        }
        $this->save(false, true);
        return ['result' => 'saved', 'count' => count($normalized), 'assignments' => $normalized];
    }

    public function assignAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $type = (string)$this->request->getPost('object_type', 'string', '');
        $name = (string)$this->request->getPost('object_name', 'string', '');
        $policyId = (string)$this->request->getPost('policy_id', 'string', '');
        return $this->applyAssignments([$this->objectKey($type, $name) => $policyId]);
    }

    public function batchAssignAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $requested = $this->request->getPost('assignments');
        if (is_string($requested)) {
            $requested = json_decode($requested, true);
        }
        if (!is_array($requested) || empty($requested)) {
            return ['result' => 'failed', 'message' => 'assignments must be a non-empty object keyed by HAProxy object.'];
        }
        return $this->applyAssignments($requested);
    }

    private function overviewState(): array
    {
        $config = Config::getInstance()->toArray();
        $policies = InterfaceSync::policies($config);
        $assignments = HAProxySync::assignments($config);
        $replicas = HAProxySync::replicas($config);
        $inventory = HAProxySync::inventory($config);
        $rows = [];
        foreach ($inventory['objects'] as $key => $object) {
            $type = $object['object_type'];
            $name = $object['object_name'];
            $raw = $object['row'];
            $policyId = '';
            $owner = 'unassigned';
            if (isset($replicas[$key])) {
                $policyId = $replicas[$key]['policy_id'];
                $owner = 'ha_peer';
            } elseif (isset($assignments[$key])) {
                $policyId = $assignments[$key]['policy_id'];
                $owner = 'local';
            }
            $policy = $policies[$policyId] ?? null;

            if ($type === 'server') {
                $address = trim((string)($raw['address'] ?? ''));
                $port = trim((string)($raw['port'] ?? ''));
                $details = $address . ($port !== '' ? ':' . $port : '');
            } else {
                $serverNames = [];
                foreach (preg_split('/[\s,]+/', trim((string)($raw['linkedServers'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $uuid) {
                    $serverNames[] = $inventory['server_uuid_to_name'][$uuid] ?? '[missing server]';
                }
                $mode = trim((string)($raw['mode'] ?? ''));
                $algorithm = trim((string)($raw['algorithm'] ?? ''));
                $details = trim($mode . ($algorithm !== '' ? ' / ' . $algorithm : '') . ($serverNames ? ' / ' . implode(', ', $serverNames) : ''));
            }

            $rows[] = [
                'uuid' => $key,
                'object_key' => $key,
                'assignment_uuid' => isset($assignments[$key]) ? (string)($assignments[$key]['@attributes']['uuid'] ?? '') : '',
                'object_type' => $type,
                'object_name' => $name,
                'description' => trim((string)($raw['description'] ?? '')),
                'details' => $details,
                'policy_id' => $policyId,
                'policy_description' => is_array($policy) ? $policy['description'] : '',
                'synchronize' => is_array($policy) ? $policy['synchronize'] : false,
                'owner' => $owner,
            ];
        }

        // A HAProxy object can be deleted through the native HAProxy page or an
        // external API client before its policy assignment is removed. Keep that
        // fail-closed assignment visible here so an operator can explicitly
        // remove the stale metadata instead of being blocked by an invisible row.
        foreach ($assignments as $key => $assignment) {
            if (isset($inventory['objects'][$key])) {
                continue;
            }
            $policyId = $assignment['policy_id'];
            $policy = $policies[$policyId] ?? null;
            $rows[] = [
                'uuid' => $key,
                'object_key' => $key,
                'assignment_uuid' => (string)($assignment['@attributes']['uuid'] ?? ''),
                'object_type' => $assignment['object_type'],
                'object_name' => $assignment['object_name'],
                'description' => 'Missing HAProxy object',
                'details' => 'Policy assignment is stale',
                'policy_id' => $policyId,
                'policy_description' => is_array($policy) ? $policy['description'] : '',
                'synchronize' => is_array($policy) ? $policy['synchronize'] : false,
                'owner' => 'stale',
            ];
        }
        usort($rows, fn($a, $b) => [$a['object_type'], $a['object_name']] <=> [$b['object_type'], $b['object_name']]);
        return ['config' => $config, 'policies' => $policies, 'rows' => $rows];
    }

    public function searchOverviewAction(): array
    {
        try {
            $policyFilter = trim((string)$this->request->getPost('policy_id', 'string', ''));
            $typeFilter = trim((string)$this->request->getPost('object_type', 'string', ''));
            $filter = function ($row) use ($policyFilter, $typeFilter) {
                if ($typeFilter !== '' && $typeFilter !== '__all' && ($row['object_type'] ?? '') !== $typeFilter) {
                    return false;
                }
                if ($policyFilter === '__unassigned') {
                    return trim((string)($row['policy_id'] ?? '')) === '';
                }
                if ($policyFilter !== '' && $policyFilter !== '__all' && ($row['policy_id'] ?? '') !== $policyFilter) {
                    return false;
                }
                return true;
            };
            return $this->searchRecordsetBase(
                $this->overviewState()['rows'],
                ['object_type', 'object_name', 'description', 'details', 'policy_id', 'policy_description', 'owner', 'assignment_uuid'],
                'object_name',
                $filter
            );
        } catch (\Throwable $error) {
            return ['total' => 0, 'rowCount' => 0, 'current' => 1, 'rows' => [], 'message' => $error->getMessage()];
        }
    }

    public function overviewAction(): array
    {
        if (!$this->request->isGet()) {
            return ['status' => 'failed', 'message' => 'GET required'];
        }
        try {
            $state = $this->overviewState();
            return [
                'status' => 'ok',
                'ha_service_enabled' => HAProxySync::isEnabled($state['config']),
                'policies' => array_values($state['policies']),
                'unassigned' => count(array_filter($state['rows'], fn($row) => $row['owner'] === 'unassigned')),
                'stale_assignments' => count(array_filter($state['rows'], fn($row) => $row['owner'] === 'stale')),
            ];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => $error->getMessage()];
        }
    }
}

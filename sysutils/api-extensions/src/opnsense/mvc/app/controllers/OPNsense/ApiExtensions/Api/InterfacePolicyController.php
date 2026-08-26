<?php

namespace OPNsense\ApiExtensions\Api;

use OPNsense\ApiExtensions\HAProxySync;
use OPNsense\ApiExtensions\InterfaceSync;
use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class InterfacePolicyController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\\OPNsense\\ApiExtensions\\InterfaceSyncPolicy';
    protected static $internalModelName = 'interface_sync_policy';

    public function searchPolicyAction()
    {
        return $this->searchBase('shared.policies.policy', ['id', 'description', 'synchronize'], 'id');
    }

    public function getPolicyAction($uuid = null)
    {
        return $this->getBase('policy', 'shared.policies.policy', $uuid);
    }

    public function addPolicyAction()
    {
        return $this->addBase('policy', 'shared.policies.policy');
    }

    public function setPolicyAction($uuid)
    {
        return $this->setBase('policy', 'shared.policies.policy', $uuid);
    }

    public function delPolicyAction($uuid)
    {
        if ($this->request->isPost()) {
            $node = $this->getModel()->getNodeByReference('shared.policies.policy.' . $uuid);
            if ($node !== null) {
                $policyId = trim((string)$node->id->getValue());
                $config = Config::getInstance()->toArray();
                foreach (InterfaceSync::assignments($config) as $assignment) {
                    if (($assignment['policy_id'] ?? '') === $policyId) {
                        return ['result' => 'failed', 'message' => 'Policy is assigned to a local interface and cannot be deleted.'];
                    }
                }
                foreach (InterfaceSync::replicas($config) as $replica) {
                    if (($replica['policy_id'] ?? '') === $policyId) {
                        return ['result' => 'failed', 'message' => 'Policy is used by an HA peer interface replica and cannot be deleted.'];
                    }
                }
                foreach (HAProxySync::assignments($config) as $assignment) {
                    if (($assignment['policy_id'] ?? '') === $policyId) {
                        return ['result' => 'failed', 'message' => 'Policy is assigned to a local HAProxy object and cannot be deleted.'];
                    }
                }
                foreach (HAProxySync::replicas($config) as $replica) {
                    if (($replica['policy_id'] ?? '') === $policyId) {
                        return ['result' => 'failed', 'message' => 'Policy is used by an HA peer HAProxy replica and cannot be deleted.'];
                    }
                }
            }
        }
        return $this->delBase('shared.policies.policy', $uuid);
    }

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

    public function searchAssignmentAction()
    {
        try {
            $config = Config::getInstance()->toArray();
            $records = [];
            foreach (InterfaceSync::assignments($config) as $assignment) {
                $records[] = [
                    'uuid' => (string)($assignment['@attributes']['uuid'] ?? ''),
                    'interface' => $assignment['interface'],
                    'policy_id' => $assignment['policy_id'],
                ];
            }
            return $this->searchRecordsetBase($records);
        } catch (\Throwable $error) {
            return ['total' => 0, 'rowCount' => 0, 'current' => 1, 'rows' => [], 'message' => $error->getMessage()];
        }
    }

    public function getAssignmentAction($uuid = null)
    {
        if ($uuid === null) {
            return ['assignment' => ['interface' => '', 'policy_id' => '']];
        }
        $node = $this->getModel()->getNodeByReference('assignments.assignment.' . $uuid);
        if ($node === null) {
            return [];
        }
        $interface = trim((string)$node->interface->getValue());
        $config = Config::getInstance()->toArray();
        $assignment = InterfaceSync::assignments($config)[$interface] ?? null;
        if ($assignment === null) {
            return [];
        }
        return ['assignment' => [
            'interface' => $assignment['interface'],
            'policy_id' => $assignment['policy_id'],
        ]];
    }

    public function addAssignmentAction()
    {
        if (!$this->request->isPost() || !$this->request->hasPost('assignment')) {
            return ['result' => 'failed'];
        }
        $posted = $this->request->getPost('assignment');
        $policies = InterfaceSync::policies(Config::getInstance()->toArray());
        $policyUuid = $this->resolvePolicyUuid((string)($posted['policy_id'] ?? ''), $policies);
        if ($policyUuid === null) {
            return ['result' => 'failed', 'message' => 'The selected interface policy does not exist.'];
        }
        return $this->addBase('assignment', 'assignments.assignment', ['policy_id' => $policyUuid]);
    }

    public function setAssignmentAction($uuid)
    {
        if (!$this->request->isPost() || !$this->request->hasPost('assignment')) {
            return ['result' => 'failed'];
        }
        $posted = $this->request->getPost('assignment');
        $policies = InterfaceSync::policies(Config::getInstance()->toArray());
        $policyUuid = $this->resolvePolicyUuid((string)($posted['policy_id'] ?? ''), $policies);
        if ($policyUuid === null) {
            return ['result' => 'failed', 'message' => 'The selected interface policy does not exist.'];
        }
        return $this->setBase('assignment', 'assignments.assignment', $uuid, ['policy_id' => $policyUuid]);
    }

    public function delAssignmentAction($uuid)
    {
        // Terraform must remove the policy relation before deleting the core interface resource.
        // During that short teardown window InterfaceSync::validateCoverage() makes HA synchronization
        // fail closed. The normal WebUI intentionally exposes reassignment, not assignment deletion.
        return $this->delBase('assignments.assignment', $uuid);
    }

    private function applyAssignments(array $interfaces, string $policyId): array
    {
        $interfaces = array_values(array_unique(array_filter(array_map(
            fn($interface) => trim((string)$interface),
            $interfaces
        ))));
        $policyId = trim($policyId);
        if (empty($interfaces) || $policyId === '') {
            return ['result' => 'failed', 'message' => 'At least one interface and policy_id are required.'];
        }

        Config::getInstance()->lock();
        $config = Config::getInstance()->toArray();
        $policies = InterfaceSync::policies($config);
        $replicas = InterfaceSync::replicas($config);
        if (!isset($policies[$policyId])) {
            return ['result' => 'failed', 'message' => 'The selected interface policy does not exist.'];
        }
        $policyUuid = $policies[$policyId]['uuid'];
        foreach ($interfaces as $interface) {
            if (!isset($config['interfaces'][$interface]) || !is_array($config['interfaces'][$interface])) {
                return ['result' => 'failed', 'message' => sprintf('Interface %s does not exist.', $interface)];
            }
            if (isset($replicas[$interface])) {
                return ['result' => 'failed', 'message' => sprintf('HA peer replica %s is read-only on this node.', $interface)];
            }
        }

        $model = $this->getModel();
        $existing = [];
        foreach ($model->assignments->assignment->iterateItems() as $candidate) {
            $interface = trim((string)$candidate->interface->getValue());
            if ($interface !== '') {
                $existing[$interface] = $candidate;
            }
        }
        foreach ($interfaces as $interface) {
            $node = $existing[$interface] ?? $model->assignments->assignment->Add();
            $node->setNodes(['interface' => $interface, 'policy_id' => $policyUuid]);
        }

        $result = $this->validate(null, null, true);
        if (!empty($result['validations'])) {
            $result['result'] = 'failed';
            return $result;
        }
        $this->save(false, true);
        return [
            'result' => 'saved',
            'count' => count($interfaces),
            'interfaces' => $interfaces,
            'policy_id' => $policyId,
        ];
    }

    public function assignAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        return $this->applyAssignments(
            [(string)$this->request->getPost('interface', 'string', '')],
            (string)$this->request->getPost('policy_id', 'string', '')
        );
    }

    public function batchAssignAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $requested = $this->request->getPost('assignments');
        // The native OPNsense ajaxCall() sends application/json and ApiControllerBase
        // maps JSON objects into POST arrays. Keep string decoding only for API-client
        // compatibility with the short-lived development endpoint.
        if (is_string($requested)) {
            $requested = json_decode($requested, true);
        }
        if (!is_array($requested) || empty($requested)) {
            return ['result' => 'failed', 'message' => 'assignments must be a non-empty object keyed by interface.'];
        }

        Config::getInstance()->lock();
        $config = Config::getInstance()->toArray();
        $policies = InterfaceSync::policies($config);
        $replicas = InterfaceSync::replicas($config);
        $normalized = [];
        foreach ($requested as $interface => $policyId) {
            $interface = trim((string)$interface);
            $policyId = trim((string)$policyId);
            if ($interface === '' || $policyId === '') {
                return ['result' => 'failed', 'message' => 'Every selected interface must have a policy.'];
            }
            if (!isset($config['interfaces'][$interface]) || !is_array($config['interfaces'][$interface])) {
                return ['result' => 'failed', 'message' => sprintf('Interface %s does not exist.', $interface)];
            }
            if (isset($replicas[$interface])) {
                return ['result' => 'failed', 'message' => sprintf('HA peer replica %s is read-only on this node.', $interface)];
            }
            if (!isset($policies[$policyId])) {
                return ['result' => 'failed', 'message' => sprintf('Policy %s does not exist.', $policyId)];
            }
            $normalized[$interface] = $policyId;
        }

        $model = $this->getModel();
        $existing = [];
        foreach ($model->assignments->assignment->iterateItems() as $candidate) {
            $interface = trim((string)$candidate->interface->getValue());
            if ($interface !== '') {
                $existing[$interface] = $candidate;
            }
        }
        foreach ($normalized as $interface => $policyId) {
            $node = $existing[$interface] ?? $model->assignments->assignment->Add();
            $node->setNodes(['interface' => $interface, 'policy_id' => $policies[$policyId]['uuid']]);
        }

        $result = $this->validate(null, null, true);
        if (!empty($result['validations'])) {
            $result['result'] = 'failed';
            return $result;
        }
        $this->save(false, true);
        return [
            'result' => 'saved',
            'count' => count($normalized),
            'assignments' => $normalized,
        ];
    }

    private function overviewState(): array
    {
        $config = Config::getInstance()->toArray();
        $policies = InterfaceSync::policies($config);
        $assignments = InterfaceSync::assignments($config);
        $replicas = InterfaceSync::replicas($config);
        $vlans = [];
        foreach (($config['vlans']['vlan'] ?? []) ?: [] as $vlan) {
            if (is_array($vlan) && trim((string)($vlan['vlanif'] ?? '')) !== '') {
                $vlans[(string)$vlan['vlanif']] = $vlan;
            }
        }

        $rows = [];
        foreach (($config['interfaces'] ?? []) as $identifier => $ifc) {
            if (!is_array($ifc)) {
                continue;
            }
            $device = trim((string)($ifc['if'] ?? ''));
            $policyId = '';
            $owner = 'unassigned';
            if (isset($replicas[$identifier])) {
                $policyId = $replicas[$identifier]['policy_id'];
                $owner = 'ha_peer';
            } elseif (isset($assignments[$identifier])) {
                $policyId = $assignments[$identifier]['policy_id'];
                $owner = 'local';
            }
            $policy = $policies[$policyId] ?? null;
            $rows[] = [
                'uuid' => (string)$identifier,
                'interface' => (string)$identifier,
                'description' => trim((string)($ifc['descr'] ?? '')),
                'device' => $device,
                'vlan' => isset($vlans[$device]) ? (string)($vlans[$device]['tag'] ?? '') : '',
                'policy_id' => $policyId,
                'policy_description' => is_array($policy) ? $policy['description'] : '',
                'synchronize' => is_array($policy) ? $policy['synchronize'] : false,
                'owner' => $owner,
            ];
        }
        usort($rows, fn($a, $b) => strcmp($a['interface'], $b['interface']));

        return [
            'config' => $config,
            'policies' => $policies,
            'rows' => $rows,
        ];
    }

    public function searchOverviewAction(): array
    {
        try {
            $policyFilter = trim((string)$this->request->getPost('policy_id', 'string', ''));
            $filter = null;
            if ($policyFilter === '__unassigned') {
                $filter = fn($row) => trim((string)($row['policy_id'] ?? '')) === '';
            } elseif ($policyFilter !== '' && $policyFilter !== '__all') {
                $filter = fn($row) => (string)($row['policy_id'] ?? '') === $policyFilter;
            }
            return $this->searchRecordsetBase(
                $this->overviewState()['rows'],
                ['interface', 'description', 'device', 'vlan', 'policy_id', 'policy_description', 'owner'],
                'interface',
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
                'ha_service_enabled' => InterfaceSync::isEnabled($state['config']),
                'policies' => array_values($state['policies']),
                'unassigned' => count(array_filter($state['rows'], fn($row) => $row['owner'] === 'unassigned')),
            ];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => $error->getMessage()];
        }
    }
}

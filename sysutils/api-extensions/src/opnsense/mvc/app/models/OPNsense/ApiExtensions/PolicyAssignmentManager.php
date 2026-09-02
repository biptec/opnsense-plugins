<?php

namespace OPNsense\ApiExtensions;

use OPNsense\Core\Config;

/**
 * Shared policy-assignment operations for native object editors.
 *
 * Policy definitions remain owned by System > High Availability > Policies.
 * Native Interfaces and HAProxy pages only select a policy for their own
 * objects. Existing API clients that omit the synthetic policy field remain
 * compatible and can keep managing the relation through the dedicated API.
 */
final class PolicyAssignmentManager
{
    private static function config(): array
    {
        return Config::getInstance()->toArray();
    }

    private static function objectKey(string $type, string $name): string
    {
        return trim($type) . ':' . trim($name);
    }

    private static function resolvePolicy(string $reference, array $policies): array
    {
        $reference = trim($reference);
        if ($reference === '') {
            throw new \InvalidArgumentException('Select an HA policy.');
        }
        if (isset($policies[$reference])) {
            return $policies[$reference];
        }
        foreach ($policies as $policy) {
            if (($policy['uuid'] ?? '') === $reference) {
                return $policy;
            }
        }
        throw new \InvalidArgumentException(sprintf('HA policy %s does not exist.', $reference));
    }

    public static function policies(): array
    {
        return InterfaceSync::policies(self::config());
    }

    public static function interfaceState(string $identifier): array
    {
        $identifier = trim($identifier);
        $config = self::config();
        $policies = InterfaceSync::policies($config);
        $assignments = InterfaceSync::assignments($config);
        $replicas = InterfaceSync::replicas($config);

        $owner = 'unassigned';
        $policyId = '';
        if (isset($replicas[$identifier])) {
            $owner = 'ha_peer';
            $policyId = $replicas[$identifier]['policy_id'];
        } elseif (isset($assignments[$identifier])) {
            $owner = 'local';
            $policyId = $assignments[$identifier]['policy_id'];
        }

        $policy = $policies[$policyId] ?? null;
        return [
            'policy_id' => $policyId,
            'policy_description' => is_array($policy) ? $policy['description'] : '',
            'synchronize' => is_array($policy) ? (bool)$policy['synchronize'] : false,
            'owner' => $owner,
            'ha_service_enabled' => InterfaceSync::isEnabled($config),
        ];
    }

    public static function haproxyState(string $type, string $name): array
    {
        $type = trim($type);
        $name = trim($name);
        $key = self::objectKey($type, $name);
        $config = self::config();
        $policies = InterfaceSync::policies($config);
        $assignments = HAProxySync::assignments($config);
        $replicas = HAProxySync::replicas($config);

        $owner = 'unassigned';
        $policyId = '';
        if (isset($replicas[$key])) {
            $owner = 'ha_peer';
            $policyId = $replicas[$key]['policy_id'];
        } elseif (isset($assignments[$key])) {
            $owner = 'local';
            $policyId = $assignments[$key]['policy_id'];
        }

        $policy = $policies[$policyId] ?? null;
        return [
            'policy_id' => $policyId,
            'policy_description' => is_array($policy) ? $policy['description'] : '',
            'synchronize' => is_array($policy) ? (bool)$policy['synchronize'] : false,
            'owner' => $owner,
            'ha_service_enabled' => HAProxySync::isEnabled($config),
        ];
    }

    public static function validatePolicy(string $reference): array
    {
        return self::resolvePolicy($reference, self::policies());
    }

    private static function saveModel(HASyncPolicy $model, string $description): void
    {
        $model->serializeToConfig(false, false);
        Config::getInstance()->save(['description' => $description]);
    }

    public static function setInterface(string $identifier, string $policyReference): void
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            throw new \InvalidArgumentException('Interface identifier is required for an HA policy assignment.');
        }

        Config::getInstance()->lock();
        $config = self::config();
        if (!isset($config['interfaces'][$identifier]) || !is_array($config['interfaces'][$identifier])) {
            throw new \InvalidArgumentException(sprintf('Interface %s does not exist.', $identifier));
        }
        if (isset(InterfaceSync::replicas($config)[$identifier])) {
            throw new \InvalidArgumentException(sprintf('HA peer replica %s is read-only on this node.', $identifier));
        }

        $policies = InterfaceSync::policies($config);
        $policy = self::resolvePolicy($policyReference, $policies);
        $model = new HASyncPolicy();
        $target = null;
        foreach ($model->assignments->assignment->iterateItems() as $candidate) {
            if (trim((string)$candidate->interface->getValue()) === $identifier) {
                $target = $candidate;
                break;
            }
        }
        $target ??= $model->assignments->assignment->Add();
        $target->setNodes([
            'interface' => $identifier,
            'policy_id' => $policy['uuid'],
        ]);
        self::saveModel($model, sprintf('Set HA policy %s on interface %s', $policy['id'], $identifier));
    }

    public static function removeInterface(string $identifier): void
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            return;
        }

        Config::getInstance()->lock();
        $model = new HASyncPolicy();
        $changed = false;
        foreach ($model->assignments->assignment->iterateItems() as $candidate) {
            if (trim((string)$candidate->interface->getValue()) === $identifier) {
                $model->assignments->assignment->del($candidate->getAttribute('uuid'));
                $changed = true;
                break;
            }
        }
        if ($changed) {
            self::saveModel($model, sprintf('Remove HA policy assignment for interface %s', $identifier));
        }
    }

    public static function assertHAProxyMutable(string $type, string $name): void
    {
        $state = self::haproxyState($type, $name);
        if ($state['owner'] === 'ha_peer') {
            throw new \InvalidArgumentException(sprintf(
                'HA peer replica %s is read-only on this node.',
                self::objectKey($type, $name)
            ));
        }
    }

    public static function setHAProxy(
        string $type,
        string $name,
        string $policyReference,
        ?string $previousName = null
    ): void {
        $type = trim($type);
        $name = trim($name);
        $previousName = trim((string)($previousName ?? $name));
        if (!in_array($type, ['healthcheck', 'server', 'backend'], true) || $name === '') {
            throw new \InvalidArgumentException('HAProxy policy assignment requires a healthcheck, server or backend name.');
        }

        Config::getInstance()->lock();
        $config = self::config();
        $inventory = HAProxySync::inventory($config);
        $key = self::objectKey($type, $name);
        if (!isset($inventory['objects'][$key])) {
            throw new \InvalidArgumentException(sprintf('HAProxy %s %s does not exist.', $type, $name));
        }
        if (isset(HAProxySync::replicas($config)[$key])) {
            throw new \InvalidArgumentException(sprintf('HA peer replica %s is read-only on this node.', $key));
        }

        $policies = InterfaceSync::policies($config);
        $policy = self::resolvePolicy($policyReference, $policies);
        $model = new HASyncPolicy();
        $target = null;
        foreach ($model->haproxy_assignments->assignment->iterateItems() as $candidate) {
            $candidateType = trim((string)$candidate->object_type->getValue());
            $candidateName = trim((string)$candidate->object_name->getValue());
            if ($candidateType === $type && ($candidateName === $name || $candidateName === $previousName)) {
                $target = $candidate;
                break;
            }
        }
        $target ??= $model->haproxy_assignments->assignment->Add();
        $target->setNodes([
            'object_type' => $type,
            'object_name' => $name,
            'policy_id' => $policy['uuid'],
        ]);
        self::saveModel($model, sprintf('Set HA policy %s on HAProxy %s %s', $policy['id'], $type, $name));
    }

    public static function renameHAProxy(string $type, string $previousName, string $name): void
    {
        $previousName = trim($previousName);
        $name = trim($name);
        if ($previousName === '' || $name === '' || $previousName === $name) {
            return;
        }

        $config = self::config();
        $assignments = HAProxySync::assignments($config);
        $previousKey = self::objectKey($type, $previousName);
        if (!isset($assignments[$previousKey])) {
            return;
        }
        self::setHAProxy($type, $name, $assignments[$previousKey]['policy_id'], $previousName);
    }

    public static function removeHAProxy(string $type, string $name): void
    {
        $type = trim($type);
        $name = trim($name);
        if ($name === '') {
            return;
        }

        Config::getInstance()->lock();
        $model = new HASyncPolicy();
        $changed = false;
        foreach ($model->haproxy_assignments->assignment->iterateItems() as $candidate) {
            if (
                trim((string)$candidate->object_type->getValue()) === $type &&
                trim((string)$candidate->object_name->getValue()) === $name
            ) {
                $model->haproxy_assignments->assignment->del($candidate->getAttribute('uuid'));
                $changed = true;
                break;
            }
        }
        if ($changed) {
            self::saveModel($model, sprintf('Remove HA policy assignment for HAProxy %s %s', $type, $name));
        }
    }
}

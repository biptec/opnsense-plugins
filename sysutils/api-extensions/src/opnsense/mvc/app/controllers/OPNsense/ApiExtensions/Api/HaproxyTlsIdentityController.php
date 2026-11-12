<?php

namespace OPNsense\ApiExtensions\Api;

use OPNsense\ApiExtensions\HAProxyTLSIdentitySync;
use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class HaproxyTlsIdentityController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\\OPNsense\\ApiExtensions\\HAProxyTLSIdentity';
    protected static $internalModelName = 'haproxy_tls_identity';

    private function postedIdentity(): ?array
    {
        if (!$this->request->isPost() || !$this->request->hasPost('identity')) {
            return null;
        }
        $posted = $this->request->getPost('identity');
        return is_array($posted) ? $posted : null;
    }

    private function normalizedRegistration(array $posted): array
    {
        return HAProxyTLSIdentitySync::validateLocalRegistration(
            Config::getInstance()->toArray(),
            $posted['frontend_name'] ?? '',
            $posted['dns_name'] ?? '',
            $posted['policy_id'] ?? ''
        );
    }

    protected function setBaseHook($node)
    {
        $config = Config::getInstance()->toArray();
        $registration = HAProxyTLSIdentitySync::validateLocalRegistration(
            $config,
            (string)$node->frontend_name->getValue(),
            (string)$node->dns_name->getValue(),
            (string)$node->policy_id->getValue()
        );

        $key = $registration['frontend_name'] . '|' . $registration['dns_name'];
        $count = 0;
        foreach ($this->getModel()->identities->identity->iterateItems() as $candidate) {
            $candidateRegistration = HAProxyTLSIdentitySync::validateLocalRegistration(
                $config,
                (string)$candidate->frontend_name->getValue(),
                (string)$candidate->dns_name->getValue(),
                (string)$candidate->policy_id->getValue()
            );
            if ($candidateRegistration['frontend_name'] . '|' . $candidateRegistration['dns_name'] === $key) {
                $count++;
            }
        }
        if ($count !== 1) {
            throw new \InvalidArgumentException('HAProxy TLS identity frontend + DNS pair must be unique');
        }

        // Once this capability is used, an empty identity set is authoritative
        // during HA synchronization. Never clear this marker on deletion.
        $this->getModel()->sync_marker->enabled = '1';
    }

    public function searchIdentityAction(): array
    {
        try {
            $records = [];
            foreach (HAProxyTLSIdentitySync::identities(Config::getInstance()->toArray()) as $identity) {
                $records[] = [
                    'uuid' => (string)($identity['@attributes']['uuid'] ?? ''),
                    'frontend_name' => $identity['frontend_name'],
                    'dns_name' => $identity['dns_name'],
                    'policy_id' => $identity['policy_id'],
                ];
            }
            return $this->searchRecordsetBase(
                $records,
                ['frontend_name', 'dns_name', 'policy_id'],
                'dns_name'
            );
        } catch (\Throwable $error) {
            return [
                'total' => 0,
                'rowCount' => 0,
                'current' => 1,
                'rows' => [],
                'message' => $error->getMessage(),
            ];
        }
    }

    public function getIdentityAction($uuid = null): array
    {
        if ($uuid === null) {
            return ['identity' => ['frontend_name' => '', 'dns_name' => '', 'policy_id' => '']];
        }
        try {
            foreach (HAProxyTLSIdentitySync::identities(Config::getInstance()->toArray()) as $identity) {
                if ((string)($identity['@attributes']['uuid'] ?? '') !== (string)$uuid) {
                    continue;
                }
                return ['identity' => [
                    'frontend_name' => $identity['frontend_name'],
                    'dns_name' => $identity['dns_name'],
                    'policy_id' => $identity['policy_id'],
                ]];
            }
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'message' => $error->getMessage()];
        }
        return [];
    }

    public function addIdentityAction(): array
    {
        $posted = $this->postedIdentity();
        if ($posted === null) {
            return ['result' => 'failed', 'message' => 'identity must be an object'];
        }
        try {
            $registration = $this->normalizedRegistration($posted);
            return $this->addBase('identity', 'identities.identity', [
                'frontend_name' => $registration['frontend_name'],
                'dns_name' => $registration['dns_name'],
                'policy_id' => $registration['policy_uuid'],
            ]);
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function setIdentityAction($uuid): array
    {
        $posted = $this->postedIdentity();
        if ($posted === null) {
            return ['result' => 'failed', 'message' => 'identity must be an object'];
        }

        $current = $this->getIdentityAction($uuid)['identity'] ?? null;
        if (!is_array($current)) {
            return ['result' => 'failed', 'message' => 'HAProxy TLS identity does not exist'];
        }
        foreach (['frontend_name', 'dns_name'] as $field) {
            if (array_key_exists($field, $posted) &&
                strtolower(rtrim(trim((string)$posted[$field]), '.')) !==
                strtolower(rtrim(trim((string)$current[$field]), '.'))) {
                return ['result' => 'failed', 'message' => 'HAProxy TLS identity frontend_name and dns_name are immutable'];
            }
        }

        try {
            $registration = $this->normalizedRegistration([
                'frontend_name' => $current['frontend_name'],
                'dns_name' => $current['dns_name'],
                'policy_id' => $posted['policy_id'] ?? $current['policy_id'],
            ]);
            return $this->setBase('identity', 'identities.identity', $uuid, [
                'frontend_name' => $registration['frontend_name'],
                'dns_name' => $registration['dns_name'],
                'policy_id' => $registration['policy_uuid'],
            ]);
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function delIdentityAction($uuid): array
    {
        try {
            return $this->delBase('identities.identity', $uuid);
        } catch (\Throwable $error) {
            return ['result' => 'failed', 'message' => $error->getMessage()];
        }
    }

    public function reconfigureAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $raw = trim((new Backend())->configdRun('api_extensions haproxy_tls_identity_reconcile'));
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [
                'status' => 'failed',
                'message' => 'HAProxy TLS identity reconciler returned invalid JSON',
                'result' => $raw,
            ];
        }
        return $decoded;
    }
}

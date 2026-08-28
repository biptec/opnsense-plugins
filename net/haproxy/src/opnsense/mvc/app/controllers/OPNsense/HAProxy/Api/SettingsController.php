<?php

/**
 *    Copyright (C) 2016-2026 Frank Wall
 *    Copyright (C) 2015 Deciso B.V.
 *
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace OPNsense\HAProxy\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UIModelGrid;
use OPNsense\Core\Config;
use OPNsense\HAProxy\HAProxy;

/**
 * Class SettingsController
 * @package OPNsense\HAProxy
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'haproxy';
    protected static $internalModelClass = '\OPNsense\HAProxy\HAProxy';
    protected static $internalModelUseSafeDelete = true;

    private function hasPolicyManager(): bool
    {
        return class_exists('\\OPNsense\\ApiExtensions\\PolicyAssignmentManager');
    }

    private function policyPayload(string $root): ?string
    {
        if (!$this->hasPolicyManager() || !$this->request->isPost() || !$this->request->hasPost($root)) {
            return null;
        }
        $payload = $this->request->getPost($root);
        if (!is_array($payload) || !array_key_exists('ha_policy', $payload)) {
            return null;
        }
        return trim((string)$payload['ha_policy']);
    }

    private function validatePolicyPayload(string $root): ?array
    {
        $policy = $this->policyPayload($root);
        if ($policy === null) {
            return null;
        }
        try {
            \OPNsense\ApiExtensions\PolicyAssignmentManager::validatePolicy($policy);
        } catch (\Throwable $error) {
            return [
                'result' => 'failed',
                'validations' => [
                    $root . '.ha_policy' => $error->getMessage()
                ]
            ];
        }
        return null;
    }

    private function objectName(string $type, string $uuid): string
    {
        $path = $type === 'server' ? 'servers.server.' : 'backends.backend.';
        $node = $this->getModel()->getNodeByReference($path . $uuid);
        return $node === null ? '' : trim((string)$node->name->getValue());
    }

    private function policyState(string $type, string $name): array
    {
        if (!$this->hasPolicyManager() || $name === '') {
            return [
                'policy_id' => '',
                'policy_description' => '',
                'synchronize' => false,
                'owner' => 'unassigned',
                'ha_service_enabled' => false,
            ];
        }
        return \OPNsense\ApiExtensions\PolicyAssignmentManager::haproxyState($type, $name);
    }

    private function enrichPolicyGet(array $result, string $root, string $type): array
    {
        if (!isset($result[$root]) || !is_array($result[$root])) {
            return $result;
        }
        $state = $this->policyState($type, trim((string)($result[$root]['name'] ?? '')));
        $options = [];
        if ($this->hasPolicyManager()) {
            foreach (\OPNsense\ApiExtensions\PolicyAssignmentManager::policies() as $policy) {
                $label = $policy['id'];
                if (!empty($policy['description'])) {
                    $label .= ' — ' . $policy['description'];
                }
                $options[$policy['id']] = [
                    'value' => $label,
                    'selected' => $policy['id'] === $state['policy_id'] ? 1 : 0,
                ];
            }
        }
        $result[$root]['ha_policy'] = $options;
        $result[$root]['ha_owner'] = $state['owner'];
        $result[$root]['ha_synchronize'] = $state['synchronize'] ? '1' : '0';
        return $result;
    }

    private function enrichPolicySearch(array $result, string $type): array
    {
        if (!isset($result['rows']) || !is_array($result['rows'])) {
            return $result;
        }
        foreach ($result['rows'] as &$row) {
            $state = $this->policyState($type, trim((string)($row['name'] ?? '')));
            $row['ha_policy'] = $state['policy_id'];
            $row['ha_owner'] = $state['owner'];
            $row['ha_synchronize'] = $state['synchronize'] ? '1' : '0';
        }
        unset($row);
        return $result;
    }

    private function readonlyReplica(string $type, string $name, string $root): ?array
    {
        if (!$this->hasPolicyManager() || $name === '') {
            return null;
        }
        $state = $this->policyState($type, $name);
        if ($state['owner'] !== 'ha_peer') {
            return null;
        }
        return [
            'result' => 'failed',
            'validations' => [
                $root . '.ha_policy' => gettext('This object is an HA peer replica and is read-only on this node.')
            ]
        ];
    }

    public function getFrontendAction($uuid = null)
    {
        return $this->getBase('frontend', 'frontends.frontend', $uuid);
    }

    public function setFrontendAction($uuid)
    {
        return $this->setBase('frontend', 'frontends.frontend', $uuid);
    }

    public function addFrontendAction()
    {
        return $this->addBase('frontend', 'frontends.frontend');
    }

    public function delFrontendAction($uuid)
    {
        return $this->delBase('frontends.frontend', $uuid);
    }

    public function toggleFrontendAction($uuid)
    {
        return $this->toggleBase('frontends.frontend', $uuid);
    }

    public function searchFrontendsAction()
    {
        return $this->searchBase('frontends.frontend', array('enabled', 'name', 'description'), 'name');
    }

    public function getBackendAction($uuid = null)
    {
        return $this->enrichPolicyGet($this->getBase('backend', 'backends.backend', $uuid), 'backend', 'backend');
    }

    public function setBackendAction($uuid)
    {
        $oldName = $this->objectName('backend', $uuid);
        if (($readonly = $this->readonlyReplica('backend', $oldName, 'backend')) !== null) {
            return $readonly;
        }
        if (($validation = $this->validatePolicyPayload('backend')) !== null) {
            return $validation;
        }
        $payload = $this->request->hasPost('backend') ? $this->request->getPost('backend') : [];
        $newName = is_array($payload) && !empty($payload['name']) ? trim((string)$payload['name']) : $oldName;
        $policy = $this->policyPayload('backend');
        $result = $this->setBase('backend', 'backends.backend', $uuid);
        if (($result['result'] ?? '') === 'saved' && $this->hasPolicyManager()) {
            try {
                if ($policy !== null) {
                    \OPNsense\ApiExtensions\PolicyAssignmentManager::setHAProxy('backend', $newName, $policy, $oldName);
                } else {
                    \OPNsense\ApiExtensions\PolicyAssignmentManager::renameHAProxy('backend', $oldName, $newName);
                }
            } catch (\Throwable $error) {
                return ['result' => 'failed', 'validations' => ['backend.ha_policy' => $error->getMessage()]];
            }
        }
        return $result;
    }

    public function addBackendAction()
    {
        if (($validation = $this->validatePolicyPayload('backend')) !== null) {
            return $validation;
        }
        $payload = $this->request->hasPost('backend') ? $this->request->getPost('backend') : [];
        $name = is_array($payload) ? trim((string)($payload['name'] ?? '')) : '';
        $policy = $this->policyPayload('backend');
        $result = $this->addBase('backend', 'backends.backend');
        if (($result['result'] ?? '') === 'saved' && $policy !== null && $this->hasPolicyManager()) {
            try {
                \OPNsense\ApiExtensions\PolicyAssignmentManager::setHAProxy('backend', $name, $policy);
            } catch (\Throwable $error) {
                if (!empty($result['uuid'])) {
                    $this->delBase('backends.backend', $result['uuid']);
                }
                return ['result' => 'failed', 'validations' => ['backend.ha_policy' => $error->getMessage()]];
            }
        }
        return $result;
    }

    public function delBackendAction($uuid)
    {
        $names = [];
        foreach (explode(',', (string)$uuid) as $itemUuid) {
            $name = $this->objectName('backend', trim($itemUuid));
            if (($readonly = $this->readonlyReplica('backend', $name, 'backend')) !== null) {
                return $readonly;
            }
            if ($name !== '') {
                $names[] = $name;
            }
        }
        $result = $this->delBase('backends.backend', $uuid);
        if (($result['result'] ?? '') === 'deleted' && $this->hasPolicyManager()) {
            foreach ($names as $name) {
                \OPNsense\ApiExtensions\PolicyAssignmentManager::removeHAProxy('backend', $name);
            }
        }
        return $result;
    }

    public function toggleBackendAction($uuid, $enabled = null)
    {
        $name = $this->objectName('backend', $uuid);
        if (($readonly = $this->readonlyReplica('backend', $name, 'backend')) !== null) {
            return $readonly;
        }
        return $this->toggleBase('backends.backend', $uuid);
    }

    public function searchBackendsAction()
    {
        return $this->enrichPolicySearch(
            $this->searchBase('backends.backend', array('enabled', 'name', 'description'), 'name'),
            'backend'
        );
    }

    public function getServerAction($uuid = null)
    {
        return $this->enrichPolicyGet($this->getBase('server', 'servers.server', $uuid), 'server', 'server');
    }

    public function setServerAction($uuid)
    {
        $oldName = $this->objectName('server', $uuid);
        if (($readonly = $this->readonlyReplica('server', $oldName, 'server')) !== null) {
            return $readonly;
        }
        if (($validation = $this->validatePolicyPayload('server')) !== null) {
            return $validation;
        }
        $payload = $this->request->hasPost('server') ? $this->request->getPost('server') : [];
        $newName = is_array($payload) && !empty($payload['name']) ? trim((string)$payload['name']) : $oldName;
        $policy = $this->policyPayload('server');
        $result = $this->setBase('server', 'servers.server', $uuid);
        if (($result['result'] ?? '') === 'saved' && $this->hasPolicyManager()) {
            try {
                if ($policy !== null) {
                    \OPNsense\ApiExtensions\PolicyAssignmentManager::setHAProxy('server', $newName, $policy, $oldName);
                } else {
                    \OPNsense\ApiExtensions\PolicyAssignmentManager::renameHAProxy('server', $oldName, $newName);
                }
            } catch (\Throwable $error) {
                return ['result' => 'failed', 'validations' => ['server.ha_policy' => $error->getMessage()]];
            }
        }
        return $result;
    }

    public function addServerAction()
    {
        if (($validation = $this->validatePolicyPayload('server')) !== null) {
            return $validation;
        }
        $payload = $this->request->hasPost('server') ? $this->request->getPost('server') : [];
        $name = is_array($payload) ? trim((string)($payload['name'] ?? '')) : '';
        $policy = $this->policyPayload('server');
        $result = $this->addBase('server', 'servers.server');
        if (($result['result'] ?? '') === 'saved' && $policy !== null && $this->hasPolicyManager()) {
            try {
                \OPNsense\ApiExtensions\PolicyAssignmentManager::setHAProxy('server', $name, $policy);
            } catch (\Throwable $error) {
                if (!empty($result['uuid'])) {
                    $this->delBase('servers.server', $result['uuid']);
                }
                return ['result' => 'failed', 'validations' => ['server.ha_policy' => $error->getMessage()]];
            }
        }
        return $result;
    }

    public function delServerAction($uuid)
    {
        $names = [];
        foreach (explode(',', (string)$uuid) as $itemUuid) {
            $name = $this->objectName('server', trim($itemUuid));
            if (($readonly = $this->readonlyReplica('server', $name, 'server')) !== null) {
                return $readonly;
            }
            if ($name !== '') {
                $names[] = $name;
            }
        }
        $result = $this->delBase('servers.server', $uuid);
        if (($result['result'] ?? '') === 'deleted' && $this->hasPolicyManager()) {
            foreach ($names as $name) {
                \OPNsense\ApiExtensions\PolicyAssignmentManager::removeHAProxy('server', $name);
            }
        }
        return $result;
    }

    public function toggleServerAction($uuid, $enabled = null)
    {
        $name = $this->objectName('server', $uuid);
        if (($readonly = $this->readonlyReplica('server', $name, 'server')) !== null) {
            return $readonly;
        }
        return $this->toggleBase('servers.server', $uuid);
    }

    public function searchServersAction()
    {
        return $this->enrichPolicySearch(
            $this->searchBase('servers.server', array('enabled', 'name', 'type', 'mode', 'address', 'port', 'description'), 'name'),
            'server'
        );
    }

    public function getHealthcheckAction($uuid = null)
    {
        return $this->getBase('healthcheck', 'healthchecks.healthcheck', $uuid);
    }

    public function setHealthcheckAction($uuid)
    {
        return $this->setBase('healthcheck', 'healthchecks.healthcheck', $uuid);
    }

    public function addHealthcheckAction()
    {
        return $this->addBase('healthcheck', 'healthchecks.healthcheck');
    }

    public function delHealthcheckAction($uuid)
    {
        return $this->delBase('healthchecks.healthcheck', $uuid);
    }

    public function searchHealthchecksAction()
    {
        return $this->searchBase('healthchecks.healthcheck', array('name', 'description'), 'name');
    }

    public function getAclAction($uuid = null)
    {
        return $this->getBase('acl', 'acls.acl', $uuid);
    }

    public function setAclAction($uuid)
    {
        return $this->setBase('acl', 'acls.acl', $uuid);
    }

    public function addAclAction()
    {
        return $this->addBase('acl', 'acls.acl');
    }

    public function delAclAction($uuid)
    {
        return $this->delBase('acls.acl', $uuid);
    }

    public function searchAclsAction()
    {
        return $this->searchBase('acls.acl', array('name', 'description'), 'name');
    }

    public function getActionAction($uuid = null)
    {
        return $this->getBase('action', 'actions.action', $uuid);
    }

    public function setActionAction($uuid)
    {
        return $this->setBase('action', 'actions.action', $uuid);
    }

    public function addActionAction()
    {
        return $this->addBase('action', 'actions.action');
    }

    public function delActionAction($uuid)
    {
        return $this->delBase('actions.action', $uuid);
    }

    public function toggleActionAction($uuid, $enabled = null)
    {
        return $this->toggleBase('actions.action', $uuid);
    }

    public function searchActionsAction()
    {
        return $this->searchBase('actions.action', array('enabled', 'name', 'description'), 'name');
    }

    public function getLuaAction($uuid = null)
    {
        return $this->getBase('lua', 'luas.lua', $uuid);
    }

    public function setLuaAction($uuid)
    {
        return $this->setBase('lua', 'luas.lua', $uuid);
    }

    public function addLuaAction()
    {
        return $this->addBase('lua', 'luas.lua');
    }

    public function delLuaAction($uuid)
    {
        return $this->delBase('luas.lua', $uuid);
    }

    public function toggleLuaAction($uuid, $enabled = null)
    {
        return $this->toggleBase('luas.lua', $uuid);
    }

    public function searchLuasAction()
    {
        return $this->searchBase('luas.lua', array('enabled', 'name', 'description'), 'name');
    }

    public function getFcgiAction($uuid = null)
    {
        return $this->getBase('fcgi', 'fcgis.fcgi', $uuid);
    }

    public function setFcgiAction($uuid)
    {
        return $this->setBase('fcgi', 'fcgis.fcgi', $uuid);
    }

    public function addFcgiAction()
    {
        return $this->addBase('fcgi', 'fcgis.fcgi');
    }

    public function delFcgiAction($uuid)
    {
        return $this->delBase('fcgis.fcgi', $uuid);
    }

    public function searchFcgisAction()
    {
        return $this->searchBase('fcgis.fcgi', array('name', 'description'), 'name');
    }

    public function getErrorfileAction($uuid = null)
    {
        return $this->getBase('errorfile', 'errorfiles.errorfile', $uuid);
    }

    public function setErrorfileAction($uuid)
    {
        return $this->setBase('errorfile', 'errorfiles.errorfile', $uuid);
    }

    public function addErrorfileAction()
    {
        return $this->addBase('errorfile', 'errorfiles.errorfile');
    }

    public function delErrorfileAction($uuid)
    {
        return $this->delBase('errorfiles.errorfile', $uuid);
    }

    public function searchErrorfilesAction()
    {
        return $this->searchBase('errorfiles.errorfile', array('name', 'description'), 'name');
    }

    public function getMapfileAction($uuid = null)
    {
        return $this->getBase('mapfile', 'mapfiles.mapfile', $uuid);
    }

    public function setMapfileAction($uuid)
    {
        return $this->setBase('mapfile', 'mapfiles.mapfile', $uuid);
    }

    public function addMapfileAction()
    {
        return $this->addBase('mapfile', 'mapfiles.mapfile');
    }

    public function delMapfileAction($uuid)
    {
        return $this->delBase('mapfiles.mapfile', $uuid);
    }

    public function searchMapfilesAction()
    {
        return $this->searchBase('mapfiles.mapfile', array('name', 'description'), 'name');
    }

    public function getCpuAction($uuid = null)
    {
        return $this->getBase('cpu', 'cpus.cpu', $uuid);
    }

    public function setCpuAction($uuid)
    {
        return $this->setBase('cpu', 'cpus.cpu', $uuid);
    }

    public function addCpuAction()
    {
        return $this->addBase('cpu', 'cpus.cpu');
    }

    public function delCpuAction($uuid)
    {
        return $this->delBase('cpus.cpu', $uuid);
    }

    public function toggleCpuAction($uuid, $enabled = null)
    {
        return $this->toggleBase('cpus.cpu', $uuid);
    }

    public function searchCpusAction()
    {
        return $this->searchBase('cpus.cpu', array('enabled', 'name', 'thread_id', 'cpu_id'), 'name');
    }

    public function getGroupAction($uuid = null)
    {
        return $this->getBase('group', 'groups.group', $uuid);
    }

    public function setGroupAction($uuid)
    {
        return $this->setBase('group', 'groups.group', $uuid);
    }

    public function addGroupAction()
    {
        return $this->addBase('group', 'groups.group');
    }

    public function delGroupAction($uuid)
    {
        return $this->delBase('groups.group', $uuid);
    }

    public function toggleGroupAction($uuid, $enabled = null)
    {
        return $this->toggleBase('groups.group', $uuid);
    }

    public function searchGroupsAction()
    {
        return $this->searchBase('groups.group', array('enabled', 'name', 'description'), 'name');
    }

    public function getUserAction($uuid = null)
    {
        return $this->getBase('user', 'users.user', $uuid);
    }

    public function setUserAction($uuid)
    {
        return $this->setBase('user', 'users.user', $uuid);
    }

    public function addUserAction()
    {
        return $this->addBase('user', 'users.user');
    }

    public function delUserAction($uuid)
    {
        return $this->delBase('users.user', $uuid);
    }

    public function toggleUserAction($uuid, $enabled = null)
    {
        return $this->toggleBase('users.user', $uuid);
    }

    public function searchUsersAction()
    {
        return $this->searchBase('users.user', array('enabled', 'name', 'description'), 'name');
    }

    public function getresolverAction($uuid = null)
    {
        return $this->getBase('resolver', 'resolvers.resolver', $uuid);
    }

    public function setresolverAction($uuid)
    {
        return $this->setBase('resolver', 'resolvers.resolver', $uuid);
    }

    public function addresolverAction()
    {
        return $this->addBase('resolver', 'resolvers.resolver');
    }

    public function delresolverAction($uuid)
    {
        return $this->delBase('resolvers.resolver', $uuid);
    }

    public function toggleresolverAction($uuid, $enabled = null)
    {
        return $this->toggleBase('resolvers.resolver', $uuid);
    }

    public function searchresolversAction()
    {
        return $this->searchBase('resolvers.resolver', array('enabled', 'name', 'nameservers'), 'name');
    }

    public function getmailerAction($uuid = null)
    {
        return $this->getBase('mailer', 'mailers.mailer', $uuid);
    }

    public function setmailerAction($uuid)
    {
        return $this->setBase('mailer', 'mailers.mailer', $uuid);
    }

    public function addmailerAction()
    {
        return $this->addBase('mailer', 'mailers.mailer');
    }

    public function delmailerAction($uuid)
    {
        return $this->delBase('mailers.mailer', $uuid);
    }

    public function togglemailerAction($uuid, $enabled = null)
    {
        return $this->toggleBase('mailers.mailer', $uuid);
    }

    public function searchmailersAction()
    {
        return $this->searchBase('mailers.mailer', array('enabled', 'name', 'mailservers', 'sender', 'recipient'), 'name');
    }
}

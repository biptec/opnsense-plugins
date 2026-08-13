<?php

/**
 *    Copyright (C) 2018 Michael Muenz <m.muenz@gmail.com>
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

namespace OPNsense\Bind\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Bind\Domain;
use OPNsense\Bind\View;

class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\Bind\General';
    protected static $internalModelName = 'general';

    protected function getModelNodes()
    {
        $nodes = parent::getModelNodes();
        unset($nodes['rndcsecret']);
        return $nodes;
    }

    public function setAction()
    {
        $result = ['result' => 'failed'];
        if ($this->request->isPost()) {
            Config::getInstance()->lock();
            $model = $this->getModel();
            $currentSecret = (string)$model->rndcsecret;
            $settings = $this->request->getPost(static::$internalModelName);
            if (!is_array($settings)) {
                $settings = [];
            }
            if (empty($settings['rndcsecret'])) {
                $settings['rndcsecret'] = $currentSecret;
            }
            $model->setNodes($settings);
            $result = $this->validate();
            if (empty($result['result'])) {
                $this->setActionHook();
                return $this->save(false, true);
            }
        }
        return $result;
    }

    private function getZoneRequest()
    {
        if (!$this->request->hasPost("zone") || !$this->request->hasPost("uuid")) {
            return null;
        }
        $uuid = $this->request->getPost("uuid");
        if (!preg_match('/^[0-9a-fA-F-]+$/', $uuid)) {
            return null;
        }
        $model = new Domain();
        $node = $model->getNodeByReference('domains.domain.' . $uuid);
        if ($node === null || (string)$node->domainname !== $this->request->getPost("zone")) {
            return null;
        }
        return [(string)$node->domainname, $uuid];
    }

    public function zonetestAction($zonename = null)
    {
        $zone = $this->getZoneRequest();
        if ($zone === null) {
            return ["response" => "request error"];
        }
        $backend = new Backend();
        return ["response" => trim($backend->configdpRun("bind zone check", $zone))];
    }

    public function zoneshowAction($zonename = null)
    {
        $zone = $this->getZoneRequest();
        if ($zone === null) {
            return [];
        }
        $backend = new Backend();
        return json_decode($backend->configdpRun("bind zone show", [$zone[1]]), true) ?? [];
    }

    public function dnssecStatusAction()
    {
        $zone = $this->getZoneRequest();
        if ($zone === null) {
            return ["error" => "request error"];
        }
        $model = new Domain();
        $node = $model->getNodeByReference('domains.domain.' . $zone[1]);
        if ($node === null || (string)$node->type !== 'primary' || (string)$node->dnssec !== '1') {
            return ["error" => "DNSSEC is not enabled for this primary zone"];
        }

        $viewName = '__default__';
        $viewUuid = (string)$node->view;
        if ($viewUuid !== '') {
            $viewModel = new View();
            $viewNode = $viewModel->getNodeByReference('views.view.' . $viewUuid);
            if ($viewNode === null || (string)$viewNode->enabled !== '1') {
                return ["error" => "zone view is missing or disabled"];
            }
            $viewName = (string)$viewNode->name;
        }

        $backend = new Backend();
        return json_decode(
            $backend->configdpRun('bind dnssec status', [$zone[0], $viewName]),
            true
        ) ?? ["error" => "empty backend response"];
    }

}

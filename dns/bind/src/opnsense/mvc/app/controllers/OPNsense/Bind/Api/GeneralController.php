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
use OPNsense\Bind\Domain;

class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\Bind\General';
    protected static $internalModelName = 'general';

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

}

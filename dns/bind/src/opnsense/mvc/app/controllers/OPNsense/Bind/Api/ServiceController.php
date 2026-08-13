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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\Bind\General;
use OPNsense\Bind\Dnsbl;
use OPNsense\Bind\Domain;
use OPNsense\Bind\Tsig;
use OPNsense\Bind\View;

/**
 * Class ServiceController
 * @package OPNsense\Bind
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Bind\General';
    protected static $internalServiceTemplate = 'OPNsense/Bind';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'bind';


    private function validateConfiguration()
    {
        $viewModel = new View();
        $viewRoot = $viewModel->getNodeByReference('views.view');
        $enabledViews = [];
        $sequences = [];
        $matchAnyViews = [];

        if ($viewRoot !== null) {
            foreach ($viewRoot->iterateItems() as $view) {
                if ((string)$view->enabled !== '1') {
                    continue;
                }
                $uuid = $view->getAttribute('uuid');
                $sequence = (int)(string)$view->sequence;
                $name = (string)$view->name;
                if ((string)$view->matchany !== '1' && (string)$view->matchclients === '') {
                    throw new UserException(
                        sprintf(gettext('BIND view "%s" has no matching clients.'), $name),
                        gettext('Configuration exception')
                    );
                }
                if (isset($sequences[$sequence])) {
                    throw new UserException(
                        sprintf(
                            gettext('BIND views "%s" and "%s" use the same sequence.'),
                            $sequences[$sequence],
                            $name
                        ),
                        gettext('Configuration exception')
                    );
                }
                $sequences[$sequence] = $name;
                $enabledViews[$uuid] = [
                    'name' => $name,
                    'sequence' => $sequence,
                    'matchany' => (string)$view->matchany === '1'
                ];
                if ((string)$view->matchany === '1') {
                    $matchAnyViews[] = $uuid;
                }
            }
        }

        if (count($matchAnyViews) > 1) {
            throw new UserException(
                gettext('Only one enabled BIND view may match every client.'),
                gettext('Configuration exception')
            );
        }
        if (count($matchAnyViews) === 1) {
            $matchAnyUuid = $matchAnyViews[0];
            $highestSequence = max(array_column($enabledViews, 'sequence'));
            if ($enabledViews[$matchAnyUuid]['sequence'] !== $highestSequence) {
                throw new UserException(
                    sprintf(
                        gettext('The match-any BIND view "%s" must have the highest sequence.'),
                        $enabledViews[$matchAnyUuid]['name']
                    ),
                    gettext('Configuration exception')
                );
            }
        }

        $tsigModel = new Tsig();
        $tsigRoot = $tsigModel->getNodeByReference('keys.key');
        $enabledTsigKeys = [];
        if ($tsigRoot !== null) {
            foreach ($tsigRoot->iterateItems() as $key) {
                if ((string)$key->enabled === '1') {
                    $enabledTsigKeys[$key->getAttribute('uuid')] = (string)$key->name;
                }
            }
        }

        $domainModel = new Domain();
        $domainRoot = $domainModel->getNodeByReference('domains.domain');
        $zoneNames = [];
        if ($domainRoot === null) {
            return;
        }

        foreach ($domainRoot->iterateItems() as $domain) {
            if ((string)$domain->enabled !== '1') {
                continue;
            }
            $viewUuid = (string)$domain->view;
            $domainName = strtolower(rtrim((string)$domain->domainname, '.'));

            if ((string)$domain->type === 'primary' && (string)$domain->primarytransferkey !== '') {
                $transferKeyUuid = (string)$domain->primarytransferkey;
                if (!isset($enabledTsigKeys[$transferKeyUuid])) {
                    throw new UserException(
                        sprintf(
                            gettext('Zone "%s" references a missing or disabled transfer TSIG key.'),
                            (string)$domain->domainname
                        ),
                        gettext('Configuration exception')
                    );
                }
            }

            if ((string)$domain->type === 'primary' && (string)$domain->updatekeys !== '') {
                foreach (explode(',', (string)$domain->updatekeys) as $keyUuid) {
                    if (!isset($enabledTsigKeys[$keyUuid])) {
                        throw new UserException(
                            sprintf(
                                gettext('Zone "%s" references a missing or disabled TSIG key.'),
                                (string)$domain->domainname
                            ),
                            gettext('Configuration exception')
                        );
                    }
                    if ((string)$domain->updatepolicy === 'self_txt') {
                        $keyName = strtolower(rtrim($enabledTsigKeys[$keyUuid], '.'));
                        if ($keyName !== $domainName && !str_ends_with($keyName, '.' . $domainName)) {
                            throw new UserException(
                                sprintf(
                                    gettext(
                                        'Exact-name update policy for zone "%s" requires TSIG key "%s" to be inside that zone.'
                                    ),
                                    (string)$domain->domainname,
                                    $enabledTsigKeys[$keyUuid]
                                ),
                                gettext('Configuration exception')
                            );
                        }
                    }
                }
            }

            if (!empty($enabledViews)) {
                if ($viewUuid === '' || !isset($enabledViews[$viewUuid])) {
                    throw new UserException(
                        sprintf(
                            gettext('Enabled zone "%s" is not assigned to an enabled BIND view.'),
                            (string)$domain->domainname
                        ),
                        gettext('Configuration exception')
                    );
                }
                $zoneKey = $viewUuid . ':' . $domainName;
                $duplicateMessage = sprintf(
                    gettext('Zone "%s" is defined more than once in BIND view "%s".'),
                    (string)$domain->domainname,
                    $enabledViews[$viewUuid]['name']
                );
            } else {
                $zoneKey = $domainName;
                $duplicateMessage = sprintf(
                    gettext('Zone "%s" is defined more than once while BIND views are disabled.'),
                    (string)$domain->domainname
                );
            }

            if (isset($zoneNames[$zoneKey])) {
                throw new UserException($duplicateMessage, gettext('Configuration exception'));
            }
            $zoneNames[$zoneKey] = true;
        }
    }

    private const RELOAD_ATTEMPTS = 5;
    private const RELOAD_DELAY_US = 500000;

    private function renderConfiguration(Backend $backend)
    {
        $result = trim($backend->configdpRun('template reload', [static::$internalServiceTemplate]));
        if ($result !== 'OK') {
            throw new UserException(
                gettext('BIND template generation failed.'),
                gettext('Configuration exception')
            );
        }
    }

    private function runServiceAction(Backend $backend, string $action)
    {
        $response = trim($backend->configdRun(
            escapeshellarg(static::$internalServiceName) . ' ' . $action
        ));
        return $response === 'OK';
    }

    private function serviceRunning()
    {
        return $this->statusAction()['status'] === 'running';
    }

    private function stopIfRunning(Backend $backend)
    {
        if ($this->serviceRunning() && !$this->runServiceAction($backend, 'stop')) {
            throw new UserException(
                gettext('BIND failed to stop.'),
                gettext('Configuration exception')
            );
        }
    }

    private function waitForReload(Backend $backend)
    {
        for ($attempt = 1; $attempt <= self::RELOAD_ATTEMPTS; $attempt++) {
            if ($this->runServiceAction($backend, 'reload')) {
                return;
            }
            if ($attempt < self::RELOAD_ATTEMPTS) {
                usleep(self::RELOAD_DELAY_US);
            }
        }
        throw new UserException(
            gettext('BIND did not accept the configuration reload.'),
            gettext('Configuration exception')
        );
    }

    private function startAndVerify(Backend $backend)
    {
        if (!$this->runServiceAction($backend, 'start')) {
            throw new UserException(
                gettext('BIND failed to start.'),
                gettext('Configuration exception')
            );
        }
        $this->waitForReload($backend);
    }

    public function reloadAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        $this->validateConfiguration();
        $backend = new Backend();
        $enabled = $this->serviceEnabled();
        $running = $this->serviceRunning();

        if (!$enabled) {
            $this->stopIfRunning($backend);
        }
        $this->renderConfiguration($backend);

        if ($enabled) {
            if (!$running) {
                $this->startAndVerify($backend);
            } else {
                $this->waitForReload($backend);
            }
        }
        return ['status' => 'ok'];
    }

    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        $this->validateConfiguration();
        $backend = new Backend();
        $this->stopIfRunning($backend);
        $this->renderConfiguration($backend);

        if ($this->serviceEnabled()) {
            $this->startAndVerify($backend);
        }
        return ['status' => 'ok'];
    }

    public function dnsblAction()
    {
        $mdl = new Dnsbl();
        $backend = new Backend();
        $response = $backend->configdpRun('bind dnsbl', [(string)$mdl->type]);
        return ['response' => $response];
    }
}

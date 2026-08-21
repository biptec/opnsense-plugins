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
use OPNsense\Core\FileObject;
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

        if ($viewRoot !== null) {
            foreach ($viewRoot->iterateItems() as $view) {
                if ((string)$view->enabled !== '1') {
                    continue;
                }
                $includedKeys = array_values(array_filter(explode(',', (string)$view->matchclienttsigkeys)));
                $excludedKeys = array_values(array_filter(explode(',', (string)$view->excludematchclienttsigkeys)));
                if (!empty(array_intersect($includedKeys, $excludedKeys))) {
                    throw new UserException(
                        sprintf(
                            gettext('BIND view "%s" includes and excludes the same client TSIG key.'),
                            (string)$view->name
                        ),
                        gettext('Configuration exception')
                    );
                }
                foreach (array_unique(array_merge($includedKeys, $excludedKeys)) as $keyUuid) {
                    if (!isset($enabledTsigKeys[$keyUuid])) {
                        throw new UserException(
                            sprintf(
                                gettext('BIND view "%s" references a missing or disabled client TSIG key.'),
                                (string)$view->name
                            ),
                            gettext('Configuration exception')
                        );
                    }
                }
            }
        }

        $domainModel = new Domain();
        $domainRoot = $domainModel->getNodeByReference('domains.domain');
        $zoneNames = [];
        if ($domainRoot === null) {
            return;
        }

        $sharedZones = [];
        foreach ($domainRoot->iterateItems() as $candidate) {
            if ((string)$candidate->enabled !== '1') {
                continue;
            }
            $candidateType = (string)$candidate->type;
            $candidateView = (string)$candidate->view;
            if (($candidateType === 'primary' || $candidateType === 'secondary') && $candidateView !== '') {
                $candidateName = strtolower(rtrim((string)$candidate->domainname, '.'));
                $sharedZones[$candidateView . ':' . $candidateName] = true;
            }
        }

        foreach ($domainRoot->iterateItems() as $domain) {
            if ((string)$domain->enabled !== '1') {
                continue;
            }
            $viewUuid = (string)$domain->view;
            $domainName = strtolower(rtrim((string)$domain->domainname, '.'));
            $domainType = (string)$domain->type;

            if ($domainType === 'inview' && empty($enabledViews)) {
                throw new UserException(
                    sprintf(gettext('In-view zone "%s" requires BIND views to be enabled.'), (string)$domain->domainname),
                    gettext('Configuration exception')
                );
            }

            if ($domainType === 'primary' && (string)$domain->primarytransferkey !== '') {
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

            if ($domainType === 'primary' && (string)$domain->updatekeys !== '') {
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

            if ($domainType === 'inview') {
                $sourceViewUuid = (string)$domain->inview;
                if ($sourceViewUuid === '' || !isset($enabledViews[$sourceViewUuid])) {
                    throw new UserException(
                        sprintf(
                            gettext('In-view zone "%s" references a missing or disabled source view.'),
                            (string)$domain->domainname
                        ),
                        gettext('Configuration exception')
                    );
                }
                if ($sourceViewUuid === $viewUuid) {
                    throw new UserException(
                        sprintf(gettext('In-view zone "%s" cannot reference its own view.'), (string)$domain->domainname),
                        gettext('Configuration exception')
                    );
                }
                if ($enabledViews[$sourceViewUuid]['sequence'] >= $enabledViews[$viewUuid]['sequence']) {
                    throw new UserException(
                        sprintf(
                            gettext('In-view zone "%s" must reference a source view ordered before its target view.'),
                            (string)$domain->domainname
                        ),
                        gettext('Configuration exception')
                    );
                }
                if (!isset($sharedZones[$sourceViewUuid . ':' . $domainName])) {
                    throw new UserException(
                        sprintf(
                            gettext('In-view zone "%s" has no matching primary or secondary zone in source view "%s".'),
                            (string)$domain->domainname,
                            $enabledViews[$sourceViewUuid]['name']
                        ),
                        gettext('Configuration exception')
                    );
                }
            }

            if (isset($zoneNames[$zoneKey])) {
                throw new UserException($duplicateMessage, gettext('Configuration exception'));
            }
            $zoneNames[$zoneKey] = true;
        }
    }

    private const START_ATTEMPTS = 20;
    private const START_DELAY_US = 250000;
    private const RECONFIGURE_LOCK = 'bind-reconfigure.lock';

    private function withServiceLock(callable $callback)
    {
        $lock = new FileObject(
            sys_get_temp_dir() . '/' . self::RECONFIGURE_LOCK,
            'a+',
            0600,
            LOCK_EX
        );
        try {
            return $callback();
        } finally {
            unset($lock);
        }
    }

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

    private function waitForRunning()
    {
        for ($attempt = 1; $attempt <= self::START_ATTEMPTS; $attempt++) {
            if ($this->serviceRunning()) {
                return;
            }
            if ($attempt < self::START_ATTEMPTS) {
                usleep(self::START_DELAY_US);
            }
        }
        throw new UserException(
            gettext('BIND did not become ready after start.'),
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
        $this->waitForRunning();
    }

    public function reloadAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        return $this->withServiceLock(function () {
            $this->validateConfiguration();
            $backend = new Backend();
            $enabled = $this->serviceEnabled();
            $this->stopIfRunning($backend);
            $this->renderConfiguration($backend);

            if ($enabled) {
                $this->startAndVerify($backend);
            }
            return ['status' => 'ok'];
        });
    }

    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        return $this->withServiceLock(function () {
            $this->validateConfiguration();
            $backend = new Backend();
            $this->stopIfRunning($backend);
            $this->renderConfiguration($backend);

            if ($this->serviceEnabled()) {
                $this->startAndVerify($backend);
            }
            return ['status' => 'ok'];
        });
    }

    public function dnsblAction()
    {
        $mdl = new Dnsbl();
        $backend = new Backend();
        $response = $backend->configdpRun('bind dnsbl', [(string)$mdl->type]);
        return ['response' => $response];
    }
}

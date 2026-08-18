<?php

/*
 * Copyright (C) 2015-2025 Deciso B.V.
 * Copyright (C) 2017 Fabian Franz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Quagga\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\Quagga
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Quagga\General';
    protected static $internalServiceTemplate = 'OPNsense/Quagga';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'quagga';

    /**
     * FRR can soft-reload normal routing changes, but frr-reload cannot add or
     * remove protocol daemons from an already running watchfrr process.
     * Restart only when the configured daemon set differs from the live set.
     */
    protected function reconfigureForceRestart()
    {
        $daemonModels = [
            'ospfd' => '\OPNsense\Quagga\OSPF',
            'ospf6d' => '\OPNsense\Quagga\OSPF6',
            'bgpd' => '\OPNsense\Quagga\BGP',
            'bfdd' => '\OPNsense\Quagga\BFD',
            'ripd' => '\OPNsense\Quagga\RIP',
            'staticd' => '\OPNsense\Quagga\STATICd',
        ];

        $backend = new Backend();
        $runningDaemons = preg_split(
            '/\s+/',
            trim($backend->configdRun('quagga daemonset')),
            -1,
            PREG_SPLIT_NO_EMPTY
        );
        $runningDaemons = array_fill_keys($runningDaemons, true);

        foreach ($daemonModels as $daemon => $modelClass) {
            $model = new $modelClass();
            $enabled = (string)$model->enabled === '1';
            $running = isset($runningDaemons[$daemon]);
            if ($enabled !== $running) {
                return 1;
            }
        }

        return 0;
    }
}

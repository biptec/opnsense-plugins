<?php
namespace OPNsense\ApiExtensions\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class EndpointSyncController extends ApiControllerBase
{
    public function pushAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $result = trim((new Backend())->configdRun('api_extensions config_sync_push'));
        $decoded = json_decode($result, true);
        if (!is_array($decoded)) {
            return ['status' => 'failed', 'message' => 'invalid config sync response'];
        }
        return $decoded;
    }
}

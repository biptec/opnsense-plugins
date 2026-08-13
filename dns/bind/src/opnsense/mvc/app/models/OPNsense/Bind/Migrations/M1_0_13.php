<?php

namespace OPNsense\Bind\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Bind\General;

class M1_0_13 extends BaseModelMigration
{
    private const LEGACY_DEFAULT_SHA256 = '3aa322d1905202ae3a57fc4157696bb950acc9f3c42ecdffa263bc89e8141194';

    public function run($model)
    {
        if (!$model instanceof General) {
            return;
        }

        parent::run($model);
        $current = (string)$model->rndcsecret;
        if ($current === '' || hash_equals(self::LEGACY_DEFAULT_SHA256, hash('sha256', $current))) {
            $model->rndcsecret->setValue(base64_encode(random_bytes(32)));
        }
    }
}

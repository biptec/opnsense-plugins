<?php

namespace OPNsense\ApiExtensions;

use OPNsense\Base\BaseModel;

/**
 * Generic HA synchronization policy catalog.
 *
 * The persisted mount intentionally remains InterfaceSyncPolicy for backward
 * compatibility with installations and API clients created before policies
 * were generalized beyond interfaces.
 */
class HASyncPolicy extends BaseModel
{
}

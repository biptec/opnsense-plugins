<?php

namespace OPNsense\ApiExtensions;

/**
 * Backward-compatible class name for the HA synchronization policy catalog.
 *
 * New code should use HASyncPolicy. The persisted mount remains
 * InterfaceSyncPolicy so no configuration migration is required.
 */
class InterfaceSyncPolicy extends HASyncPolicy
{
}

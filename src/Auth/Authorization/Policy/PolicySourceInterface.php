<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization\Policy;

interface PolicySourceInterface
{
    /**
     * Load policies from this source.
     * 
     * @return Policy[]
     */
    public function load(): array;
}

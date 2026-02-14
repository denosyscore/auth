<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Policy;

interface PolicySourceInterface
{
    /**
     * Load policies from this source.
     * 
     * @return Policy[]
     */
    public function load(): array;
}

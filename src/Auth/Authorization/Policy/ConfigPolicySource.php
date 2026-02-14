<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization\Policy;

class ConfigPolicySource implements PolicySourceInterface
{
    /**
     * @param string $configPath Path to the policies.php config file
     */
    public function __construct(
        private readonly string $configPath,
    ) {}

    /**

     * @return array<string, mixed>

     */

public function load(): array

    {
        if (!file_exists($this->configPath)) {
            return [];
        }

        $config = require $this->configPath;

        if (!is_array($config)) {
            return [];
        }

        $policies = [];

        foreach ($config as $policyData) {
            if ($policyData instanceof Policy) {
                $policies[] = $policyData;
            } elseif ($policyData instanceof PolicyBuilder) {
                $policies[] = $policyData->build();
            } elseif (is_array($policyData)) {
                $policies[] = Policy::fromArray($policyData);
            }
        }

        return $policies;
    }
}

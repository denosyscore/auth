<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization\Voter;

use Denosys\Auth\Authorization\Decision;
use Denosys\Auth\Authorization\Policy\PolicyLoader;
use Denosys\Auth\Identity\IdentityInterface;

class PolicyVoter implements VoterInterface
{
    public function __construct(
        private readonly PolicyLoader $policyLoader,
    ) {}

    public function supports(string $attribute, mixed $subject): bool
    {
        // PolicyVoter can vote on anything
        return true;
    }

    public function vote(IdentityInterface $identity, string $attribute, mixed $subject): Decision
    {
        $resourceType = $this->getResourceType($subject);

        $policies = $this->policyLoader->findMatching(
            $identity->getId(),
            $identity->getRoles(),
            $attribute,
            $resourceType
        );

        if (empty($policies)) {
            return Decision::ABSTAIN;
        }

        foreach ($policies as $policy) {
            if (!$policy->evaluateCondition($identity, $subject)) {
                continue;
            }

            return $policy->isAllow() ? Decision::ALLOW : Decision::DENY;
        }

        return Decision::ABSTAIN;
    }

    /**
     * Determine the resource type from the subject.
     */
    private function getResourceType(mixed $subject): string
    {
        if ($subject === null) {
            return '*';
        }

        if (is_string($subject)) {
            return $subject;
        }

        if (is_object($subject)) {
            if (method_exists($subject, 'getResourceType')) {
                return $subject->getResourceType();
            }

            if (method_exists($subject, 'getTable')) {
                return $subject->getTable();
            }

            $class = get_class($subject);
            $parts = explode('\\', $class);
            return strtolower(end($parts));
        }

        return '*';
    }
}

<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Voter;

use CFXP\Core\Auth\Authorization\Decision;
use CFXP\Core\Auth\Identity\IdentityInterface;

class OwnershipVoter implements VoterInterface
{
    /**
     * @param array<string> $supportedAttributes Actions this voter handles
     * @param string $ownerField The field/method name on the subject that returns owner ID
     */
    public function __construct(
        /**
         * @param array<string, mixed> $supportedAttributes
         */
        private readonly array $supportedAttributes = ['edit', 'update', 'delete', 'view'],
        private readonly string $ownerField = 'user_id',
    ) {}

    public function supports(string $attribute, mixed $subject): bool
    {
        // Only vote on objects that might have an owner
        if (!is_object($subject)) {
            return false;
        }

        return in_array($attribute, $this->supportedAttributes, true);
    }

    public function vote(IdentityInterface $identity, string $attribute, mixed $subject): Decision
    {
        if (!$this->supports($attribute, $subject)) {
            return Decision::ABSTAIN;
        }

        if (!$identity->isAuthenticated()) {
            return Decision::ABSTAIN;
        }

        $ownerId = $this->getOwnerId($subject);

        if ($ownerId === null) {
            return Decision::ABSTAIN;
        }

        if ((string) $ownerId === (string) $identity->getId()) {
            return Decision::ALLOW;
        }

        return Decision::ABSTAIN; // Let other voters decide
    }

    /**
     * Extract the owner ID from the subject.
     */
    private function getOwnerId(object $subject): string|int|null
    {
        $method = 'get' . str_replace('_', '', ucwords($this->ownerField, '_'));
        if (method_exists($subject, $method)) {
            return $subject->$method();
        }

        if (property_exists($subject, $this->ownerField)) {
            return $subject->{$this->ownerField};
        }

        if (method_exists($subject, '__get')) {
            return $subject->{$this->ownerField};
        }

        if (method_exists($subject, 'getAttribute')) {
            return $subject->getAttribute($this->ownerField);
        }

        return null;
    }
}

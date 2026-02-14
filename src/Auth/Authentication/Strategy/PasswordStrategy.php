<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authentication\Strategy;

use CFXP\Core\Auth\Authentication\Credential\CredentialInterface;
use CFXP\Core\Auth\Authentication\Credential\PasswordCredential;
use CFXP\Core\Auth\Authentication\Result;
use CFXP\Core\Auth\Authentication\UserProviderInterface;
use CFXP\Core\Auth\Identity\Identity;

class PasswordStrategy implements StrategyInterface
{
    public function __construct(
        private readonly UserProviderInterface $userProvider,
        private readonly ?string $identifierField = null,
    ) {}

    public function getName(): string
    {
        return 'password';
    }

    public function supports(CredentialInterface $credential): bool
    {
        return $credential instanceof PasswordCredential;
    }

    public function authenticate(CredentialInterface $credential): Result
    {
        if (!$credential instanceof PasswordCredential) {
            return Result::failure('Invalid credential type');
        }

        $field = $this->identifierField ?? $this->getDefaultIdentifierField();

        $user = $this->userProvider->findByCredential($field, $credential->identifier);

        if ($user === null) {
            return Result::invalidCredentials();
        }

        if (!$this->userProvider->validatePassword($user, $credential->password)) {
            return Result::invalidCredentials();
        }

        $this->userProvider->rehashPasswordIfRequired($user, $credential->password);

        $identity = Identity::fromAuthenticatable($user);

        return Result::success($identity, $user, [
            'remember' => $credential->remember,
        ]);
    }

    /**
     * Get the default identifier field from the user provider.
     */
    private function getDefaultIdentifierField(): string
    {
        if ($this->userProvider instanceof \CFXP\Core\Auth\Authentication\ModelUserProvider) {
            return $this->userProvider->getIdentifierField();
        }

        return 'email';
    }
}

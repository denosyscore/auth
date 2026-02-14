<?php

declare(strict_types=1);

namespace Denosys\Auth\Identity;

/**
 * @mixin \Denosys\Database\Model
 */
trait Authenticatable
{
    /**
     * Get the unique identifier for authentication.
     */
    public function getAuthIdentifier(): string|int
    {
        return $this->getKey();
    }

    /**
     * Get the name of the unique identifier column.
     */
    public function getAuthIdentifierName(): string
    {
        return $this->getKeyName();
    }

    /**
     * Get the hashed password.
     */
    public function getAuthPassword(): string
    {
        return $this->getAttribute('password') ?? '';
    }

    /**
     * Get the remember-me token.
     */
    public function getRememberToken(): ?string
    {
        $token = $this->getAttribute($this->getRememberTokenName());
        return $token !== '' ? $token : null;
    }

    /**
     * Set the remember-me token.
     */
    public function setRememberToken(string $token): void
    {
        $this->setAttribute($this->getRememberTokenName(), $token);
    }

    /**
     * Get the column name for the remember token.
     */
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * Get claims to include in the identity.
     * 
     * Override this method to add custom claims like roles, permissions, etc.
     */
    /**
     * @return array<string, mixed>
     */
public function getAuthClaims(): array
    {
        $claims = [
            'id' => $this->getAuthIdentifier(),
        ];

        if ($this->getAttribute('email') !== null) {
            $claims['email'] = $this->getAttribute('email');
        }

        if ($this->getAttribute('name') !== null) {
            $claims['name'] = $this->getAttribute('name');
        }

        if (method_exists($this, 'getRoles')) {
            $claims['roles'] = $this->getRoles();
        } elseif ($this->getAttribute('role') !== null) {
            $claims['roles'] = [$this->getAttribute('role')];
        } else {
            $claims['roles'] = ['user'];
        }

        return $claims;
    }
}

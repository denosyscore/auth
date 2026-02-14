<?php

declare(strict_types=1);

namespace Denosys\Auth;

use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\Authentication\ModelUserProvider;
use Denosys\Auth\Authentication\UserProviderInterface;
use Denosys\Auth\Authentication\Strategy\PasswordStrategy;
use Denosys\Auth\Middleware\AuthenticateMiddleware;
use Denosys\Container\ContainerInterface;
use Denosys\Http\ResponseFactory;
use Denosys\Contracts\ServiceProviderInterface;
use Denosys\Session\SessionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use RuntimeException;

class AuthServiceProvider implements ServiceProviderInterface
{
    public function register(ContainerInterface $container): void
    {
        $container->singleton(UserProviderInterface::class, function (ContainerInterface $container) {
            $config = $container->get('config');
            $userModel = $config->get('auth.model', null);
            if (!is_string($userModel) || $userModel === '') {
                throw new RuntimeException(
                    'auth.model must be configured with a valid user model class.'
                );
            }
            $identifierField = $config->get('auth.identifier', 'email');

            return new ModelUserProvider($userModel, $identifierField);
        });

        $container->singleton(PasswordStrategy::class, function (ContainerInterface $container) {
            return new PasswordStrategy(
                $container->get(UserProviderInterface::class)
            );
        });

        $container->singleton(Authenticator::class, function (ContainerInterface $container) {
            // Get event dispatcher if available (optional dependency)
            $eventDispatcher = null;
            if ($container->has(EventDispatcherInterface::class)) {
                $eventDispatcher = $container->get(EventDispatcherInterface::class);
            }

            $authenticator = new Authenticator(
                $container->get(SessionInterface::class),
                $container->get(UserProviderInterface::class),
                $eventDispatcher
            );

            $authenticator->addStrategy($container->get(PasswordStrategy::class));

            return $authenticator;
        });

        $container->singleton(AuthenticateMiddleware::class, function (ContainerInterface $container) {
            $config = $container->get('config');

            return new AuthenticateMiddleware(
                $container->get(Authenticator::class),
                $container->get(ResponseFactory::class),
                $container,
                $config->get('auth.redirect')
            );
        });

        $container->singleton(Middleware\GuestMiddleware::class, function (ContainerInterface $container) {
            $config = $container->get('config');

            return new Middleware\GuestMiddleware(
                $container->get(Authenticator::class),
                $container->get(ResponseFactory::class),
                $config->get('auth.guest_redirect')
            );
        });

        $container->alias('auth', Authenticator::class);
    }

    public function boot(ContainerInterface $container, ?EventDispatcherInterface $dispatcher = null): void
    {
    }
}

<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Middleware;

use CFXP\Core\Auth\Authentication\Authenticator;
use CFXP\Core\Container\Container;
use CFXP\Core\Http\Request;
use CFXP\Core\Http\ResponseFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthenticateMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly Authenticator $authenticator,
        private readonly ResponseFactory $responseFactory,
        private readonly Container $container,
        private readonly ?string $redirectTo = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->authenticator->check()) {
            // Set the authenticated user on the request object
            if ($request instanceof Request) {
                $request = $request->withUser($this->authenticator->user());
                
                // Re-bind the updated request to container
                $this->container->instance(ServerRequestInterface::class, $request);
                $this->container->instance(Request::class, $request);
            }
            
            return $handler->handle($request);
        }

        if ($this->redirectTo !== null) {
            $url = route($this->redirectTo);
            return $this->responseFactory->redirect($url);
        }

        return $this->responseFactory->json(['error' => 'Unauthenticated'], 401);
    }
}

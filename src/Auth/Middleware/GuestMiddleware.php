<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Middleware;

use CFXP\Core\Auth\Authentication\Authenticator;
use CFXP\Core\Http\ResponseFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class GuestMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly Authenticator $authenticator,
        private readonly ResponseFactory $responseFactory,
        private readonly ?string $redirectTo = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->authenticator->guest()) {
            return $handler->handle($request);
        }

        if ($this->redirectTo !== null) {
            $url = route($this->redirectTo);
            return $this->responseFactory->redirect($url);
        }

        return $this->responseFactory->json(['error' => 'Already authenticated'], 403);
    }
}

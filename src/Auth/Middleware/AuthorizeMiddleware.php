<?php

declare(strict_types=1);

namespace Denosys\Auth\Middleware;

use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\Authorization\Authorizer;
use Denosys\Http\ResponseFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthorizeMiddleware implements MiddlewareInterface
{
    /**
     * @param Authenticator $authenticator
     * @param Authorizer $authorizer
     * @param ResponseFactory $responseFactory
     * @param string $attribute The permission to check (e.g., 'edit', 'ROLE_ADMIN')
     * @param \Closure|null $subjectResolver Callable to resolve the subject from the request
     */
    public function __construct(
        private readonly Authenticator $authenticator,
        private readonly Authorizer $authorizer,
        private readonly ResponseFactory $responseFactory,
        private readonly string $attribute,
        private readonly ?\Closure $subjectResolver = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identity = $this->authenticator->identity();

        $subject = null;
        if ($this->subjectResolver !== null) {
            $subject = ($this->subjectResolver)($request);
        }

        if ($this->authorizer->isGranted($identity, $this->attribute, $subject)) {
            return $handler->handle($request);
        }

        if (!$identity->isAuthenticated()) {
            return $this->responseFactory->json(['error' => 'Unauthenticated'], 401);
        }

        return $this->responseFactory->json(['error' => 'Forbidden'], 403);
    }
}

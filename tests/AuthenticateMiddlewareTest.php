<?php

declare(strict_types=1);

namespace Denosys\Auth\Tests;

use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Auth\Middleware\AuthenticateMiddleware;
use Denosys\Container\Container;
use Denosys\Http\Request;
use Denosys\Http\ResponseFactory;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthenticateMiddlewareTest extends TestCase
{
    public function testGenericPsrRequestCarriesAuthenticatedUserAndPreservesAttributes(): void
    {
        $user = $this->createMock(AuthenticatableInterface::class);
        $authenticator = $this->createMock(Authenticator::class);
        $authenticator->method('check')->willReturn(true);
        $authenticator->method('user')->willReturn($user);
        $container = new Container();
        $handler = new class implements RequestHandlerInterface {
            public ?ServerRequestInterface $received = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->received = $request;

                return new HtmlResponse('ok');
            }
        };
        $request = new ServerRequest([], [], 'https://example.test/office', 'POST');
        $request = $request->withAttribute('trace', 'retained')->withParsedBody(['field' => 'value']);

        $response = new AuthenticateMiddleware($authenticator, new ResponseFactory(), $container)
            ->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertInstanceOf(Request::class, $handler->received);
        self::assertSame($user, $handler->received->user());
        self::assertSame('POST', $handler->received->getMethod());
        self::assertSame('retained', $handler->received->getAttribute('trace'));
        self::assertSame(['field' => 'value'], $handler->received->getParsedBody());
        self::assertSame($handler->received, $container->get(Request::class));
        self::assertSame($handler->received, $container->get(ServerRequestInterface::class));
    }

    public function testUnauthenticatedRequestStillReturnsUnauthorizedWithoutInvokingHandler(): void
    {
        $authenticator = $this->createMock(Authenticator::class);
        $authenticator->method('check')->willReturn(false);
        $handler = new class implements RequestHandlerInterface {
            public bool $called = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;

                return new HtmlResponse('unexpected');
            }
        };

        $response = new AuthenticateMiddleware($authenticator, new ResponseFactory(), new Container())
            ->process(new ServerRequest([], [], 'https://example.test/office', 'GET'), $handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($handler->called);
    }
}

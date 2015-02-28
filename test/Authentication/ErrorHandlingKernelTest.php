<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class ErrorHandlingKernelTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    private $wrapped, $kernel, $request;

    public function testKernelReturnsResponseFromWrappedKernelWhenNoExceptionIsThrown()
    {
        $resp = new Response('hello, world');
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($this->request))
            ->willReturn($resp);

        $this->assertSame($resp, $this->kernel->handle($this->request));
    }

    /**
     * @expectedException Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function testKernelThrowsAccessDeniedExceptionWhenAuthenticationFailsAndCatchIsFalse()
    {
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($this->request))
            ->willThrowException(new AuthenticationException('oops'));

        $this->kernel->handle($this->request, HttpKernelInterface::MASTER_REQUEST, false);
    }

    protected function setUp()
    {
        $this->wrapped = $this->getMock(HttpKernelInterface::class);
        $this->kernel = new ErrorHandlingKernel($this->wrapped);
        $this->request = $this->createRequest();
    }
}

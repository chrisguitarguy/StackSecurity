<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authorization;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class ErrorHandlingKernelTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    private $wrapped, $kernel;

    public function testKernelReturnsResponseFromWrappedKernelWhenNoExceptionIsThrown()
    {
        $resp = new Response();
        $req = $this->createRequest('/');
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($req))
            ->willReturn($resp);

        $this->assertSame($resp, $this->kernel->handle($req));
    }

    /**
     * @expectedException Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function testKernelThrowsAccessDeniedExceptionWhenSecurityAccessDeniedExceptionIsThrown()
    {
        $req = $this->createRequest('/');
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($req))
            ->willThrowException(new AccessDeniedException());

        $this->kernel->handle($req);
    }

    protected function setUp()
    {
        $this->wrapped = $this->getMock(HttpKernelInterface::class);
        $this->kernel = new ErrorHandlingKernel($this->wrapped);
    }
}

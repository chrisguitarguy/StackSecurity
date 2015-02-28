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

class ChallengingKernelTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    private $wrapped, $kernel, $request;

    public function testResponseWithout401StatusAndStackHeaderIsReturned()
    {
        $resp = new Response('Access Denied', 401);
        $this->kernelReturns($resp);

        $this->assertSame($resp, $this->kernel->handle($this->request));
    }

    /**
     * @expectedException Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
     */
    public function testKernelWithStackAuthResponseCallsEntryPointForAChallengeResponse()
    {
        $resp = new Response('broken', 401, ['WWW-Authenticate' => 'Stack']);
        $this->kernelReturns($resp);

        $this->kernel->handle($this->request);
    }

    protected function setUp()
    {
        $this->wrapped = $this->getMock(HttpKernelInterface::class);
        $this->kernel = new ChallengingKernel($this->wrapped);
        $this->request = $this->createRequest();
    }

    private function kernelReturns(Response $resp)
    {
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($this->request))
            ->willReturn($resp);
    }
}

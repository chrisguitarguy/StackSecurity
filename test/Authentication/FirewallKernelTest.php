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
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Chrisguitarguy\StackSecurity\Authentication\Firewall\Firewall;

class FirewallKernelTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    private $wrapped, $firewall, $auth, $kernel, $request;

    public function testRequestWithTokenAlreadyPresentCallsWrappedKernelDirectly()
    {
        $this->firewall->expects($this->never())
            ->method('match');
        $resp = $this->willCallKernel();
        $this->request->attributes->set('stack.authn.token', 'yep');

        $this->assertSame($resp, $this->kernel->handle($this->request));
    }

    public function testNoResultFromFirewallCallsWrappedKernelWithoutGoingToAuthentication()
    {
        $this->firewall->expects($this->once())
            ->method('match')
            ->with($this->identicalTo($this->request))
            ->willReturn(null);
        $this->auth->expects($this->never())
            ->method('authenticate');
        $resp = $this->willCallKernel();

        $this->assertSame($resp, $this->kernel->handle($this->request));
    }

    public function testResponseFromFirewallIsReturnedWithoutCallingWrappedKernel()
    {
        $resp = new Response('oops');
        $this->firewall->expects($this->once())
            ->method('match')
            ->with($this->identicalTo($this->request))
            ->willReturn($resp);
        $this->auth->expects($this->never())
            ->method('authenticate');
        $this->wrapped->expects($this->never())
            ->method('handle');

        $this->assertSame($resp, $this->kernel->handle($this->request));
    }

    public function testFirewallThatReturnsTokenPassesItToAuthenticatorThenCallsWrappedKernel()
    {
        $resp = $this->willCallKernel();
        $token = new AnonymousToken('testProvider', 'username');
        $this->firewall->expects($this->once())
            ->method('match')
            ->with($this->identicalTo($this->request))
            ->willReturn($token);
        $this->auth->expects($this->once())
            ->method('authenticate')
            ->with($this->identicalTo($token))
            ->willReturn($token);

        $this->assertSame($resp, $this->kernel->handle($this->request));
        $this->assertSame($token, $this->request->attributes->get('stack.authn.token'));
    }

    protected function setUp()
    {
        $this->wrapped = $this->getMock(HttpKernelInterface::class);
        $this->firewall = $this->getMock(Firewall::class);
        $this->auth = $this->getMock(AuthenticationManagerInterface::class);
        $this->kernel = new FirewallKernel($this->wrapped, $this->firewall, $this->auth);
        $this->request = $this->createRequest();
    }

    private function willCallKernel()
    {
        $resp = new Response('hello, world');
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($this->request))
            ->willReturn($resp);

        $resp;
    }
}

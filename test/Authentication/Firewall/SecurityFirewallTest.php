<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication\Firewall;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

interface _CombinedPreAuth extends SimplePreAuthenticatorInterface, AuthenticationEntryPointInterface
{

}

class SecurityFirewallTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    const PROVIDER = 'testProvider';

    private $matcher, $preauth, $firewall;

    public function testFirewallReturnsNullWhenMatcherDoesNotMatchRequestAndNoEntryPointIsFound()
    {
        $preauth = $this->getMock(SimplePreAuthenticatorInterface::class);
        $firewall = new SecurityFirewall('^/test', self::PROVIDER, $preauth);
        $req = $this->createRequest('/');
        $preauth->expects($this->never())
            ->method('createToken');

        $this->assertEquals(Firewall::DECLINE, $firewall->match($req));
    }

    public function testFirewallCallsStartOnPreAuthWhenPreAuthImplementsEntryPointAndTokenDeclines()
    {
        $preauth = $this->getMock(_CombinedPreAuth::class);
        $firewall = new SecurityFirewall(new RequestMatcher('^/test'), self::PROVIDER, $preauth);
        $req = $this->createRequest('/test');
        $resp = new Response('test');
        $preauth->expects($this->once())
            ->method('createToken')
            ->willReturn(null);
        $preauth->expects($this->once())
            ->method('start')
            ->with($this->identicalTo($req))
            ->willReturn($resp);

        $this->assertSame($resp, $firewall->match($req));
    }

    public function testFirewallCallsEntryPointWhenPreAuthIsNotEntryPointAndTokenDeclines()
    {
        $preauth = $this->getMock(SimplePreAuthenticatorInterface::class);
        $entry = $this->getMock(AuthenticationEntryPointInterface::class);
        $firewall = new SecurityFirewall(new RequestMatcher('^/test'), self::PROVIDER, $preauth, $entry);
        $req = $this->createRequest('/test');
        $resp = new Response('test');
        $preauth->expects($this->once())
            ->method('createToken')
            ->willReturn(null);
        $entry->expects($this->once())
            ->method('start')
            ->with($this->identicalTo($req))
            ->willReturn($resp);

        $this->assertSame($resp, $firewall->match($req));
    }

    public function testFirewallCallsPreAuthenticatorWhenRequestMatcherSucceedes()
    {
        $token = new AnonymousToken(self::PROVIDER, 'username');
        $req = $this->createRequest('/test');
        $preauth = $this->getMock(SimplePreAuthenticatorInterface::class);
        $firewall = new SecurityFirewall('^/test', self::PROVIDER, $preauth);
        $preauth->expects($this->once())
            ->method('createToken')
            ->with($this->identicalTo($req), self::PROVIDER)
            ->willReturn($token);

        $this->assertSame($token, $firewall->match($req));
    }

    protected function setUp()
    {
    }
}

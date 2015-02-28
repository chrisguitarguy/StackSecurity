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
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;

class SecurityFirewallTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    const PROVIDER = 'testProvider';

    private $matcher, $preauth, $firewall;

    public function testFirewallReturnsNullWhenMatcherDoesNotMatchRequest()
    {
        $req = $this->createRequest('/');
        $this->preauth->expects($this->never())
            ->method('createToken');

        $this->assertEquals(Firewall::DECLINE, $this->firewall->match($req));
    }

    public function testFirewallCallsPreAuthenticatorWhenRequestMatcherSucceedes()
    {
        $token = new AnonymousToken(self::PROVIDER, 'username');
        $req = $this->createRequest('/test');
        $this->preauth->expects($this->once())
            ->method('createToken')
            ->with($this->identicalTo($req), self::PROVIDER)
            ->willReturn($token);

        $this->assertSame($token, $this->firewall->match($req));
    }

    protected function setUp()
    {
        $this->matcher = new RequestMatcher('^/test');
        $this->preauth = $this->getMock(SimplePreAuthenticatorInterface::class);
        $this->firewall = new SecurityFirewall($this->matcher, self::PROVIDER, $this->preauth);
    }
}

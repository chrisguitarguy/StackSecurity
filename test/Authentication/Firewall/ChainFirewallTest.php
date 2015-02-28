<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication\Firewall;

use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;

/**
 * @group unit
 */
class ChainFirewallTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    public function testMatchReturnsNullWhenNoFirewallsMatchRequest()
    {
        $f = new ChainFirewall([
            $this->firewallReturning(null),
            $this->firewallReturning(null),
        ]);

        $this->assertNull($f->match($this->createRequest()));
    }

    public function testMatchReturnsTheValueFromAMatchingFirewall()
    {
        $token = new AnonymousToken('test', 'a user');
        $f = new ChainFirewall([
            $this->firewallReturning(null),
            $this->firewallReturning($token),
        ]);

        $this->assertSame($token, $f->match($this->createRequest()));
    }

    protected function firewallReturning($ret)
    {
        $f = $this->getMock(Firewall::class);
        $f->expects($this->atLeastOnce())
            ->method('match')
            ->willReturn($ret);

        return $f;
    }
}

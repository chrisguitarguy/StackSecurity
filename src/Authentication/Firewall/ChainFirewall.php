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

/**
 * Matches a request based on a collection of firewalls.
 *
 * @since   0.1
 */
final class ChainFirewall implements Firewall
{
    private $firewalls = [];

    /**
     * Constructor. Optionally set up some initial firewalls.
     *
     * @param   Firewall[] $firewalls The initial firewalls
     * @return  void
     */
    public function __construct(array $firewalls=[])
    {
        foreach ($firewalls as $firewall) {
            $this->add($firewall);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function match(Request $request)
    {
        foreach ($this->firewalls as $firewall) {
            if (self::DECLINE !== $tokenOrResponse = $firewall->match($request)) {
                return $tokenOrResponse;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function add(Firewall $firewall)
    {
        $this->firewalls[] = $firewall;
    }
}

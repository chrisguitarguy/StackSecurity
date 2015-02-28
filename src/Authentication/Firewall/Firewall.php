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
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Firewalls match income requests again known rules and a rule matches, the firewall
 * will return an SimplePreAuthenticatorInterface that can kick off the authentication
 * process.
 *
 * @since   0.1
 */
interface Firewall
{
    /**
     * Match the request agains the know firewalls.
     *
     * @param   $request The request to match
     * @return  TokenInterface|null if no match was found.
     */
    public function match(Request $request);
}

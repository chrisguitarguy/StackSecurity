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
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Firewalls match income requests again known rules and a rule matches, the firewall
 * will return an SimplePreAuthenticatorInterface that can kick off the authentication
 * process.
 *
 * @since   0.1
 */
interface Firewall
{
    const DECLINE = null;

    /**
     * Match the request agains the know firewalls. A response would be returned
     * here if your firewall requires authentication and needs to issue a challenge.
     *
     * @param   $request The request to match
     * @return  TokenInterface|Response|null Null if the firewall declines to
     *          intervene in the request. If a response is returned the firewall
     *          is issuing a challenge. Otherwise a token can be passed off to
     *          the an authentication manager.
     */
    public function match(Request $request);
}

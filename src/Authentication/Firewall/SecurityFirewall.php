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
use Symfony\Component\HttpFoundation\RequestMatcherInterface;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * A firewall implementation that uses the Symfony SimplePreAutheticatorInterface
 * along with a RequestMatcher to check and see if a request is firewalled.
 *
 * @since   0.1
 */
final class SecurityFirewall implements Firewall
{
    /**
     * @var     RequestMatcherInterface
     */
    private $matcher;

    /**
     * @var     string
     */
    private $providerKey;

    /**
     * @var     SimplePreAuthenticatorInterface
     */
    private $preauth;

    /**
     * @var     AuthenticationEntryPointInterface|null
     */
    private $entryPoint;

    /**
     * Constructor. Set up the matcher and pre authenticator.
     *
     * @param   RequestMatcherInterface|string $matcher This will be treated as
     *          a path if it's a string.
     * @param   string $providerKey The provider key for the token. This is used 
     *          to tell the authenticator the provider as well as sending signals
     *          around to other collaborators. In other words, you could use it to
     *          let things like an authenication provider know that it should
     *          support a given token.
     * @param   $preauth The pre authenticator to use
     * @return  void
     */
    public function __construct(
        $matcher,
        $providerKey,
        SimplePreAuthenticatorInterface $preauth,
        AuthenticationEntryPointInterface $entryPoint=null
    ) {
        $this->matcher = $matcher instanceof RequestMatcherInterface ? $matcher : new RequestMatcher($matcher);
        $this->providerKey = $providerKey;
        $this->preauth = $preauth;
        $this->entryPoint = $entryPoint;
    }

    /**
     * {@inheritdoc}
     */
    public function match(Request $request)
    {
        if (!$this->matcher->matches($request)) {
            return self::DECLINE;
        }

        $token = $this->preauth->createToken($request, $this->providerKey);

        return $token ? $token : $this->start($request);
    }

    private function start(Request $req)
    {
        if ($this->preauthIsEntrypoint()) {
            return $this->preauth->start($req);
        }

        return $this->hasEntryPoint() ? $this->entryPoint->start($req) : self::DECLINE;
    }

    private function preauthIsEntrypoint()
    {
        return $this->preauth instanceof AuthenticationEntryPointInterface;
    }

    private function hasEntryPoint()
    {
        return null !== $this->entryPoint;
    }

}

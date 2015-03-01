<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication\Authenticator;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\EntryPoint\BasicAuthenticationEntryPoint;

/**
 * An simple authenticator/entrypoint/errorhandler that does HTTP Basic Auth.
 *
 * Use this as an example of what your own integration might do.
 *
 * @since   0.1
 */
final class HttpBasicAuthenticator
    extends BasicAuthenticationEntryPoint
    implements AuthenticationFailureHandlerInterface,
               SimplePreAuthenticatorInterface
{
    /**
     * @var     UserPasswordEncoderInterface
     */
    private $encoder;

    public function __construct($realm, UserPasswordEncoderInterface $encoder)
    {
        parent::__construct($realm);
        $this->encoder = $encoder;
    }

    /**
     * {@inheritdoc}
     */
    public function createToken(Request $req, $providerKey)
    {
        $username = $req->getUser();
        if (null === $username) {
            return null;
        }

        return new UsernamePasswordToken($username, $req->getPassword(), $providerKey);
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        try {
            $user = $userProvider->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $e) {
            throw new BadCredentialsException('Bad Credentials', 0, $e);
        }

        if (!$this->validPassword($user, $token->getCredentials())) {
            throw new BadCredentialsException('Invalid Password.');
        }

        return new UsernamePasswordToken($user, $token->getCredentials(), $providerKey, $user->getRoles());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey() === $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $req, AuthenticationException $e)
    {
        return $this->start($req, $e);
    }

    public function validPassword(UserInterface $user, $rawPassword)
    {
        return $this->encoder->isPasswordValid($user, $rawPassword);
    }
}

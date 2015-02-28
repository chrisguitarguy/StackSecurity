<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;

/**
 * A failure handler that just rethrows the exception as an access denied
 * http exception
 *
 * @since   0.1
 */
final class DefaultFailureHandler implements AuthenticationFailureHandlerInterface
{
    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        throw new AccessDeniedHttpException('Authentication Failed', $exception);
    }
}

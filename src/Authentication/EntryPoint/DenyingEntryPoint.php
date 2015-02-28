<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication\EntryPoint;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * An authentication entry point that just throws an access denied exception.
 *
 * @since   0.1
 */
final class DenyingEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * {@inheritdoc}
     */
    public function start(Request $req, AuthenticationException $exception=null)
    {
        throw new AccessDeniedHttpException('Access Denied', $exception);
    }
}

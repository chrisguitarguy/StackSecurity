<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authorization\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;

/**
 * An AccessDeniedHandlerInterface implementation that simply rethrows the
 * exception as a HttpException.
 *
 * @since   0.1
 */
final class DefaultDeniedHandler implements AccessDeniedHandlerInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, AccessDeniedException $e)
    {
        throw new AccessDeniedHttpException('Access Denied', $e);
    }
}

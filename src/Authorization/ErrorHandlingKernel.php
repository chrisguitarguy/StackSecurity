<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authorization;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;
use Chrisguitarguy\StackSecurity\AbstractKernel;

/**
 * Uses an AccessDeniedHandlerInterface to deal with AccessDeniedExceptions
 * from the wrapped kernel. The default bevahior is just to rethrow the exception
 * as a HttpException.
 *
 * @since   0.1
 */
final class ErrorHandlingKernel extends AbstractKernel
{
    /**
     * @var     AccessDeniedHandlerInterface
     */
    private $handler;

    public function __construct(HttpKernelInterface $wrapped, AccessDeniedHandlerInterface $handler=null)
    {
        parent::__construct($wrapped);
        $this->handler = $handler ?: new Handler\DefaultDeniedHandler();
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        try {
            return parent::handle($req, $type, $catch);
        } catch (AccessDeniedException $e) {
            return $this->handler->handle($req, $e);
        }
    }
}

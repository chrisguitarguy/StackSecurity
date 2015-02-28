<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Chrisguitarguy\StackSecurity\AbstractKernel;

/**
 * A Kernel that uses an AuthenticationFailureHandlerInterface implementation
 * to deal with failed authentication attempts.
 *
 * @since   0.1
 */
final class ErrorHandlingKernel extends AbstractKernel
{
    /**
     * @var     AuthenticationFailureHandlerInterface
     */
    private $failureHandler;

    public function __construct(HttpKernelInterface $wrapped, AuthenticationFailureHandlerInterface $handler=null)
    {
        parent::__construct($wrapped);
        $this->failureHandler = $handler ?: new Handler\DefaultFailureHandler();
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        try {
            return parent::handle($req, $type, $catch);
        } catch (AuthenticationException $e) {
            return $this->failureHandler->onAuthenticationFailure($req, $e);
        }
    }
}

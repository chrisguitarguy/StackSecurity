<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\TerminableInterface;

/**
 * ABC for other kernels. Provides the decorator functionality.
 *
 * @since   0.1
 */
abstract class AbstractKernel implements HttpKernelInterface, TerminableInterface
{
    const TOKENATTR = 'stack.authn.token';

    /**
     * The wrapped HTTP Kernel
     *
     * @var     HttpKernelInterface
     */
    private $wrapped;

    public function __construct(HttpKernelInterface $wrapped)
    {
        $this->wrapped = $wrapped;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        return $this->wrapped->handle($req, $type, $catch);
    }

    /**
     * {@inheritdoc}
     */
    public function terminate(Request $req, Response $resp)
    {
        if ($this->wrapped instanceof TerminableInterface) {
            $this->wrapped->terminate($req, $resp);
        }
    }
}

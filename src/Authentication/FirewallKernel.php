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
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Chrisguitarguy\StackSecurity\AbstractKernel;
use Chrisguitarguy\StackSecurity\Authentication\Firewall\Firewall;

/**
 * An HTTP Kernel that uses firewalls to check the incoming request.
 *
 * @since   0.1
 */
final class FirewallKernel extends AbstractKernel
{
    /**
     * @var     Firewall
     */
    private $firewall;

    /**
     * @var     AuthenticationMangagerInterface
     */
    private $authenticator;

    public function __construct(HttpKernelInterface $wrapped, Firewall $firewall, AuthenticationManagerInterface $auth)
    {
        parent::__construct($wrapped);
        $this->firewall = $firewall;
        $this->authenticator = $auth;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        if ($req->attributes->has(self::TOKENATTR)) {
            return parent::handle($req, $type, $catch);
        }

        $tokenOrResponse = $this->firewall->match($req);
        if (!$tokenOrResponse) {
            return parent::handle($req, $type, $catch);
        }

        if ($tokenOrResponse instanceof Response) {
            return $tokenOrResponse;
        }

        $token = $this->authenticator->authenticate($tokenOrResponse);
        $req->attributes->set(self::TOKENATTR, $token);

        return parent::handle($req, $type, $catch);
    }
}

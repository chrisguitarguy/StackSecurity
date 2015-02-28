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
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Chrisguitarguy\StackSecurity\AbstractKernel;

/**
 * A kernel that inspects the response for a `WWW-Authenticat: Stack` header
 * and issues a challenge via an AuthenticationEntryPointInterface implementation
 *
 * @since   0.1
 */
final class ChallengingKernel extends AbstractKernel
{
    /**
     * @var     AuthenticationEntryPointInterface
     */
    private $entryPoint;

    public function __construct(HttpKernelInterface $wrapped, AuthenticationEntryPointInterface $entry=null)
    {
        parent::__construct($wrapped);
        $this->entryPoint = $entry ?: new EntryPoint\DenyingEntryPoint();
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        $resp = parent::handle($req, $type, $catch);
        if ($this->shouldChallenge($resp)) {
            return $this->entryPoint->start($req);
        }

        return $resp;
    }

    private function shouldChallenge(Response $resp)
    {
        return $resp->getStatusCode() == 401 && $resp->headers->get('WWW-Authenticate') === 'Stack';
    }
}

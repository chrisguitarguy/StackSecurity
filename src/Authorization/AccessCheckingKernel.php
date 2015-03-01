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
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\AccessMapInterface;
use Chrisguitarguy\StackSecurity\AbstractKernel;

/**
 * A kernel that uses an AccessDecisionManager and AccessMap to determine if the
 * current user can access a resource.
 *
 * @since   0.1
 */
final class AccessCheckingKernel extends AbstractKernel
{
    /**
     * @var     AccessDecisionManagerInterface
     */
    private $decisionManager;

    /**
     * @var     AccessMapInterface
     */
    private $accessMap;

    public function __construct(HttpKernelInterface $wrapped, AccessDecisionManagerInterface $manager, AccessMapInterface $map)
    {
        parent::__construct($wrapped);
        $this->decisionManager = $manager;
        $this->accessMap = $map;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $req, $type=self::MASTER_REQUEST, $catch=true)
    {
        list($attributes,) = $this->accessMap->getPatterns($req);

        if (null === $attributes) {
            return parent::handle($req, $type, $catch);
        }

        if (!$req->attributes->has(self::TOKENATTR)) {
            return new Response('', 401, ['WWW-Authenticate' => 'Stack']);
        }

        $token = $req->attributes->get(self::TOKENATTR);
        if (!$token instanceof TokenInterface) {
            throw new \UnexpectedValueException(sprintf(
                'Expected %s to be a `%s`, but got `%s`',
                self::TOKENATTR,
                TokenInterface::class,
                is_object($token) ? get_class($token) : gettype($token)
            ));
        }

        if (!$this->decisionManager->decide($token, $attributes, $req)) {
            throw new AccessDeniedException();
        }

        return parent::handle($req, $type, $catch);
    }
}

<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authorization;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\AccessMap;

/**
 * This is very much an integration test.
 */
class AccessCheckingKernelTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    private $wrapped, $accessMap, $decisionManager, $kernel;

    public function testAccessingUnblockedAreaCallsWrappedKernelDirectly()
    {
        $req = $this->createRequest('/not_blocked');
        $resp = $this->callsKernelWith($req);

        $this->assertSame($resp, $this->kernel->handle($req));
    }

    public function testAccessingBlockedAreaWithoutTokenIssuesChallengeResponseForStackAuthenticationMiddleware()
    {
        $req = $this->createRequest('/blocked');
        $this->wrapped->expects($this->never())
            ->method('handle');

        $resp = $this->kernel->handle($req);

        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertEquals('Stack', $resp->headers->get('WWW-Authenticate'));
    }

    public static function badTokens()
    {
        return [
            [null],
            [false],
            [['an', 'array']],
            ['a string'],
            [new \stdClass],
        ];
    }

    /**
     * @dataProvider badTokens
     * @expectedException UnexpectedValueException
     */
    public function testAccessingBlockedAreaWithInvalidTokenCausesError($token)
    {
        $req = $this->createRequest('/blocked');
        $req->attributes->set('stack.authn.token', $token);
        $this->wrapped->expects($this->never())
            ->method('handle');

        $this->kernel->handle($req);
    }

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\AccessDeniedException
     */
    public function testValidTokenAccessingBlockedAreaDeniesAccessWhenDecisionManagerRejectsToken()
    {
        $req = $this->createRequest('/blocked');
        $req->attributes->set('stack.authn.token', new AnonymousToken('testToken', 'username', []));
        $this->wrapped->expects($this->never())
            ->method('handle');

        $this->kernel->handle($req);
    }

    public function testValidTokenAccessingBlockedAreaPassesToWrappedKernelWhenDecisionManagerGrants()
    {
        $req = $this->createRequest('/blocked');
        $req->attributes->set('stack.authn.token', new AnonymousToken('testToken', 'username', ['ROLE_USER']));
        $resp = $this->callsKernelWith($req);

        $this->assertSame($resp, $this->kernel->handle($req));
    }

    protected function setUp()
    {
        $this->wrapped = $this->getMock(HttpKernelInterface::class);
        $this->accessMap = new AccessMap();
        $this->accessMap->add(new RequestMatcher('^/blocked'), ['ROLE_USER']);
        $this->decisionManager = new AccessDecisionManager([
            new RoleVoter(),
        ]);
        $this->kernel = new AccessCheckingKernel($this->wrapped, $this->decisionManager, $this->accessMap);
    }

    private function callsKernelWith(Request $req)
    {
        $resp = new Response('Hello, World');
        $this->wrapped->expects($this->once())
            ->method('handle')
            ->with($this->identicalTo($req))
            ->willReturn($resp);

        return $resp;
    }
}

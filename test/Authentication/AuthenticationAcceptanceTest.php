<?php
/**
 * This file is part of Stack Security
 *
 * @package     Chrisguitarguy\StackSecurity
 * @license     http://opensource.org/licenses/MIT MIT
 * @copyright   (c) Christopher Davis <http://christopherdavis.me>
 */

namespace Chrisguitarguy\StackSecurity\Authentication;

use Stack\CallableHttpKernel;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlainTextPasswordEncoder;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoder;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Tests all the authentication kernels together.
 *
 * @group acceptance
 */
class AuthenticationAcceptanceTest extends \Chrisguitarguy\StackSecurity\TestCase
{
    const USER = 'testUser';
    const PASS = 'password';
    const PROVIDERKEY = 'test';

    public function testNonFirewalledRequestIsPassedDirectlyToTheApplication()
    {
        $app = $this->createApplication();
        $client = $this->createClient($app);

        $client->request('GET', '/not_firewalled');

        $this->assertEquals('Hello, World', $client->getResponse()->getContent());
    }

    public function testRequestToFirewalledAreaWithoutUserOrPasswordIssuesChallenge()
    {
        $app = $this->createApplication();
        $client = $this->createClient($app);

        $client->request('GET', '/firewalled');
        $resp = $client->getResponse();

        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertEquals('Basic realm="TestRealm"', $resp->headers->get('WWW-Authenticate'));
    }

    public function testRequestToFirewalledAreaWithInvalidUsernameIssuesChallenge()
    {
        $app = $this->createApplication();
        $client = $this->createClient($app, ['PHP_AUTH_USER' => 'DoesNotExist']);

        $client->request('GET', '/firewalled');
        $resp = $client->getResponse();

        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertEquals('Basic realm="TestRealm"', $resp->headers->get('WWW-Authenticate'));
    }

    public function testRequestToFirewalledAreaWithInvalidPasswordIssuesChallenge()
    {
        $app = $this->createApplication();
        $client = $this->createClient($app, [
            'PHP_AUTH_USER' => self::USER,
            'PHP_AUTH_PW'   => 'NotTheRightPassword',
        ]);

        $client->request('GET', '/firewalled');
        $resp = $client->getResponse();

        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertEquals('Basic realm="TestRealm"', $resp->headers->get('WWW-Authenticate'));
    }

    public function testRequestToFirewalledAreaWithCorrectUserAndPasswordGetsResponse()
    {
        $app = $this->createApplication();
        $client = $this->createClient($app, [
            'PHP_AUTH_USER' => self::USER,
            'PHP_AUTH_PW'   => self::PASS,
        ]);

        $client->request('GET', '/firewalled');
        $resp = $client->getResponse();

        $this->assertTrue($resp->isOk());
        $this->assertEquals('Hello, World', $resp->getContent());
    }

    public function testKernelThatReturnsWWWAuthenticateStackHeaderIssuesChallenge()
    {
        $app = $this->createApplication($this->kernelReturning(new Response('', 401, [
            'WWW-Authenticate' => 'Stack',
        ])));
        $client = $this->createClient($app);

        $client->request('GET', '/not_firewalled');
        $resp = $client->getResponse();

        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertEquals('Basic realm="TestRealm"', $resp->headers->get('WWW-Authenticate'));
    }

    private function createApplication(HttpKernelInterface $app=null)
    {
        $app = $app ?: $this->kernelReturning(new Response('Hello, World'));
        $authenticator = $this->createAuthenticator();

        $userProvider = new InMemoryUserProvider([
            self::USER  => ['password' => self::PASS, 'roles' => ['ROLE_USER']],
        ]);

        $authManager = new AuthenticationProviderManager([
            new SimpleAuthenticationProvider($authenticator, $userProvider, self::PROVIDERKEY),
        ]);

        $firewall = new Firewall\ChainFirewall([
            new Firewall\PreAuthFirewall('^/firewalled', self::PROVIDERKEY, $authenticator),
        ]);

        $app = (new \Stack\Builder())
            ->push(ChallengingKernel::class, $authenticator)
            ->push(ErrorHandlingKernel::class, $authenticator)
            ->push(FirewallKernel::class, $firewall, $authManager)
            ->resolve($app);

        return $app;
    }

    private function createAuthenticator()
    {
        $encoder = new UserPasswordEncoder(new EncoderFactory([
            // don't do this in real life
            UserInterface::class    => new PlainTextPasswordEncoder(),
        ]));

        return new Authenticator\HttpBasicAuthenticator('TestRealm', $encoder);
    }

    private function createClient(HttpKernelInterface $app, array $server=[])
    {
        return new Client($app, $server);
    }

    private function kernelReturning(Response $resp)
    {
        return new CallableHttpKernel(function () use ($resp) {
            return $resp;
        });
    }
}

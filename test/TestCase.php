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

/**
 * ABC for tests.
 *
 * @since   0.1
 */
abstract class TestCase extends \PHPUnit_Framework_TestCase
{
    protected static function createRequest($path='/', $method='GET')
    {
        return Request::create($path, $method);
    }
}

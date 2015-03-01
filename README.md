# Stack Security

This is an experiment to see how integrating the Symfony [Security Component](http://symfony.com/doc/current/components/security/introduction.html)
into some [StackPHP](http://stackphp.com/) middleware might work.

Look at the [Acceptance Test](https://github.com/chrisguitarguy/StackSecurity/blob/master/test/AcceptanceTest.php)
to see an example of putting everything together.

## Authentication

Authentication is divided into three parts:

1. A `FirewallKernel` that uses a [`Firewall`](https://github.com/chrisguitarguy/StackSecurity/blob/master/src/Authentication/Firewall/Firewall.php)
   object to check if a response can be authenticated or needs a challenge.
1. An `ErrorHandlingKernel` that catches `AuthenticationException` and invokes
   an *Authentication Failure Handler*.
1. A `ChallengingKernel` that invokes an *Authorization Entry Point* if a
   `WWW-Authenticat: Stack` response is received.

## Authorization

There are two parts here:

1. An `AccessCheckingKernel` that uses an *Access Decision Manager* and *Access Map*
   to see if the current user (defined by the *token* in the `stack.authn.token`
   request attribute) can access a URL.
1. An `ErrorHandlingKernel` that listens catches `AccessDeniedException` and
   invokes an *Access Denied Handler*.

## MIT License

Copyright (c) 2015 Christopher Davis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

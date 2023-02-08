<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_password_grant\Kernel;

use Drupal\Component\Serialization\Json;
use Symfony\Component\HttpFoundation\Request;

/**
 * Password tests.
 *
 * @group simple_oauth_password_grant
 */
class PasswordTest extends AuthorizedRequestBase {

  /**
   * Test the password grant.
   */
  public function testPasswordGrant(): void {
    // 1. Test with username and password.
    $parameters = [
      'grant_type' => 'password',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'username' => $this->user->getAccountName(),
      'password' => $this->password,
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertValidTokenResponse($response, TRUE);

    // 2. Test with email and password.
    $parameters = [
      'grant_type' => 'password',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'username' => $this->user->getEmail(),
      'password' => $this->password,
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertValidTokenResponse($response, TRUE);

    // 3. Test with invalid username.
    $parameters = [
      'grant_type' => 'password',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'username' => 'invalid-username',
      'password' => $this->password,
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(400, $response->getStatusCode());
    $parsed_response = Json::decode((string) $response->getContent());
    $this->assertSame('invalid_grant', $parsed_response['error']);

    // 4. Test with invalid password.
    $parameters = [
      'grant_type' => 'password',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'username' => $this->user->getAccountName(),
      'password' => 'invalid-password',
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(400, $response->getStatusCode());
    $parsed_response = Json::decode((string) $response->getContent());
    $this->assertSame('invalid_grant', $parsed_response['error']);
  }

  /**
   * Test the password grant with an inactive user.
   */
  public function testPasswordGrantWithInactiveUser(): void {
    $this->user->set('status', 0)->save();

    $parameters = [
      'grant_type' => 'password',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'username' => $this->user->getAccountName(),
      'password' => $this->password,
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(400, $response->getStatusCode());
    $parsed_response = Json::decode((string) $response->getContent());
    $this->assertSame('invalid_grant', $parsed_response['error']);
  }

}

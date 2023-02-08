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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    \Drupal::configFactory()->getEditable('user.flood')
      ->set('ip_limit', 10)
      ->set('user_limit', 5)
      ->save();
  }

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

  /**
   * Test the password grant flood protection.
   */
  public function testPasswordGrantUserFloodProtection(): void {
    $login = function ($status) {
      $parameters = [
        'grant_type' => 'password',
        'client_id' => $this->client->getClientId(),
        'client_secret' => $this->clientSecret,
        'username' => $this->user->getAccountName(),
        'password' => $status === 'success' ? $this->password : 'wrong-password',
      ];

      $request = Request::create($this->url->toString(), 'POST', $parameters);
      $response = $this->httpKernel->handle($request);

      return $response;
    };

    // Default configuration are 5 failed attempts.
    // 1. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 2. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 3. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 4. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // Successful login resets the flood counter.
    $response = $login('success');
    $this->assertValidTokenResponse($response, TRUE);

    // Fail here to make sure the flood counter is reset.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // Successful login due to flood counter reset.
    $response = $login('success');
    $this->assertValidTokenResponse($response, TRUE);

    // 1. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 2. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 3. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 4. Fail.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // 5. Fail - Flood protection kicks in.
    $response = $login('failed');
    $this->assertEquals(400, $response->getStatusCode());

    // Successful login is not possible anymore.
    $response = $login('success');
    $this->assertEquals(400, $response->getStatusCode());
  }

  /**
   * Test the password grant flood protection.
   */
  public function testPasswordGrantIpFloodProtection(): void {
    $newUser = $this->drupalCreateUser();

    // Flood config is set to max 10 failed attempts per IP.
    for ($i = 0; $i < 10; $i++) {
      $parameters = [
        'grant_type' => 'password',
        'client_id' => $this->client->getClientId(),
        'client_secret' => $this->clientSecret,
        'username' => $newUser->getAccountName(),
        'password' => 'wrong-password',
      ];

      $request = Request::create($this->url->toString(), 'POST', $parameters);
      $response = $this->httpKernel->handle($request);
    }

    // Original user should not be able to login.
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
  }

}

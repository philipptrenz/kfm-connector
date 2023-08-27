<?php

namespace PhilippTrenz\KFMConnector;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

use Kirby\Cms\App;
use Kirby\Http\Request;
use Kirby\Http\Response;
use Kirby\Http\Remote;
use Kirby\Cache\Cache;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;

JWT::$leeway = 60;  // in seconds

final class API {

    private App $kirby;
    private Request $request;
    private Cache $cache;

    private string $issuer;
    private int $jwksCacheDuration;

    public function __construct() {
        $this->kirby   = App::instance();
        $this->request = $this->kirby->request();
        $this->cache   = $this->kirby->cache('philipptrenz.kirby-fleet-manager-connector');

        $this->issuer            = $this->kirby->option('philipptrenz.kirby-fleet-manager-connector.issuer');
        $this->jwksCacheDuration = $this->kirby->option('philipptrenz.kirby-fleet-manager-connector.jwksCacheDuration', 60*24*3);
    }

    private function getJwks($ignoreCache=false): array|null
    {
        if ($ignoreCache) $this->cache->remove('jwks');

        $issuer = $this->issuer;
        $jwksCache = $this->cache->getOrSet('jwks', function() use ($issuer) {
            // Fetch JWKS
            $jwksUrl = rtrim($issuer, '/') . '/jwks';
            $response = Remote::get($jwksUrl);
            return $response->json();

        }, $this->jwksCacheDuration);

        return $jwksCache;
    }

    private function isJWTValid(string $jwt, string $audience, bool $retry = false): bool
    {   
        
        try {
            $jwks = $this->getJwks();  // ignore cache on retry
            $payload = JWT::decode($jwt, JWK::parseKeySet($jwks));
        } catch (InvalidArgumentException $e) {
            // provided key/key-array is empty or malformed.
            return false;
        } catch (DomainException $e) {
            // provided algorithm is unsupported OR
            // provided key is invalid OR
            // unknown error thrown in openSSL or libsodium OR
            // libsodium is required but not available.
            return false;
        } catch (SignatureInvalidException $e) {
            // provided JWT signature verification failed.
            return false;
        } catch (BeforeValidException $e) {
            // provided JWT is trying to be used before "nbf" claim OR
            // provided JWT is trying to be used before "iat" claim.
            return false;
        } catch (ExpiredException $e) {
            // provided JWT is trying to be used after "exp" claim.
            return false;
        } catch (UnexpectedValueException $e) {
            // provided JWT is malformed OR
            // provided JWT is missing an algorithm / using an unsupported algorithm OR
            // provided JWT algorithm does not match provided key OR
            // provided key ID in key/key-array is empty or invalid.

            if ($retry === false) {  // prevent recursion
                // if key ID is missing in JWKS, the cached JWKS might be outdated
                // therefore, force cache update and validate again
                $this->getJwks(true);
                return $this->isJWTValid($jwt, $audience, true);
            }

            return false;
        }
        return $payload->iss === $this->issuer && $payload->aud === $audience;
    }

    private function isAuthorized(): bool 
    {   
        if ($authHeader = $this->request->header('Authorization')) {
            $jwt = str_replace('Bearer ', '', $authHeader);
            $audience = $this->kirby->site()->url();
            return $this->isJWTValid($jwt, $audience) === true;
        }
        return false;
    }

    public function handleRequest(): Response 
    {
        if ($this->isAuthorized() === false) {
            return new Response([
                'code' => 401,
                'message' => 'Not authorized'
            ]);
        }
        return Response::json((new Status)->getStatus());
    }
}
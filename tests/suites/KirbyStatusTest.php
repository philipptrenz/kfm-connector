<?php

use Kirby\Cms\App;
use PHPUnit\Framework\TestCase;
use Swaggest\JsonSchema\Schema;
use PhilippTrenz\KFMConnector\KirbyStatus;

final class KirbyStatusTest extends TestCase
{

    private static string $jsonSchema = <<<'JSON'
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "url": {
      "type": "string"
    },
    "users": {
      "type": "integer"
    },
    "system": {
      "type": "object",
      "properties": {
        "environment": {
          "type": "object",
          "properties": {
            "license": {
              "type": "boolean"
            },
            "version": {
              "type": "string"
            },
            "php": {
              "type": ["string", "null"]
            },
            "server": {
              "type": ["string", "null"]
            }
          },
          "required": [
            "license",
            "version",
            "php",
            "server"
          ]
        },
        "security": {
          "type": "object",
          "properties": {
            "debug": {
              "type": "boolean"
            },
            "https": {
              "type": "boolean"
            }
          },
          "required": [
            "debug",
            "https"
          ]
        },
        "plugins": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "properties": {
                "author": {
                  "type": ["string", "null"]
                },
                "license": {
                  "type": ["string", "null"]
                },
                "link": {
                  "type": ["string", "null"]
                },
                "name": {
                  "type": ["string", "null"]
                },
                "version": {
                  "type": ["string", "null"]
                },
                "latestVersion": {
                  "type": ["string", "null"]
                }
              },
              "required": [
                "author",
                "license",
                "link",
                "name",
                "version"
              ]
            }
          ]
        }
      },
      "required": [
        "environment",
        "security",
        "plugins"
      ]
    }
  },
  "required": [
    "url",
    "users",
    "system"
  ]
}
JSON;

    private App $kirby;

    protected function setUp(): void
    {
        $this->kirby = kirby();
    }

    public function testConformsWithJsonSchema() : void 
    {
        $schema = Schema::import(
            json_decode(self::$jsonSchema)
        );

        $status = (new KirbyStatus)->getStatus();
        $schema->in(
            json_decode(
                json_encode(
                    $status
                )
            )
        );

        $this->assertTrue(true);
    }
}
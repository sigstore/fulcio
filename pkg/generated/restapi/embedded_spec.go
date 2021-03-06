// Code generated by go-swagger; DO NOT EDIT.

// /*
// Copyright The Fulcio Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */
//

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http",
    "https"
  ],
  "swagger": "2.0",
  "info": {
    "title": "Fulcio",
    "version": "1.0.0"
  },
  "host": "fulcio.sigstore.dev",
  "basePath": "/api/v1",
  "paths": {
    "/signingCert": {
      "post": {
        "security": [
          {
            "key": []
          }
        ],
        "description": "create a cert, return content with a location header (with URL to CTL entry)",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "operationId": "signingCert",
        "parameters": [
          {
            "description": "Submit CSR",
            "name": "submitcsr",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Submit"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Successful CSR Submit",
            "schema": {
              "$ref": "#/definitions/SubmitSuccess"
            }
          },
          "400": {
            "description": "Bad Request"
          },
          "401": {
            "description": "Unauthorized",
            "schema": {
              "type": "string"
            }
          },
          "500": {
            "description": "Server error",
            "schema": {
              "type": "string"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "Submit": {
      "type": "object",
      "properties": {
        "proof": {
          "type": "string",
          "format": "byte"
        },
        "pub": {
          "type": "string",
          "format": "byte"
        }
      }
    },
    "SubmitSuccess": {
      "type": "object",
      "properties": {
        "certificate": {
          "type": "string"
        }
      }
    }
  },
  "securityDefinitions": {
    "key": {
      "type": "apiKey",
      "name": "access_token",
      "in": "query"
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "schemes": [
    "http",
    "https"
  ],
  "swagger": "2.0",
  "info": {
    "title": "Fulcio",
    "version": "1.0.0"
  },
  "host": "fulcio.sigstore.dev",
  "basePath": "/api/v1",
  "paths": {
    "/signingCert": {
      "post": {
        "security": [
          {
            "key": []
          }
        ],
        "description": "create a cert, return content with a location header (with URL to CTL entry)",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "operationId": "signingCert",
        "parameters": [
          {
            "description": "Submit CSR",
            "name": "submitcsr",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Submit"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Successful CSR Submit",
            "schema": {
              "$ref": "#/definitions/SubmitSuccess"
            }
          },
          "400": {
            "description": "Bad Request"
          },
          "401": {
            "description": "Unauthorized",
            "schema": {
              "type": "string"
            }
          },
          "500": {
            "description": "Server error",
            "schema": {
              "type": "string"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "Submit": {
      "type": "object",
      "properties": {
        "proof": {
          "type": "string",
          "format": "byte"
        },
        "pub": {
          "type": "string",
          "format": "byte"
        }
      }
    },
    "SubmitSuccess": {
      "type": "object",
      "properties": {
        "certificate": {
          "type": "string"
        }
      }
    }
  },
  "securityDefinitions": {
    "key": {
      "type": "apiKey",
      "name": "access_token",
      "in": "query"
    }
  }
}`))
}

/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package magiclink

import "github.com/asgardeo/thunder/internal/system/error/serviceerror"

// Client errors for Magic Link authentication service.
var (
	// ErrorInvalidRecipient is the error returned when the provided recipient is invalid.
	ErrorInvalidRecipient = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1001",
		Error:            "Invalid recipient",
		ErrorDescription: "The provided recipient email is invalid or empty",
	}
	// ErrorInvalidToken is the error returned when the provided magic link token is invalid.
	ErrorInvalidToken = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1002",
		Error:            "Invalid token",
		ErrorDescription: "The provided magic link token is invalid",
	}
	// ErrorExpiredToken is the error returned when the magic link token has expired.
	ErrorExpiredToken = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1003",
		Error:            "Expired token",
		ErrorDescription: "The magic link token has expired",
	}
	// ErrorMalformedTokenClaims is the error returned when the token claims are malformed.
	ErrorMalformedTokenClaims = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1004",
		Error:            "Malformed token claims",
		ErrorDescription: "The magic link token contains invalid or missing claims",
	}
	// ErrorTokenAlreadyUsed is the error returned when the token has already been used.
	// Reserved for future stateful one-time token mode.
	ErrorTokenAlreadyUsed = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1005",
		Error:            "Token already used",
		ErrorDescription: "The magic link token has already been used",
	}
	// ErrorClientErrorWhileResolvingUser is the error returned when there is a client error while resolving the user.
	ErrorClientErrorWhileResolvingUser = serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "AUTHN-ML-1006",
		Error:            "Error resolving user",
		ErrorDescription: "An error occurred while resolving the user for the recipient",
	}
)

// ErrorMagicLinkNotConfigured is the error returned when magic link service is not configured.
var ErrorMagicLinkNotConfigured = serviceerror.ServiceError{
	Type:             serviceerror.ClientErrorType,
	Code:             "MAGIC_LINK_NOT_CONFIGURED",
	Error:            "Magic link authentication is not configured",
	ErrorDescription: "Magic link service is not available",
}

// Server errors for Magic Link authentication service.
var (
	// ErrorTemplateRenderFailed is the error returned when template rendering fails.
	ErrorTemplateRenderFailed = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-ML-2001",
		Error:            "Template render failed",
		ErrorDescription: "Failed to render the magic link email template",
	}
	// ErrorEmailSendFailed is the error returned when sending the magic link email fails.
	ErrorEmailSendFailed = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-ML-2002",
		Error:            "Email send failed",
		ErrorDescription: "Failed to send the magic link email",
	}
	// ErrorTokenGenerationFailed is the error returned when token generation fails.
	ErrorTokenGenerationFailed = serviceerror.ServiceError{
		Type:             serviceerror.ServerErrorType,
		Code:             "AUTHN-ML-2003",
		Error:            "Token generation failed",
		ErrorDescription: "Failed to generate the magic link token",
	}
)

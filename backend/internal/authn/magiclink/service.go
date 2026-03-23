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

// Package magiclink implements the magic link authentication service.
package magiclink

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/system/config"
	"github.com/asgardeo/thunder/internal/system/email"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/jose/jwt"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/template"
	"github.com/asgardeo/thunder/internal/userprovider"
)

// MagicLinkAuthnServiceInterface defines the interface for magic link authentication operations.
type MagicLinkAuthnServiceInterface interface {
	SendMagicLink(ctx context.Context, recipient string) *serviceerror.ServiceError
	VerifyMagicLink(ctx context.Context, token string) (*userprovider.User, *serviceerror.ServiceError)
}

// magicLinkAuthnService is the default implementation of MagicLinkAuthnServiceInterface.
type magicLinkAuthnService struct {
	jwtService      jwt.JWTServiceInterface
	emailClient     email.EmailClientInterface
	userProvider    userprovider.UserProviderInterface
	templateService template.TemplateServiceInterface
	logger          *log.Logger
}

// newMagicLinkAuthnService creates a new instance of MagicLinkAuthnService.
func newMagicLinkAuthnService(
	jwtSvc jwt.JWTServiceInterface,
	emailClient email.EmailClientInterface,
	userProvider userprovider.UserProviderInterface,
	templateService template.TemplateServiceInterface,
) MagicLinkAuthnServiceInterface {
	service := &magicLinkAuthnService{
		jwtService:      jwtSvc,
		emailClient:     emailClient,
		userProvider:    userProvider,
		templateService: templateService,
		logger:          log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MagicLinkAuthnService")),
	}
	common.RegisterAuthenticator(service.getMetadata())

	return service
}

// SendMagicLink sends a magic link to the specified recipient email address.
// Returns nil on success or error. Does not return the token to prevent user enumeration.
func (s *magicLinkAuthnService) SendMagicLink(ctx context.Context,
	recipient string) *serviceerror.ServiceError {
	s.logger.Debug("Sending magic link", log.String("recipient", log.MaskString(recipient)))

	recipient = strings.TrimSpace(recipient)
	if recipient == "" || !isValidEmail(recipient) {
		return &ErrorInvalidRecipient
	}

	// Privacy-preserving: return success without sending for non-existent users
	// to prevent user enumeration attacks.
	userID, upErr := s.userProvider.IdentifyUser(map[string]interface{}{userAttributeEmail: recipient})
	if upErr != nil {
		if upErr.Code == userprovider.ErrorCodeUserNotFound {
			s.logger.Debug("User not found for recipient, returning success without sending email",
				log.String("recipient", log.MaskString(recipient)))
			return nil
		}
		return &serviceerror.InternalServerError
	}

	if userID == nil || *userID == "" {
		s.logger.Debug("No user found for recipient, returning success without sending email",
			log.String("recipient", log.MaskString(recipient)))
		return nil
	}

	claims := map[string]interface{}{
		claimKeyMagicLinkData: map[string]interface{}{
			claimKeyRecipient: recipient,
			claimKeyUserID:    *userID,
		},
	}

	issuer := config.GetThunderRuntime().Config.JWT.Issuer
	token, _, jwtErr := s.jwtService.GenerateJWT(
		tokenSubject,
		tokenAudience,
		issuer,
		DefaultExpirySeconds,
		claims,
		jwt.TokenTypeJWT,
	)
	if jwtErr != nil {
		return &ErrorTokenGenerationFailed
	}

	verifyURL := s.buildMagicLinkURL(token)

	expiryMinutes := strconv.Itoa(DefaultExpirySeconds / 60)
	templateData := template.TemplateData{
		"magicLink":     verifyURL,
		"expiryMinutes": expiryMinutes,
	}

	rendered, svcErr := s.templateService.Render(ctx, template.ScenarioMagicLink, templateData)
	if svcErr != nil {
		return &ErrorTemplateRenderFailed
	}

	if s.emailClient == nil {
		return &ErrorEmailSendFailed
	}

	sendErr := s.emailClient.Send(email.EmailData{
		To:      []string{recipient},
		Subject: rendered.Subject,
		Body:    rendered.Body,
		IsHTML:  rendered.IsHTML,
	})
	if sendErr != nil {
		return &ErrorEmailSendFailed
	}

	s.logger.Debug("Magic link sent successfully",
		log.String("recipient", log.MaskString(recipient)),
		log.String("expiryMinutes", expiryMinutes))

	return nil
}

// VerifyMagicLink verifies the magic link token and returns the authenticated user.
func (s *magicLinkAuthnService) VerifyMagicLink(ctx context.Context,
	token string) (*userprovider.User, *serviceerror.ServiceError) {
	s.logger.Debug("Verifying magic link token")

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, &ErrorInvalidToken
	}

	// Verify the JWT token.
	issuer := config.GetThunderRuntime().Config.JWT.Issuer
	verifyErr := s.jwtService.VerifyJWT(token, tokenAudience, issuer)
	if verifyErr != nil {
		if verifyErr.Code == jwt.ErrorTokenExpired.Code {
			return nil, &ErrorExpiredToken
		}
		s.logger.Debug("Invalid magic link token", log.String("errorCode", verifyErr.Code))
		return nil, &ErrorInvalidToken
	}

	payload, decodeErr := jwt.DecodeJWTPayload(token)
	if decodeErr != nil {
		s.logger.Debug("Failed to decode magic link token payload", log.Error(decodeErr))
		return nil, &ErrorInvalidToken
	}

	mlData, ok := payload[claimKeyMagicLinkData].(map[string]interface{})
	if !ok {
		s.logger.Debug("Magic link data claim not found or invalid")
		return nil, &ErrorMalformedTokenClaims
	}

	recipient, ok := mlData[claimKeyRecipient].(string)
	if !ok || strings.TrimSpace(recipient) == "" {
		s.logger.Debug("Recipient claim not found or invalid")
		return nil, &ErrorMalformedTokenClaims
	}

	claimUserID := extractString(mlData[claimKeyUserID])
	if claimUserID == "" {
		s.logger.Debug("User ID claim not found or invalid")
		return nil, &ErrorMalformedTokenClaims
	}

	userID, upErr := s.userProvider.IdentifyUser(map[string]interface{}{userAttributeEmail: recipient})
	if upErr != nil {
		return nil, s.handleUserProviderError(upErr)
	}
	if userID == nil || *userID == "" {
		s.logger.Debug("No user found for recipient in token",
			log.String("recipient", log.MaskString(recipient)))
		return nil, &common.ErrorUserNotFound
	}

	if claimUserID != *userID {
		s.logger.Debug("User ID mismatch between token claim and resolved user")
		return nil, &ErrorMalformedTokenClaims
	}

	user, upErr := s.userProvider.GetUser(*userID)
	if upErr != nil {
		return nil, s.handleUserProviderError(upErr)
	}

	s.logger.Debug("Magic link verification successful", log.String("userId", user.UserID))
	return user, nil
}

// buildMagicLinkURL constructs the magic link URL with the token.
func (s *magicLinkAuthnService) buildMagicLinkURL(token string) string {
	base := config.GetServerURL(&config.GetThunderRuntime().Config.Server)
	return base + "/auth/magiclink?token=" + url.QueryEscape(token)
}

// handleUserProviderError converts user provider errors to ServiceError.
func (s *magicLinkAuthnService) handleUserProviderError(
	upErr *userprovider.UserProviderError,
) *serviceerror.ServiceError {
	if upErr.Code == userprovider.ErrorCodeUserNotFound {
		return &common.ErrorUserNotFound
	}
	if upErr.Code == userprovider.ErrorCodeSystemError {
		return &serviceerror.InternalServerError
	}
	return serviceerror.CustomServiceError(ErrorClientErrorWhileResolvingUser,
		fmt.Sprintf("An error occurred while retrieving user: %s", upErr.Description))
}

// getMetadata returns the authenticator metadata for magic link authenticator.
func (s *magicLinkAuthnService) getMetadata() common.AuthenticatorMeta {
	return common.AuthenticatorMeta{
		Name:    common.AuthenticatorMagicLink,
		Factors: []common.AuthenticationFactor{common.FactorPossession},
	}
}

// isValidEmail validates if the provided string is a valid email address.
// Uses mail.ParseAddress for basic parsing and additional checks for stricter validation.
func isValidEmail(emailAddr string) bool {
	addr, err := mail.ParseAddress(emailAddr)
	if err != nil {
		return false
	}

	// mail.ParseAddress accepts formats like "Name <email@domain.com>",
	// but we need to validate the actual email part only.
	email := addr.Address

	// Check for @ and split into local and domain parts
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 || atIndex == 0 || atIndex == len(email)-1 {
		return false
	}

	localPart := email[:atIndex]
	domain := email[atIndex+1:]

	// Validate local part is not empty and doesn't start/end with a dot
	if len(localPart) == 0 || strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return false
	}

	// Validate domain has at least one dot and doesn't start/end with a dot or hyphen
	if !strings.Contains(domain, ".") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}

	return true
}

// extractString safely extracts a string value from an interface{}.
func extractString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

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

package executor

import (
	"errors"
	"fmt"

	authncm "github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/authn/magiclink"
	"github.com/asgardeo/thunder/internal/flow/common"
	"github.com/asgardeo/thunder/internal/flow/core"
	"github.com/asgardeo/thunder/internal/system/log"
	"github.com/asgardeo/thunder/internal/system/observability"
	"github.com/asgardeo/thunder/internal/userprovider"
)

// EmailInput is the input definition for email collection.
var EmailInput = common.Input{
	Ref:        "email_input",
	Identifier: userAttributeEmail,
	Type:       common.InputTypeText,
	Required:   true,
}

// MagicLinkTokenInput is the input definition for magic link token verification.
var MagicLinkTokenInput = common.Input{
	Ref:        "magic_link_token_input",
	Identifier: userInputMagicLinkToken,
	Type:       common.InputTypeText,
	Required:   true,
}

// magicLinkAuthExecutor implements the ExecutorInterface for Magic Link authentication.
type magicLinkAuthExecutor struct {
	core.ExecutorInterface
	identifyingExecutorInterface
	userProvider      userprovider.UserProviderInterface
	magicLinkService  magiclink.MagicLinkAuthnServiceInterface
	observabilitySvc  observability.ObservabilityServiceInterface
	logger            *log.Logger
}

var _ core.ExecutorInterface = (*magicLinkAuthExecutor)(nil)
var _ identifyingExecutorInterface = (*magicLinkAuthExecutor)(nil)

// newMagicLinkAuthExecutor creates a new instance of MagicLinkAuthExecutor.
func newMagicLinkAuthExecutor(
	flowFactory core.FlowFactoryInterface,
	magicLinkService magiclink.MagicLinkAuthnServiceInterface,
	observabilitySvc observability.ObservabilityServiceInterface,
	userProvider userprovider.UserProviderInterface,
) *magicLinkAuthExecutor {
	defaultInputs := []common.Input{
		MagicLinkTokenInput,
	}
	prerequisites := []common.Input{
		EmailInput,
	}

	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "MagicLinkAuthExecutor"),
		log.String(log.LoggerKeyExecutorName, ExecutorNameMagicLinkAuth))

	identifyExec := newIdentifyingExecutor(ExecutorNameMagicLinkAuth, defaultInputs, prerequisites,
		flowFactory, userProvider)
	base := flowFactory.CreateExecutor(ExecutorNameMagicLinkAuth, common.ExecutorTypeAuthentication,
		defaultInputs, prerequisites)

	return &magicLinkAuthExecutor{
		ExecutorInterface:            base,
		identifyingExecutorInterface: identifyExec,
		userProvider:                 userProvider,
		magicLinkService:             magicLinkService,
		observabilitySvc:             observabilitySvc,
		logger:                       logger,
	}
}

// Execute executes the Magic Link authentication logic.
func (m *magicLinkAuthExecutor) Execute(ctx *core.NodeContext) (*common.ExecutorResponse, error) {
	logger := m.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing Magic Link authentication executor")

	execResp := &common.ExecutorResponse{
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}

	if !m.ValidatePrerequisites(ctx, execResp) {
		logger.Debug("Prerequisites not met for Magic Link authentication executor")
		return execResp, nil
	}

	// Determine the executor mode
	switch ctx.ExecutorMode {
	case ExecutorModeSend:
		return m.executeSend(ctx, execResp)
	case ExecutorModeVerify:
		return m.executeVerify(ctx, execResp)
	default:
		return execResp, fmt.Errorf("invalid executor mode: %s", ctx.ExecutorMode)
	}
}

// executeSend executes the magic link sending step.
func (m *magicLinkAuthExecutor) executeSend(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) (*common.ExecutorResponse, error) {
	logger := m.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))

	err := m.InitiateMagicLink(ctx, execResp)
	if err != nil {
		return execResp, err
	}

	logger.Debug("Magic link send completed", log.String("status", string(execResp.Status)))

	return execResp, nil
}

// executeVerify executes the magic link verification step.
func (m *magicLinkAuthExecutor) executeVerify(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) (*common.ExecutorResponse, error) {
	logger := m.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))

	if !m.HasRequiredInputs(ctx, execResp) {
		logger.Debug("Required inputs for Magic Link verification are not provided")
		execResp.Status = common.ExecUserInputRequired
		return execResp, nil
	}

	err := m.ProcessAuthFlowResponse(ctx, execResp)
	if err != nil {
		return execResp, err
	}

	logger.Debug("Magic link verify completed",
		log.String("status", string(execResp.Status)),
		log.Bool("isAuthenticated", execResp.AuthenticatedUser.IsAuthenticated))

	return execResp, nil
}

// InitiateMagicLink initiates the magic link sending process to the user's email address.
func (m *magicLinkAuthExecutor) InitiateMagicLink(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) error {
	logger := m.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Sending magic link to user")

	if m.magicLinkService == nil {
		logger.Error("Magic link service is not configured")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = "Magic link authentication is not configured"
		return nil
	}

	email, err := m.getUserEmailFromContext(ctx)
	if err != nil {
		return err
	}

	var userID *string
	if ctx.AuthenticatedUser.IsAuthenticated {
		userIDVal := m.GetUserIDFromContext(ctx)
		if userIDVal == "" {
			return errors.New("user ID is empty in the context")
		}
		userID = &userIDVal
	} else {
		// Identify user by email if not authenticated
		if email == "" {
			logger.Error("Email is empty in the context")
		}

		filter := map[string]interface{}{userAttributeEmail: email}
		userID, err = m.IdentifyUser(filter, execResp)
		if err != nil {
			logger.Error("Failed to identify user", log.Error(err))
			return fmt.Errorf("failed to identify user: %w", err)
		}
	}

	// Handle registration flows.
	if ctx.FlowType == common.FlowTypeRegistration {
		if execResp.Status == common.ExecFailure && execResp.FailureReason != failureReasonUserNotFound {
			logger.Error("Failed to identify user during registration flow", log.Error(err))
			return fmt.Errorf("failed to identify user during registration flow: %w", err)
		}

		if userID != nil && *userID != "" {
			// At this point, a unique user is found in the system. Hence fail the execution.
			execResp.Status = common.ExecFailure
			execResp.FailureReason = "User already exists with the provided email."
			return nil
		}

		execResp.Status = ""
		execResp.FailureReason = ""
	} else {
		if execResp.Status == common.ExecFailure {
			return nil
		}
		execResp.RuntimeData[userAttributeUserID] = *userID
	}

	// Send the magic link to the user's email address.
	if err := m.sendMagicLink(email, ctx, execResp, logger); err != nil {
		logger.Error("Failed to send magic link", log.Error(err))
		return fmt.Errorf("failed to send magic link: %w", err)
	}
	if execResp.Status == common.ExecFailure {
		return nil
	}

	logger.Debug("Magic link sent successfully")
	execResp.Status = common.ExecComplete

	return nil
}

// ProcessAuthFlowResponse processes the authentication flow response for Magic Link.
func (m *magicLinkAuthExecutor) ProcessAuthFlowResponse(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) error {
	logger := m.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Processing authentication flow response for Magic Link")

	err := m.validateMagicLinkToken(ctx, execResp, logger)
	if err != nil {
		logger.Error("Error validating magic link token", log.Error(err))
		return fmt.Errorf("error validating magic link token: %w", err)
	}
	if execResp.Status == common.ExecFailure {
		return nil
	}

	authenticatedUser, err := m.getAuthenticatedUser(ctx, execResp)
	if err != nil {
		logger.Error("Failed to get authenticated user details", log.Error(err))
		return fmt.Errorf("failed to get authenticated user details: %w", err)
	}

	execResp.AuthenticatedUser = *authenticatedUser
	execResp.Status = common.ExecComplete

	logger.Debug("User authenticated successfully with Magic Link")

	return nil
}

// sendMagicLink sends a magic link to the user's email.
func (m *magicLinkAuthExecutor) sendMagicLink(email string, ctx *core.NodeContext,
	execResp *common.ExecutorResponse, logger *log.Logger) error {
	logger.Debug("Sending magic link to user", log.String("email", log.MaskString(email)))

	svcErr := m.magicLinkService.SendMagicLink(ctx.Context, email)
	if svcErr != nil {
		logger.Error("Failed to send magic link", log.String("error", svcErr.Error))
		execResp.Status = common.ExecFailure
		execResp.FailureReason = "Failed to send magic link"
		return nil
	}

	return nil
}

// validateMagicLinkToken validates the magic link token provided by the user.
func (m *magicLinkAuthExecutor) validateMagicLinkToken(ctx *core.NodeContext,
	execResp *common.ExecutorResponse, logger *log.Logger) error {
	token, ok := ctx.UserInputs[userInputMagicLinkToken]
	if !ok || token == "" {
		logger.Debug("Magic link token not found in user inputs")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = "Magic link token is required"
		return nil
	}

	logger.Debug("Verifying magic link token")
	user, svcErr := m.magicLinkService.VerifyMagicLink(ctx.Context, token)
	if svcErr != nil {
		logger.Error("Failed to verify magic link token", log.String("error", svcErr.Error))
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonInvalidMagicLinkToken
		return nil
	}

	if user == nil {
		logger.Error("User not found after magic link verification")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonUserNotFound
		return nil
	}

	execResp.RuntimeData[userAttributeUserID] = user.UserID
	logger.Debug("Magic link token validated successfully", log.String("userID", user.UserID))

	return nil
}

// getUserEmailFromContext retrieves the user's email from the context.
func (m *magicLinkAuthExecutor) getUserEmailFromContext(ctx *core.NodeContext) (string, error) {
	if email, ok := ctx.UserInputs[userAttributeEmail]; ok && email != "" {
		return email, nil
	}
	if email, ok := ctx.RuntimeData[userAttributeEmail]; ok && email != "" {
		return email, nil
	}
	return "", errors.New("email not found in user inputs or runtime data")
}

// getAuthenticatedUser retrieves the authenticated user details from the user provider.
func (m *magicLinkAuthExecutor) getAuthenticatedUser(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) (*authncm.AuthenticatedUser, error) {
	userID, ok := execResp.RuntimeData[userAttributeUserID]
	if !ok || userID == "" {
		return nil, errors.New("user ID not found in runtime data")
	}

	user, err := m.userProvider.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &authncm.AuthenticatedUser{
		IsAuthenticated: true,
		UserID:          user.UserID,
		UserType:        user.UserType,
		OUID:            user.OUID,
	}, nil
}

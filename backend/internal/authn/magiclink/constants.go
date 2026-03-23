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

const (
	// DefaultExpirySeconds is the default expiry time for magic link tokens in seconds.
	DefaultExpirySeconds = 300

	// tokenSubject is the subject claim for magic link tokens.
	tokenSubject = "magiclink-svc"

	// tokenAudience is the audience claim for magic link tokens.
	tokenAudience = "magiclink-svc"

	// claimKeyMagicLinkData is the claim key for magic link specific data in the JWT.
	claimKeyMagicLinkData = "ml_data"

	// claimKeyRecipient is the claim key for the recipient email address.
	claimKeyRecipient = "recipient"

	// claimKeyUserID is the claim key for the user ID.
	claimKeyUserID = "user_id"

	// userAttributeEmail is the user attribute name for email.
	userAttributeEmail = "email"
)

/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

const response = await fetch('/runtime.json');
const runtimeConfig = await response.json();

const placeholderValuePattern = /^\{[^{}]+\}$/;

// Helper to parse boolean values that can be either boolean or string (from env or runtime.json)
const parseBoolean = (value: boolean | string | undefined, defaultValue: boolean): boolean => {
    if (value === undefined || value === '') return defaultValue;
    if (typeof value === 'boolean') return value;
    return value.toLowerCase() === 'true';
};

const resolveStringValue = (runtimeValue?: string, envValue?: string): string => {
    const runtimeCandidate = runtimeValue?.trim();
    if (runtimeCandidate && !placeholderValuePattern.test(runtimeCandidate)) {
        return runtimeCandidate;
    }

    const envCandidate = envValue?.trim();
    if (envCandidate && !placeholderValuePattern.test(envCandidate)) {
        return envCandidate;
    }

    return '';
};

const config = {
    applicationID: resolveStringValue(runtimeConfig.applicationID, import.meta.env.VITE_REACT_APP_AUTH_APP_ID),
    applicationsEndpoint: resolveStringValue(
        runtimeConfig.applicationsEndpoint,
        import.meta.env.VITE_REACT_APPLICATIONS_ENDPOINT,
    ),
    flowEndpoint: resolveStringValue(runtimeConfig.flowEndpoint, import.meta.env.VITE_REACT_APP_SERVER_FLOW_ENDPOINT),
    redirectBasedLogin: parseBoolean(runtimeConfig.redirectBasedLogin ?? import.meta.env.VITE_REACT_APP_REDIRECT_BASED_LOGIN, false),
    authorizationEndpoint: resolveStringValue(
        runtimeConfig.authorizationEndpoint,
        import.meta.env.VITE_REACT_APP_SERVER_AUTHORIZATION_ENDPOINT,
    ),
    tokenEndpoint: resolveStringValue(runtimeConfig.tokenEndpoint, import.meta.env.VITE_REACT_APP_SERVER_TOKEN_ENDPOINT),
    clientId: resolveStringValue(runtimeConfig.clientId, import.meta.env.VITE_REACT_APP_CLIENT_ID),
    redirectUri: resolveStringValue(runtimeConfig.redirectUri, import.meta.env.VITE_REACT_APP_REDIRECT_URI),
    scope: resolveStringValue(runtimeConfig.scope, import.meta.env.VITE_REACT_APP_SCOPE)
};

export default config;

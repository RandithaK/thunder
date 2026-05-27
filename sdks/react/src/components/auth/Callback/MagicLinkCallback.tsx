/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

import {
  EmbeddedSignInFlowStatusV2,
  EmbeddedSignInFlowTypeV2,
  navigate as browserNavigate,
} from '@thunderid/browser';
import type {EmbeddedSignInFlowResponseV2} from '@thunderid/browser';
import {FC, useEffect, useRef} from 'react';
import useThunderID from '../../../contexts/ThunderID/useThunderID';

export interface MagicLinkCallbackProps {
  onError?: (error: Error) => void;
  onNavigate?: (path: string) => void;
  onSuccess?: (authData: Record<string, any>) => void;
  signInPath?: string;
}

export const MagicLinkCallback: FC<MagicLinkCallbackProps> = ({
  onNavigate,
  onError,
  onSuccess,
  signInPath = '/signin',
}: MagicLinkCallbackProps) => {
  const processingRef: any = useRef(false);
  const {isInitialized, isLoading, signIn} = useThunderID();

  const navigate = (path: string): void => {
    if (onNavigate) {
      onNavigate(path);
    } else {
      browserNavigate(path);
    }
  };

  const clearTokenFromUrl = (): void => {
    if (!window?.location?.href) {
      return;
    }

    const url: URL = new URL(window.location.href);
    url.searchParams.delete('token');
    window.history.replaceState({}, '', url.toString());
  };



  const initiateOAuthRedirect = (redirectURL: string): void => {
    const redirectUrlObj: URL = new URL(redirectURL);
    const state: string = redirectUrlObj.searchParams.get('state') || crypto.randomUUID();

    sessionStorage.setItem(
      `thunderid_oauth_${state}`,
      JSON.stringify({
        path: signInPath,
        timestamp: Date.now(),
      }),
    );

    browserNavigate(redirectUrlObj.toString());
  };

  const buildSignInPath = (executionId?: string | null, applicationId?: string | null): string => {
    const params: URLSearchParams = new URLSearchParams();
    if (executionId) {
      params.set('executionId', executionId);
    }
    if (applicationId) {
      params.set('applicationId', applicationId);
    }

    return params.toString() ? `${signInPath}?${params.toString()}` : signInPath;
  };

  const redirectWithError = (error: Error): void => {
    sessionStorage.removeItem('thunderid_execution_id');

    onError?.(error);

    const params: URLSearchParams = new URLSearchParams();
    params.set('error', 'magic_link_failed');
    params.set('error_description', error.message);
    navigate(`${signInPath}?${params.toString()}`);
  };

  useEffect(() => {
    if (!isInitialized || isLoading || processingRef.current) {
      return;
    }

    const processMagicLink = async (): Promise<void> => {
      processingRef.current = true;

      try {
        const urlParams: URLSearchParams = new URLSearchParams(window.location.search);
        const executionId: string | null = urlParams.get('id');
        const token: string | null = urlParams.get('token');
        const applicationId: string | null = urlParams.get('applicationId');

        clearTokenFromUrl();

        if (!executionId || !token) {
          const error = new Error('Missing executionId or token in Magic Link URL');
          // eslint-disable-next-line no-console
          console.error('Magic Link callback error:', error);
          redirectWithError(error);
          return;
        }

        const response: EmbeddedSignInFlowResponseV2 = (await signIn({
          executionId,
          inputs: {
            token,
          },
        })) as EmbeddedSignInFlowResponseV2;

        if (response.type === EmbeddedSignInFlowTypeV2.Redirection) {
          const redirectURL: string | undefined = (response.data as any)?.redirectURL || (response as any)?.redirectURL;
          const nextExecutionId: string = response.executionId || executionId;

          sessionStorage.setItem('thunderid_execution_id', nextExecutionId);

          if (redirectURL) {
            initiateOAuthRedirect(redirectURL);
            return;
          }
        }

        if (response.flowStatus === EmbeddedSignInFlowStatusV2.Complete) {
          const redirectUrl: string | undefined = (response as any)?.redirectUrl || (response as any)?.redirect_uri;

          sessionStorage.removeItem('thunderid_execution_id');
          localStorage.removeItem('thunderid_auth_id');

          onSuccess?.({
            redirectUrl,
            ...(response.data || {}),
          });

          if (redirectUrl && window?.location) {
            window.location.href = redirectUrl;
            return;
          }

          navigate(signInPath);
          return;
        }

        if (response.flowStatus === EmbeddedSignInFlowStatusV2.Error) {
          const failureReason: string | undefined = (response as any)?.failureReason;
          const error = new Error(failureReason || 'Magic Link authentication failed. Please try again.');
          // eslint-disable-next-line no-console
          console.error('Magic Link callback error:', error);
          redirectWithError(error);
          return;
        }

        const nextExecutionId: string = response.executionId || executionId;
        sessionStorage.setItem('thunderid_execution_id', nextExecutionId);
        navigate(buildSignInPath(nextExecutionId, applicationId));
      } catch (err) {
        const error: Error = err instanceof Error ? err : new Error('Magic Link callback processing failed');
        // eslint-disable-next-line no-console
        console.error('Magic Link callback error:', err);
        redirectWithError(error);
      }
    };

    processMagicLink();
  }, [isInitialized, isLoading, onError, onNavigate, onSuccess, signIn, signInPath]);

  return null;
};

export default MagicLinkCallback;

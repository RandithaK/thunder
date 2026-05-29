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

import {render, waitFor} from '@testing-library/react';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {MagicLinkCallback} from '../MagicLinkCallback';

const mockSignIn: any = vi.fn();
const mockGetHybridDataParameter: any = vi.fn();
const mockRemoveHybridDataParameter: any = vi.fn();

const thunderIDContext: any = {
  afterSignInUrl: undefined,
  getStorageManager: vi.fn(() =>
    Promise.resolve({
      getHybridDataParameter: mockGetHybridDataParameter,
      removeHybridDataParameter: mockRemoveHybridDataParameter,
    }),
  ),
  isInitialized: true,
  isLoading: false,
  signIn: mockSignIn,
};

vi.mock('../../../../contexts/ThunderID/useThunderID', () => ({
  default: () => thunderIDContext,
}));

describe('MagicLinkCallback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    window.history.replaceState({}, '', '/');
    mockGetHybridDataParameter.mockResolvedValue(undefined);
    mockRemoveHybridDataParameter.mockResolvedValue(undefined);
  });

  afterEach(() => {
    sessionStorage.clear();
    window.history.replaceState({}, '', '/');
  });

  it('verifies the Magic Link token on the callback route and removes it from the URL', async () => {
    const onNavigate: any = vi.fn();
    mockSignIn.mockResolvedValue({
      executionId: 'next-exec',
      flowStatus: 'INCOMPLETE',
      type: 'VIEW',
    });
    window.history.replaceState({}, '', '/magiclink?id=exec-1&applicationId=app-1&token=secret-token');

    render(<MagicLinkCallback onNavigate={onNavigate} />);

    await waitFor(() => {
      expect(mockSignIn).toHaveBeenCalledWith({
        executionId: 'exec-1',
        inputs: {
          token: 'secret-token',
        },
      });
    });

    expect(new URL(window.location.href).searchParams.get('token')).toBeNull();
    expect(sessionStorage.getItem('thunderid_execution_id')).toBe('next-exec');
    expect(onNavigate).toHaveBeenCalledWith('/signin?id=next-exec&applicationId=app-1');
  });

  it('redirects to sign-in with an error when required parameters are missing', async () => {
    const onError: any = vi.fn();
    const onNavigate: any = vi.fn();
    window.history.replaceState({}, '', '/magiclink?id=exec-1');

    render(<MagicLinkCallback onError={onError} onNavigate={onNavigate} />);

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.objectContaining({message: 'Missing executionId or token in Magic Link URL'}));
    });

    expect(mockSignIn).not.toHaveBeenCalled();
    expect(onNavigate).toHaveBeenCalledWith(
      '/signin?error=magic_link_failed&error_description=Missing+executionId+or+token+in+Magic+Link+URL',
    );
  });

  it('redirects to sign-in with an error when verification fails', async () => {
    const onError: any = vi.fn();
    const onNavigate: any = vi.fn();
    mockSignIn.mockRejectedValue(new Error('Invalid magic link'));
    window.history.replaceState({}, '', '/magiclink?id=exec-1&token=secret-token');

    render(<MagicLinkCallback onError={onError} onNavigate={onNavigate} />);

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.objectContaining({message: 'Invalid magic link'}));
    });

    expect(onNavigate).toHaveBeenCalledWith('/signin?error=magic_link_failed&error_description=Invalid+magic+link');
  });

  it('redirects to sign-up when hybrid storage indicates a registration flow', async () => {
    const onNavigate: any = vi.fn();
    mockSignIn.mockResolvedValue({
      executionId: 'next-exec',
      flowStatus: 'INCOMPLETE',
      type: 'VIEW',
    });
    mockGetHybridDataParameter.mockResolvedValue(true);

    window.history.replaceState({}, '', '/magiclink?id=exec-1&applicationId=app-1&token=secret-token');

    render(<MagicLinkCallback onNavigate={onNavigate} />);

    await waitFor(() => {
      expect(mockSignIn).toHaveBeenCalledWith({
        executionId: 'exec-1',
        inputs: {
          token: 'secret-token',
        },
      });
    });

    expect(new URL(window.location.href).searchParams.get('token')).toBeNull();
    expect(sessionStorage.getItem('thunderid_execution_id')).toBe('next-exec');
    expect(onNavigate).toHaveBeenCalledWith('/signup?id=next-exec&applicationId=app-1');
  });
});

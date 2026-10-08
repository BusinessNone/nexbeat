import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import type { AppConfig } from '../api/types'
import { AuthContext, type AuthState } from '../auth/AuthContext'
import { startI18n } from '../i18n'
import { LoginPage } from './LoginPage'

const CONFIG: AppConfig = {
  version: '1.2.0',
  needs_setup: false,
  mail_configured: false,
  default_language: 'en',
  previews_enabled: true,
  requests_enabled: true,
  oidc_enabled: true,
  oidc_name: 'Microsoft',
}

function show(config: Partial<AppConfig>, url = '/') {
  const value: AuthState = {
    status: 'ready',
    user: null,
    config: { ...CONFIG, ...config },
    needsSetup: false,
    login: vi.fn(),
    startSession: vi.fn(),
    logout: vi.fn(),
    refreshUser: vi.fn(async () => undefined),
    updateUser: vi.fn(),
  }
  return render(
    <AuthContext.Provider value={value}>
      <MemoryRouter initialEntries={[url]}>
        <LoginPage />
      </MemoryRouter>
    </AuthContext.Provider>,
  )
}

describe('LoginPage with single sign-on', () => {
  beforeAll(async () => {
    await startI18n('en')
  })

  it('offers the provider button only when the server says it is ready', () => {
    const { unmount } = show({ oidc_enabled: false })
    expect(screen.queryByRole('button', { name: /Sign in with/ })).toBeNull()
    unmount()
    show({})
    expect(screen.getByRole('button', { name: 'Sign in with Microsoft' })).toBeTruthy()
  })

  it('explains an error the server sent back in the address', () => {
    show({}, '/?sso_error=sso_domain_not_allowed')
    expect(screen.getByText(/not allowed to use nexbeat/)).toBeTruthy()
  })

  it('ignores a made-up error code', () => {
    show({}, '/?sso_error=<script>')
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

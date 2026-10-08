import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { api, errorMessage } from '../../api/client'
import { Button, Card, ErrorBanner, Field, OkBanner, PageLoading, Toggle } from '../../components/ui'
import { useSettings } from './useSettings'

/** Anmeldung ueber OIDC (Entra, Keycloak, Google ...). Wer aus einer erlaubten Domaene kommt, bekommt ein Konto. */
export function AdminSsoSettings() {
  const { t } = useTranslation()
  const { query, settings, save } = useSettings()
  const filled = useRef(false)
  const [copied, setCopied] = useState(false)
  const [draft, setDraft] = useState({
    oidc_enabled: false,
    oidc_name: 'Microsoft',
    oidc_issuer: '',
    oidc_client_id: '',
    oidc_client_secret: '',
    oidc_allowed_domains: '',
    oidc_auto_create: true,
  })

  useEffect(() => {
    if (!settings || filled.current) return
    filled.current = true
    setDraft({
      oidc_enabled: settings.oidc_enabled,
      oidc_name: settings.oidc_name,
      oidc_issuer: settings.oidc_issuer,
      oidc_client_id: settings.oidc_client_id,
      // Bleibt leer: Ein versehentliches Speichern soll das Geheimnis nicht ersetzen.
      oidc_client_secret: '',
      oidc_allowed_domains: settings.oidc_allowed_domains,
      oidc_auto_create: settings.oidc_auto_create,
    })
  }, [settings])

  const test = useMutation({
    mutationFn: () => api.post<{ ok: boolean }>('/api/settings/test/oidc', { issuer: draft.oidc_issuer.trim() || null }),
  })

  if (query.isPending) return <PageLoading />

  function update(patch: Partial<typeof draft>) {
    setDraft((current) => ({ ...current, ...patch }))
    test.reset()
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    save.mutate(draft)
  }

  const redirectUri = `${settings?.public_url || window.location.origin}/api/auth/oidc/callback`
  const complete =
    Boolean(draft.oidc_issuer.trim() && draft.oidc_client_id.trim() && draft.oidc_allowed_domains.trim()) &&
    (Boolean(draft.oidc_client_secret) || Boolean(settings?.oidc_client_secret_set))

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Card className="flex flex-col gap-4">
        <div>
          <h2 className="text-lg font-semibold">{t('sso.title')}</h2>
          <p className="mt-1 text-sm text-mist-500">{t('sso.intro')}</p>
        </div>
        <Toggle
          label={t('sso.enabled')}
          hint={t('sso.enabledHint')}
          checked={draft.oidc_enabled}
          onChange={(checked) => update({ oidc_enabled: checked })}
        />
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium text-mist-300">{t('sso.redirectUri')}</span>
          <div className="flex items-center gap-3">
            <code className="min-w-0 flex-1 truncate rounded-md bg-ink-900 px-3 py-2 text-sm text-mist-200">{redirectUri}</code>
            <Button
              type="button"
              variant="ghost"
              onClick={() => void navigator.clipboard?.writeText(redirectUri).then(() => setCopied(true))}
            >
              {copied ? t('common.copied') : t('common.copy')}
            </Button>
          </div>
          <span className="text-xs text-mist-500">{t('sso.redirectUriHint')}</span>
        </div>
        <Field
          label={t('sso.issuer')}
          value={draft.oidc_issuer}
          onChange={(event) => update({ oidc_issuer: event.target.value })}
          placeholder="https://login.microsoftonline.com/…/v2.0"
          hint={t('sso.issuerHint')}
          autoComplete="off"
        />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field
            label={t('sso.clientId')}
            value={draft.oidc_client_id}
            onChange={(event) => update({ oidc_client_id: event.target.value })}
            autoComplete="off"
          />
          <Field
            label={t('sso.clientSecret')}
            type="password"
            value={draft.oidc_client_secret}
            onChange={(event) => update({ oidc_client_secret: event.target.value })}
            placeholder={settings?.oidc_client_secret_set ? settings.oidc_client_secret : ''}
            hint={settings?.oidc_client_secret_set ? t('common.secretSetHint') : undefined}
            autoComplete="new-password"
          />
        </div>
        <Field
          label={t('sso.domains')}
          value={draft.oidc_allowed_domains}
          onChange={(event) => update({ oidc_allowed_domains: event.target.value })}
          placeholder="example.com"
          hint={t('sso.domainsHint')}
          autoComplete="off"
        />
        <Toggle
          label={t('sso.autoCreate')}
          hint={t('sso.autoCreateHint')}
          checked={draft.oidc_auto_create}
          onChange={(checked) => update({ oidc_auto_create: checked })}
        />
        <Field
          label={t('sso.name')}
          value={draft.oidc_name}
          onChange={(event) => update({ oidc_name: event.target.value })}
          hint={t('sso.nameHint')}
          maxLength={40}
          autoComplete="off"
        />
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" loading={save.isPending}>
            {t('common.save')}
          </Button>
          <Button type="button" variant="ghost" onClick={() => test.mutate()} loading={test.isPending} disabled={!draft.oidc_issuer.trim()}>
            {t('sso.test')}
          </Button>
          {test.isSuccess && <span className="text-sm text-ok-500">{t('sso.testOk')}</span>}
          {test.isError && <span className="text-sm text-bad-500">{errorMessage(test.error)}</span>}
        </div>
        {save.isError && <ErrorBanner message={errorMessage(save.error)} />}
        {save.isSuccess && <OkBanner message={draft.oidc_enabled && !complete ? t('sso.notReady') : t('common.saved')} />}
      </Card>
    </form>
  )
}

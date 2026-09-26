import type { MusicRequest } from '../api/types'
import { canRetry, handingOver } from './requests'

function request(status: MusicRequest['status'], errorCode = ''): Pick<MusicRequest, 'status' | 'error_code'> {
  return { status, error_code: errorCode }
}

describe('retry in the admin list', () => {
  it('is offered for failed requests and dry runs only', () => {
    expect(canRetry(request('failed', 'album_not_in_lidarr'))).toBe(true)
    expect(canRetry(request('approved', 'dry_run'))).toBe(true)
    expect(canRetry(request('approved', 'lidarr_timeout'))).toBe(false)
    expect(canRetry(request('approved', 'lidarr_pending'))).toBe(false)
    expect(canRetry(request('searching'))).toBe(false)
  })
})

describe('hand-over to nexcrate', () => {
  it('shows an approved request with an open hand-over as being handed over', () => {
    // 25.09.2026: nexcrate brauchte 90 Sekunden, der Proxy meldete 504, obwohl die Anfrage ankam.
    expect(handingOver(request('approved', 'nexcrate_pending'))).toBe(true)
    expect(handingOver(request('approved', 'nexcrate_timeout'))).toBe(true)
    expect(handingOver(request('approved', 'nexcrate_unavailable'))).toBe(true)
    expect(handingOver(request('approved', 'dry_run'))).toBe(false)
    expect(handingOver(request('approved'))).toBe(false)
    expect(handingOver(request('searching'))).toBe(false)
    expect(handingOver(request('failed', 'nexcrate_refused'))).toBe(false)
  })
})

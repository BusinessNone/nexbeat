import type { MusicRequest } from '../api/types'

/**
 * Erneut senden gibt es nur fuer gescheiterte Anfragen und den Probelauf.
 * 12.09.2026: Solange nexbeat noch nachsah, ob Lidarr eine Anfrage bekommen hatte, liess erneutes Senden sie scheitern.
 */
/** Kennungen einer Anfrage, die nexcrate noch nicht bestaetigt hat. nexbeat sendet sie von selbst weiter. */
const HANDOVER_CODES = ['nexcrate_pending', 'nexcrate_timeout', 'nexcrate_unreachable', 'nexcrate_busy', 'nexcrate_unavailable']

/**
 * Freigegeben, aber von nexcrate noch nicht bestaetigt: "wird uebergeben".
 * 25.09.2026: nexcrate brauchte 90 Sekunden, der Proxy meldete 504, obwohl die Anfrage ankam.
 */
export function handingOver(request: Pick<MusicRequest, 'status' | 'error_code'>): boolean {
  return request.status === 'approved' && HANDOVER_CODES.includes(request.error_code)
}

export function canRetry(request: Pick<MusicRequest, 'status' | 'error_code'>): boolean {
  return request.status === 'failed' || (request.status === 'approved' && request.error_code === 'dry_run')
}

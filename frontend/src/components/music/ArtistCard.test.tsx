import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import type { ArtistItem } from '../../api/types'
import { startI18n } from '../../i18n'
import { ArtistCard } from './ArtistCard'

beforeAll(async () => {
  await startI18n('de')
})

function show(artist: Partial<ArtistItem>) {
  const item: ArtistItem = { mbid: 'a', name: 'Logic', image: '', in_library: false, ...artist }
  render(
    <MemoryRouter>
      <ArtistCard artist={item} />
    </MemoryRouter>,
  )
}

describe('artist card', () => {
  it('tells namesakes apart by country and description', () => {
    // 25.09.2026: Die Suche nach "logic" zeigte zwoelf gleiche Karten, man konnte leicht den Falschen anfragen.
    show({ namesakes: true, country: 'GB', disambiguation: 'UK rapper' })
    expect(screen.getByText('GB · UK rapper')).toBeInTheDocument()
  })

  it('stays plain when the name is unique', () => {
    show({ namesakes: false, country: 'GB', disambiguation: 'UK rapper' })
    expect(screen.queryByText('GB · UK rapper')).not.toBeInTheDocument()
  })
})

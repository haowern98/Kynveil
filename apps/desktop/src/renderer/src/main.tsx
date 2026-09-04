import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

const root = document.getElementById('root')

if (root === null) {
  throw new Error('Kynveil renderer root is missing')
}

createRoot(root).render(
  <StrictMode>
    <main>
      <h1>Kynveil</h1>
      <p>Secure desktop foundation</p>
    </main>
  </StrictMode>
)

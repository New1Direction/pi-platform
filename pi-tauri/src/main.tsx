import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// Apply the saved theme before first paint to avoid a light flash.
document.documentElement.dataset.theme = localStorage.getItem('pi_theme') === 'dark' ? 'dark' : 'light'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

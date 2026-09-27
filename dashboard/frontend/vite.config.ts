import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The brand pack this build uses: src/brand/<VITE_BRAND>, imported in the app as "@brand".
const brandName = process.env.VITE_BRAND || 'harborlight'
const brandDir = fileURLToPath(new URL(`./src/brand/${brandName}`, import.meta.url))
if (!/^[a-z0-9-]+$/.test(brandName) || !existsSync(`${brandDir}/index.ts`)) {
  throw new Error(`VITE_BRAND=${brandName}: there's no brand pack at src/brand/${brandName}`)
}

/** The brand's page title and favicon (inlined, so nothing brand-specific sits in public/). */
function brandHtml(): Plugin {
  return {
    name: 'brand-html',
    transformIndexHtml(html) {
      const { title } = JSON.parse(readFileSync(`${brandDir}/meta.json`, 'utf8')) as { title: string }
      const favicon = readFileSync(`${brandDir}/favicon.svg`, 'utf8').trim()
      const escape = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
      return html
        .replace('%BRAND_TITLE%', escape(title))
        .replace('%BRAND_FAVICON%', `data:image/svg+xml,${encodeURIComponent(favicon)}`)
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), brandHtml()],
  resolve: { alias: { '@brand': brandDir } },
})

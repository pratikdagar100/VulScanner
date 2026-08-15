/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Origin of the VulScanner API, e.g. https://vulscanner.internal.example.
   * Leave unset for same-origin, which covers the dev proxy and any deployment
   * that serves the UI and the API behind one reverse proxy.
   */
  readonly VITE_API_BASE_URL?: string;

  /**
   * Set to "true" for a UI-only deployment with no API behind it (a public
   * showcase of the interface). The app then says so plainly instead of
   * presenting connection failures as if something were broken.
   */
  readonly VITE_UI_ONLY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

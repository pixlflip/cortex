import {
  Activity, Archive, BookOpen, Bot, Boxes, ChevronDown, ChevronRight,
  CircleGauge, Copy, Database, Download, FileText, Folder, FolderOpen, KeyRound, Link2,
  LogOut, Menu, Moon, Network, Plus, RefreshCw, Search, Server, Settings,
  ShieldCheck, Sun, Trash2, UserPlus, Users, Vault, Wrench,
} from 'lucide-react'
import {
  createContext, FormEvent, ReactNode, useCallback, useContext, useEffect,
  useRef, useState,
} from 'react'
import ReactMarkdown from 'react-markdown'
import rehypeSanitize from 'rehype-sanitize'
import remarkGfm from 'remark-gfm'
import {
  Link, Navigate, NavLink, Route, Routes, useNavigate,
  useParams, useSearchParams,
} from 'react-router-dom'

type Json = Record<string, any>
type User = {
  username: string; display_name?: string; email?: string; auth_source: 'local' | 'ldap'
  is_admin: boolean; disabled: boolean; groups: string[]; created_at: number; last_login_at?: number
}

class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message); this.status = status; this.code = code
  }
}

async function api<T = Json>(path: string, options: RequestInit = {}, csrf?: string | null): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (csrf && !['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase())) {
    headers.set('X-Cortex-CSRF', csrf)
  }
  const response = await fetch(`/api/v1${path}`, { ...options, headers, credentials: 'same-origin' })
  if (response.status === 204) return undefined as T
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    const error = body.error || {}
    throw new ApiError(response.status, error.code || 'request_failed', error.message || response.statusText)
  }
  return body as T
}

type AuthState = {
  user: User | null; csrf: string | null; loading: boolean
  login: (username: string, password: string) => Promise<void>; logout: () => Promise<void>
  refresh: () => Promise<void>
}
const AuthContext = createContext<AuthState | null>(null)
const useAuth = () => useContext(AuthContext)!

function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [csrf, setCsrf] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const refresh = useCallback(async () => {
    try {
      const data = await api<{ user: User; csrf_token?: string }>('/auth/me')
      setUser(data.user); setCsrf(data.csrf_token || null)
    } catch { setUser(null); setCsrf(null) }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { void refresh() }, [refresh])
  const login = async (username: string, password: string) => {
    const data = await api<{ user: User; csrf_token: string }>('/auth/login', {
      method: 'POST', body: JSON.stringify({ username, password }),
    })
    setUser(data.user); setCsrf(data.csrf_token)
  }
  const logout = async () => {
    await api('/auth/logout', { method: 'POST' }, csrf)
    setUser(null); setCsrf(null)
  }
  return <AuthContext.Provider value={{ user, csrf, loading, login, logout, refresh }}>{children}</AuthContext.Provider>
}

function useLoad<T>(loader: () => Promise<T>, dependencies: any[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const reload = useCallback(async () => {
    setLoading(true); setError(null)
    try { setData(await loader()) } catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setLoading(false) }
  }, dependencies)
  useEffect(() => { void reload() }, [reload])
  return { data, error, loading, reload, setData }
}

function App() {
  return <AuthProvider><AppRoutes /></AuthProvider>
}

function AppRoutes() {
  const auth = useAuth()
  if (auth.loading) return <Splash />
  return <Routes>
    <Route path="/login" element={auth.user ? <Navigate to="/vault" replace /> : <LoginPage />} />
    <Route path="/*" element={auth.user ? <Shell /> : <Navigate to="/login" replace />} />
  </Routes>
}

function Splash() {
  return <div className="splash"><div className="brand-mark"><Network /></div><p>Waking Cortex…</p></div>
}

function LoginPage() {
  const auth = useAuth(); const navigate = useNavigate()
  const [username, setUsername] = useState(''); const [password, setPassword] = useState('')
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError('')
    try { await auth.login(username, password); navigate('/vault') }
    catch (err) { setError(err instanceof Error ? err.message : 'Login failed') }
    finally { setBusy(false) }
  }
  return <main className="login-page">
    <section className="login-story">
      <div className="brand-lockup"><div className="brand-mark"><Network /></div><span>CORTEX</span></div>
      <div className="story-copy"><p className="eyebrow">GOVERNED MEMORY</p><h1>Your knowledge.<br /><em>Alive and accountable.</em></h1>
        <p>One private memory layer for people and AI—scoped by identity, audited by design, and always yours.</p></div>
      <div className="orbit"><span /><span /><span /><div><ShieldCheck /><small>Private by default</small></div></div>
    </section>
    <section className="login-panel"><form className="login-card" onSubmit={submit}>
      <div><p className="eyebrow">WELCOME BACK</p><h2>Enter your Cortex</h2><p>Local and directory accounts use the same secure entrance.</p></div>
      <label>Username<input autoFocus autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} /></label>
      <label>Password<input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></label>
      {error && <div className="error-banner">{error}</div>}
      <button className="button primary" disabled={busy}>{busy ? 'Opening…' : 'Open Cortex'}<ChevronRight /></button>
      <small className="login-note"><ShieldCheck /> Credentials are verified by your Cortex server.</small>
    </form></section>
  </main>
}

const primaryNav = [
  ['/vault', BookOpen, 'Vault'], ['/tokens', KeyRound, 'Tokens'], ['/mcp', Bot, 'MCP Tools'],
] as const
const adminNav = [
  ['/admin/overview', CircleGauge, 'Overview'], ['/admin/users', Users, 'People'],
  ['/admin/vaults', Vault, 'Vaults'], ['/admin/gateway', Network, 'Gateway'],
  ['/admin/audit', Activity, 'Audit'],
] as const

function Shell() {
  const auth = useAuth(); const navigate = useNavigate(); const [mobile, setMobile] = useState(false)
  const [theme, setTheme] = useState(() => localStorage.getItem('cortex-theme') || 'dark')
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('cortex-theme', theme) }, [theme])
  useEffect(() => { const shortcut = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); navigate('/vault'); setTimeout(() => window.dispatchEvent(new Event('cortex-focus-search')), 0) } }; window.addEventListener('keydown', shortcut); return () => window.removeEventListener('keydown', shortcut) }, [navigate])
  return <div className="app-shell">
    <aside className={`sidebar ${mobile ? 'open' : ''}`}>
      <Link className="brand-lockup compact" to="/vault"><div className="brand-mark"><Network /></div><span>CORTEX</span></Link>
      <nav><p className="nav-label">WORKSPACE</p>{primaryNav.map(([to, Icon, label]) => <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}><Icon />{label}</NavLink>)}
        {auth.user?.is_admin && <><p className="nav-label">ADMINISTRATION</p>{adminNav.map(([to, Icon, label]) => <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}><Icon />{label}</NavLink>)}</>}
      </nav>
      <div className="sidebar-foot"><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun /> : <Moon />}</button>
        <div className="avatar">{(auth.user?.display_name || auth.user?.username || '?')[0].toUpperCase()}</div><div><strong>{auth.user?.display_name || auth.user?.username}</strong><small>{auth.user?.is_admin ? 'Administrator' : auth.user?.auth_source === 'ldap' ? 'Directory user' : 'Member'}</small></div>
        <button className="icon-button" title="Log out" onClick={() => void auth.logout()}><LogOut /></button></div>
    </aside>
    <main className="workspace"><header className="mobile-bar"><button onClick={() => setMobile(!mobile)}><Menu /></button><span>CORTEX</span></header>
      <Routes>
        <Route path="/vault" element={<VaultPage />} /><Route path="/tokens" element={<TokensPage />} /><Route path="/mcp" element={<McpPage />} />
        <Route path="/admin/:section" element={auth.user?.is_admin ? <AdminPage /> : <Navigate to="/vault" />} />
        <Route path="*" element={<Navigate to="/vault" replace />} />
      </Routes>
    </main>
  </div>
}

function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return <header className="page-header"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{description && <p>{description}</p>}</div><div className="header-actions">{actions}</div></header>
}

function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="empty error-state"><ShieldCheck /><h3>That didn’t work</h3><p>{message}</p>{retry && <button className="button" onClick={retry}><RefreshCw />Try again</button>}</div>
}
function Empty({ icon: Icon = Boxes, title, text, action }: { icon?: any; title: string; text: string; action?: ReactNode }) {
  return <div className="empty"><Icon /><h3>{title}</h3><p>{text}</p>{action}</div>
}
function Loading() { return <div className="loading"><span /><span /><span /></div> }
function HighlightedSnippet({ text, query }: { text: string; query: string }) {
  const terms = query.trim().split(/\s+/).filter(Boolean)
  if (!terms.length) return <>{text}</>
  const escaped = terms.map(term => term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  const parts = String(text).split(new RegExp(`(${escaped.join('|')})`, 'gi'))
  return <>{parts.map((part, index) => terms.some(term => term.toLowerCase() === part.toLowerCase()) ? <mark key={index}>{part}</mark> : part)}</>
}
function Stat({ label, value, icon: Icon, tone = '' }: { label: string; value: ReactNode; icon: any; tone?: string }) {
  return <div className={`stat-card ${tone}`}><div className="stat-icon"><Icon /></div><div><small>{label}</small><strong>{value}</strong></div></div>
}
function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span> }

type TreeNode = { name: string; type: 'folder' | 'note'; path?: string; children?: TreeNode[] }
function TreeBranch({ node, active, onOpen, level = 0 }: { node: TreeNode; active?: string; onOpen: (path: string) => void; level?: number }) {
  const [open, setOpen] = useState(level < 1)
  if (node.type === 'note') return <button className={`tree-row ${active === node.path ? 'selected' : ''}`} style={{ paddingLeft: 12 + level * 16 }} onClick={() => onOpen(node.path!)}><FileText />{node.name.replace(/\.markdown?$/, '')}</button>
  if (!node.name) return <>{node.children?.map(child => <TreeBranch key={child.path || child.name} node={child} active={active} onOpen={onOpen} level={level} />)}</>
  return <div><button className="tree-row folder" style={{ paddingLeft: 12 + level * 16 }} onClick={() => setOpen(!open)}>{open ? <ChevronDown /> : <ChevronRight />}{open ? <FolderOpen /> : <Folder />}{node.name}</button>
    {open && node.children?.map(child => <TreeBranch key={child.path || child.name} node={child} active={active} onOpen={onOpen} level={level + 1} />)}</div>
}

function obsidianMarkdown(markdown: string, vault: string) {
  return markdown
    .replace(/!\[\[([^\]|]+)(?:\|[^\]]+)?\]\]/g, (_m, target) => `![${target}](/api/v1/vaults/${encodeURIComponent(vault)}/assets/${target.split('/').map(encodeURIComponent).join('/')})`)
    .replace(/\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|([^\]]+))?\]\]/g, (_m, target, alias) => `[${alias || target}](/vault?vault=${encodeURIComponent(vault)}&path=${encodeURIComponent(target.endsWith('.md') ? target : `${target}.md`)})`)
}

function VaultPage() {
  const [params, setParams] = useSearchParams(); const vaultParam = params.get('vault'); const notePath = params.get('path')
  const vaults = useLoad(() => api<{ vaults: any[] }>('/vaults'), [])
  const selectedVault = vaultParam || vaults.data?.vaults[0]?.id
  const tree = useLoad(() => selectedVault ? api<{ tree: TreeNode }>(`/vaults/${encodeURIComponent(selectedVault)}/tree`) : Promise.resolve({ tree: { name: '', type: 'folder', children: [] } as TreeNode }), [selectedVault])
  const note = useLoad(() => selectedVault && notePath ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/notes/${notePath.split('/').map(encodeURIComponent).join('/')}`) : Promise.resolve(null), [selectedVault, notePath])
  const links = useLoad(() => selectedVault && notePath ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/links/${notePath.split('/').map(encodeURIComponent).join('/')}`) : Promise.resolve(null), [selectedVault, notePath])
  const tags = useLoad(() => selectedVault ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/tags`) : Promise.resolve({ tags: [] }), [selectedVault]); const [activeTag, setActiveTag] = useState<string | null>(null)
  const history = useLoad(() => selectedVault ? api<any>(`/audit/commits?vault=${encodeURIComponent(selectedVault)}&limit=12${notePath ? `&path=${encodeURIComponent(notePath)}` : ''}`) : Promise.resolve({ commits: [] }), [selectedVault, notePath])
  const searchInput = useRef<HTMLInputElement>(null); const [query, setQuery] = useState(''); const [folderFilter, setFolderFilter] = useState(''); const [tagFilter, setTagFilter] = useState(''); const [results, setResults] = useState<any[]>([]); const [searching, setSearching] = useState(false); const [selectedResult, setSelectedResult] = useState(0)
  useEffect(() => { const focus = () => searchInput.current?.focus(); window.addEventListener('cortex-focus-search', focus); return () => window.removeEventListener('cortex-focus-search', focus) }, [])
  useEffect(() => { const handle = setTimeout(async () => { if (!query.trim() || !selectedVault) { setResults([]); return } setSearching(true); try { const params = new URLSearchParams({ q: query }); if (folderFilter) params.set('folder', folderFilter); if (tagFilter) params.set('tag', tagFilter); const data = await api<{ results: any[] }>(`/vaults/${selectedVault}/search?${params}`); setResults(data.results); setSelectedResult(0) } finally { setSearching(false) } }, 180); return () => clearTimeout(handle) }, [query, selectedVault, folderFilter, tagFilter])
  const open = (path: string) => setParams({ vault: selectedVault!, path })
  if (vaults.loading) return <Loading />
  if (vaults.error) return <ErrorState message={vaults.error} retry={vaults.reload} />
  return <div className="vault-page">
    <PageHeader eyebrow="OBSIDIAN MEMORY" title="Vault" description="Browse the knowledge your identity is allowed to see." actions={<select value={selectedVault} onChange={e => setParams({ vault: e.target.value })}>{vaults.data?.vaults.map(v => <option key={v.id} value={v.id}>{v.id}{v.relation === 'owner' ? ' · mine' : ''}</option>)}</select>} />
    <div className="vault-layout">
      <aside className="vault-tree panel"><div className="search-box"><Search /> <input ref={searchInput} placeholder="Search this vault…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={event => { if (event.key === 'ArrowDown') { event.preventDefault(); setSelectedResult(Math.min(results.length - 1, selectedResult + 1)) } if (event.key === 'ArrowUp') { event.preventDefault(); setSelectedResult(Math.max(0, selectedResult - 1)) } if (event.key === 'Enter' && results[selectedResult]) { open(results[selectedResult].path); setQuery('') } }} /><kbd>⌘K</kbd></div><div className="search-filters"><input placeholder="Folder filter" value={folderFilter} onChange={event => setFolderFilter(event.target.value)} /><input placeholder="Tag filter" value={tagFilter} onChange={event => setTagFilter(event.target.value)} /></div>
        {query && <div className="search-popover">{searching && <small>Searching…</small>}{results.map((result, index) => <button className={index === selectedResult ? 'selected' : ''} key={`${result.path}-${result.line}`} onMouseEnter={() => setSelectedResult(index)} onClick={() => { open(result.path); setQuery('') }}><strong>{result.path}</strong><span><HighlightedSnippet text={result.snippet} query={query} /></span></button>)}{!searching && !results.length && <small>No visible matches.</small>}</div>}
        <div className="tree-heading"><span>FILES</span><small>{vaults.data?.vaults.find(v => v.id === selectedVault)?.note_count || 0} notes</small></div>
        <div className="tree-scroll">{tree.loading ? <Loading /> : tree.data && <TreeBranch node={tree.data.tree} active={notePath || undefined} onOpen={open} />}</div>
      </aside>
      <article className="note-panel panel">{!notePath ? <Empty icon={BookOpen} title="Choose a note" text="Select a note from the tree or search across your visible memory." /> : note.loading ? <Loading /> : note.error ? <ErrorState message={note.error} retry={note.reload} /> : note.data && <>
        <div className="note-title"><div><p className="breadcrumb">{note.data.path.split('/').slice(0, -1).join(' / ') || selectedVault}</p><h1>{note.data.frontmatter?.title || note.data.path.split('/').pop()?.replace(/\.markdown?$/, '')}</h1></div><Badge tone="safe"><ShieldCheck /> Scoped</Badge></div>
        {Object.keys(note.data.frontmatter || {}).length > 0 && <div className="properties"><p><Settings /> PROPERTIES</p><dl>{Object.entries(note.data.frontmatter).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{Array.isArray(value) ? value.map(item => <Badge key={String(item)}>{String(item)}</Badge>) : String(value)}</dd></div>)}</dl></div>}
        <div className="markdown"><ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]} components={{ a: ({ href, children }) => { if (href?.startsWith('/vault?')) { const requested = new URL(href, location.origin).searchParams.get('path') || ''; const match = links.data?.outbound?.find((link: any) => [link.target, `${link.target}.md`].some(candidate => candidate.toLowerCase() === requested.toLowerCase())); if (!match?.path) return <span className="broken-link" title="Missing or outside your scope">{children}</span>; const resolved = `/vault?vault=${encodeURIComponent(selectedVault!)}&path=${encodeURIComponent(match.path)}`; return <a href={resolved} onClick={event => { event.preventDefault(); open(match.path) }}>{children}</a> } return <a href={href}>{children}</a> } }}>{obsidianMarkdown(note.data.markdown, selectedVault!)}</ReactMarkdown></div>
      </>}</article>
      <aside className="context-panel"><section className="panel"><p className="panel-label"><Link2 /> BACKLINKS</p>{links.data?.inbound?.length ? links.data.inbound.map((path: string) => <button key={path} onClick={() => open(path)}><FileText />{path}</button>) : <small>No visible backlinks.</small>}</section><section className="panel"><p className="panel-label"><Boxes /> TAGS</p><div className="tool-chips">{tags.data?.tags?.slice(0, 20).map((tag: any) => <button key={tag.name} onClick={() => setActiveTag(activeTag === tag.name ? null : tag.name)}>#{tag.name} · {tag.count}</button>)}</div>{activeTag && tags.data?.tags?.find((tag: any) => tag.name === activeTag)?.paths.map((path: string) => <button key={path} onClick={() => open(path)}><FileText />{path}</button>)}</section>
        <section className="panel"><p className="panel-label"><Activity /> {notePath ? 'HISTORY' : 'RECENT'}</p>{history.data?.commits?.length ? history.data.commits.slice(0, 6).map((commit: any) => <div className="mini-event" key={commit.sha}><strong>{commit.subject}</strong><small>{formatDate(commit.date)} · {commit.sha.slice(0, 8)}</small></div>) : <small>No visible commits.</small>}</section><section className="panel"><p className="panel-label"><Activity /> FRESHNESS</p><dl className="mini-stats"><div><dt>Last commit</dt><dd>{formatDate(vaults.data?.vaults.find(v => v.id === selectedVault)?.last_commit_iso)}</dd></div><div><dt>Index</dt><dd>{formatDate(vaults.data?.vaults.find(v => v.id === selectedVault)?.last_indexed_iso)}</dd></div></dl></section></aside>
    </div>
  </div>
}

function TokensPage() {
  const { csrf } = useAuth(); const tokens = useLoad(() => api<{ tokens: any[] }>('/tokens'), [])
  const [created, setCreated] = useState<string | null>(null)
  const create = async () => { const name = prompt('Name this token (for example “Claude Desktop”)'); if (!name) return; const data = await api<any>('/tokens', { method: 'POST', body: JSON.stringify({ name }) }, csrf); setCreated(data.token); await tokens.reload() }
  const revoke = async (id: number) => { if (!confirm('Revoke this token? Connected clients will immediately lose access.')) return; await api(`/tokens/${id}`, { method: 'DELETE' }, csrf); await tokens.reload() }
  return <div className="page"><PageHeader eyebrow="CREDENTIALS" title="My tokens" description="Issue separate, revocable credentials for each AI client." actions={<button className="button primary" onClick={create}><Plus />New token</button>} />
    {created && <section className="secret-reveal panel"><ShieldCheck /><div><strong>Copy this token now</strong><p>It cannot be shown again.</p><code>{created}</code></div><button className="button" onClick={() => navigator.clipboard.writeText(created)}><Copy />Copy</button><button className="icon-button" onClick={() => setCreated(null)}>×</button></section>}
    {tokens.loading ? <Loading /> : tokens.error ? <ErrorState message={tokens.error} retry={tokens.reload} /> : !tokens.data?.tokens.length ? <Empty icon={KeyRound} title="No tokens yet" text="Create one for every AI or script you connect." action={<button className="button primary" onClick={create}>Create token</button>} /> : <div className="table-panel panel"><table><thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Status</th><th /></tr></thead><tbody>{tokens.data.tokens.map(token => <tr key={token.id}><td><strong>{token.name}</strong></td><td><code>{token.token_prefix}…</code></td><td>{formatDate(token.last_used_at)}</td><td><Badge tone={token.revoked_at ? 'danger' : 'safe'}>{token.revoked_at ? 'Revoked' : 'Active'}</Badge></td><td><button className="icon-button danger" onClick={() => revoke(token.id)}><Trash2 /></button></td></tr>)}</tbody></table></div>}
  </div>
}

function McpPage() {
  const { csrf } = useAuth(); const [tab, setTab] = useState<'connect' | 'tools' | 'servers' | 'activity'>('connect')
  const tools = useLoad(() => api<{ tools: any[] }>('/mcp/tools'), [])
  const servers = useLoad(() => api<any>('/mcp/servers'), [])
  const activity = useLoad(() => api<{ calls: any[] }>('/audit/tools'), [])
  const tokenConfig = `{
  "mcpServers": {
    "cortex": {
      "url": "${location.origin}/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}`
  const addServer = async () => { const name = prompt('Short namespace for this MCP server'); if (!name) return; const url = prompt('Streamable HTTP endpoint URL'); if (!url) return; await api('/mcp/servers', { method: 'POST', body: JSON.stringify({ name, url, global: false }) }, csrf); await servers.reload() }
  return <div className="page"><PageHeader eyebrow="ONE GOVERNED ENDPOINT" title="MCP gateway" description="Cortex exposes only the tools your identity may use—and records every call." />
    <div className="tabs">{(['connect', 'tools', 'servers', 'activity'] as const).map(value => <button key={value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{value}</button>)}</div>
    {tab === 'connect' && <div className="two-column"><section className="panel content-card"><div className="card-icon"><Network /></div><h2>Connect your AI once</h2><p>Give the client Cortex as its only MCP. The token determines which vaults and upstream tools appear.</p><pre><code>{tokenConfig}</code></pre><button className="button" onClick={() => navigator.clipboard.writeText(tokenConfig)}><Copy />Copy configuration</button></section><section className="panel trust-card"><ShieldCheck /><h3>The gateway contract</h3><ul><li>Upstream secrets never reach your AI.</li><li>Denied tools are invisible and uncallable.</li><li>Arguments are audited by shape, not content.</li><li>Dead upstreams cannot stall the whole session.</li></ul><Link className="button primary" to="/tokens">Create a token</Link></section></div>}
    {tab === 'tools' && (tools.loading ? <Loading /> : <div className="tool-grid">{tools.data?.tools.map(tool => <article className="panel tool-card" key={tool.id}><div><Badge>{tool.server}</Badge><Wrench /></div><h3>{tool.name}</h3><p>{tool.description || 'Cortex governed tool'}</p><code>{tool.id}</code></article>)}</div>)}
    {tab === 'servers' && <><div className="section-actions"><div><h2>Registered servers</h2><p>Personal servers remain usable only by you.</p></div>{servers.data?.allow_user_servers && <button className="button primary" onClick={addServer}><Plus />Add server</button>}</div>{servers.loading ? <Loading /> : !servers.data?.servers?.length ? <Empty icon={Server} title="No upstream servers" text={servers.data?.allow_user_servers ? 'Add a personal MCP server to bring its tools through Cortex.' : 'Personal server registration is disabled by your administrator.'} /> : <div className="card-list">{servers.data.servers.map((server: any) => <section className="panel server-row" key={server.id}><div className="server-icon"><Server /></div><div><h3>{server.name} <Badge tone={server.enabled ? 'safe' : 'danger'}>{server.enabled ? 'Connected' : 'Disabled'}</Badge></h3><p>{server.url}</p><small>{server.tool_count} tools · {formatDate(server.last_checked_at)}</small>{server.last_error && <p className="danger-text">{server.last_error}</p>}</div><button className="icon-button" title="Refresh inventory" onClick={async () => { await api(`/mcp/servers/${server.id}/refresh`, { method: 'POST' }, csrf); await servers.reload() }}><RefreshCw /></button></section>)}</div>}</>}
    {tab === 'activity' && <AuditTable rows={activity.data?.calls || []} loading={activity.loading} />}
  </div>
}

function AdminPage() {
  const { section = 'overview' } = useParams(); const navigate = useNavigate()
  const tabs = ['overview', 'users', 'vaults', 'gateway', 'audit']
  return <div className="page"><PageHeader eyebrow="ADMINISTRATION" title={section[0].toUpperCase() + section.slice(1)} description="Operate Cortex without leaving the governed surface." actions={<select value={section} onChange={e => navigate(`/admin/${e.target.value}`)}>{tabs.map(tab => <option key={tab}>{tab}</option>)}</select>} />
    {section === 'overview' && <AdminOverview />}{section === 'users' && <AdminPeople />}{section === 'vaults' && <AdminVaults />}{section === 'gateway' && <AdminGateway />}{section === 'audit' && <AdminAudit />}
  </div>
}

function AdminOverview() {
  const users = useLoad(() => api<any>('/users'), []); const vaults = useLoad(() => api<any>('/vaults'), []); const servers = useLoad(() => api<any>('/mcp/servers'), [])
  const audit = useLoad(() => api<any>('/audit/tools?limit=8'), [])
  return <><div className="stats-grid"><Stat label="People" value={users.data?.users?.length || '—'} icon={Users} /><Stat label="Managed vaults" value={vaults.data?.vaults?.length || '—'} icon={Vault} /><Stat label="Gateway servers" value={servers.data?.servers?.length || '—'} icon={Server} /><Stat label="Recent tool calls" value={audit.data?.calls?.length || '—'} icon={Activity} tone="accent" /></div>
    <div className="two-column"><section className="panel content-card"><div className="section-actions"><div><p className="eyebrow">SYSTEM POSTURE</p><h2>Boundaries are active</h2></div><ShieldCheck className="hero-icon" /></div><div className="posture-list"><p><span className="dot safe" />Session + CSRF protection</p><p><span className="dot safe" />Per-user vault isolation</p><p><span className="dot safe" />Deny-wins tool permissions</p><p><span className="dot safe" />Central call telemetry</p></div></section><section className="panel content-card"><p className="eyebrow">QUICK ACTIONS</p><h2>Keep things moving</h2><div className="action-grid"><Link to="/admin/users"><UserPlus />Add a person</Link><Link to="/admin/vaults"><Vault />Inspect vaults</Link><Link to="/admin/gateway"><Network />Connect MCP</Link><Link to="/admin/audit"><Activity />Review calls</Link></div></section></div></>
}

function AdminPeople() {
  const { csrf } = useAuth(); const [tab, setTab] = useState<'users' | 'groups' | 'ldap' | 'tokens'>('users')
  const users = useLoad(() => api<any>('/users'), []); const groups = useLoad(() => api<any>('/groups'), []); const ldap = useLoad(() => api<any>('/ldap/status'), []); const tokens = useLoad(() => api<any>('/admin/tokens'), [])
  const addUser = async () => { const username = prompt('Username'); if (!username) return; const password = prompt('Temporary password'); if (!password) return; await api('/users', { method: 'POST', body: JSON.stringify({ username, password }) }, csrf); await users.reload() }
  const editUser = async (user: User) => { const display_name = prompt('Display name', user.display_name || ''); if (display_name === null) return; const email = prompt('Email', user.email || ''); if (email === null) return; const adminAnswer = prompt('Administrator? yes or no', user.is_admin ? 'yes' : 'no'); if (adminAnswer === null || !['yes', 'no'].includes(adminAnswer.toLowerCase())) return; const password = user.auth_source === 'local' ? prompt('New password (leave blank to keep the current password)', '') : ''; const body: Json = { display_name: display_name || user.username, is_admin: adminAnswer.toLowerCase() === 'yes' }; if (email) body.email = email; if (password) body.password = password; await api(`/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', body: JSON.stringify(body) }, csrf); await users.reload() }
  const toggleUser = async (user: User) => { await api(`/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', body: JSON.stringify({ disabled: !user.disabled }) }, csrf); await users.reload() }
  const deleteUser = async (user: User) => { if (!confirm(`Delete ${user.username}? Their vault remains until explicitly archived.`)) return; await api(`/users/${encodeURIComponent(user.username)}`, { method: 'DELETE' }, csrf); await users.reload() }
  const addGroup = async () => { const name = prompt('Group name'); if (!name) return; await api('/groups', { method: 'POST', body: JSON.stringify({ name, scopes: [], write_scopes: [] }) }, csrf); await groups.reload() }
  const editGroup = async (group: any) => { const read = prompt('Read scopes, comma separated', group.scopes.join(', ')); if (read === null) return; const write = prompt('Write scopes, comma separated', (group.write_scopes || []).join(', ')); if (write === null) return; const scopes = read.split(',').map((value: string) => value.trim()).filter(Boolean); const write_scopes = write.split(',').map((value: string) => value.trim()).filter(Boolean); await api(`/groups/${encodeURIComponent(group.name)}`, { method: 'PATCH', body: JSON.stringify({ scopes, write_scopes }) }, csrf); await groups.reload() }
  const addMember = async (group: any) => { const username = prompt(`Add which username to ${group.name}?`); if (!username) return; await api(`/groups/${encodeURIComponent(group.name)}/members`, { method: 'POST', body: JSON.stringify({ username }) }, csrf); await groups.reload(); await users.reload() }
  const removeMember = async (group: any) => { const username = prompt(`Remove which member from ${group.name}?`, group.members[0] || ''); if (!username) return; await api(`/groups/${encodeURIComponent(group.name)}/members/${encodeURIComponent(username)}`, { method: 'DELETE' }, csrf); await groups.reload(); await users.reload() }
  const revokeAdminToken = async (id: number) => { if (!confirm('Revoke this token immediately?')) return; await api(`/tokens/${id}`, { method: 'DELETE' }, csrf); await tokens.reload() }
  const editLdapPolicy = async () => { if (!ldap.data?.configured) return; const jit = confirm('Enable just-in-time provisioning for successful directory logins?'); const raw = prompt('LDAP group mapping JSON', JSON.stringify(ldap.data.group_mappings || {}, null, 2)); if (raw === null) return; let group_mappings: Json; try { group_mappings = JSON.parse(raw) } catch { alert('Group mappings must be valid JSON.'); return } await api('/ldap/status', { method: 'PATCH', body: JSON.stringify({ jit_provisioning: jit, group_mappings }) }, csrf); await ldap.reload() }
  return <><div className="tabs">{(['users', 'groups', 'ldap', 'tokens'] as const).map(value => <button className={tab === value ? 'active' : ''} onClick={() => setTab(value)} key={value}>{value}</button>)}</div>
    {tab === 'users' && <><div className="section-actions"><div><h2>People</h2><p>Local and directory identities share one policy model.</p></div><button className="button primary" onClick={addUser}><UserPlus />New local user</button></div><div className="table-panel panel"><table><thead><tr><th>User</th><th>Source</th><th>Groups</th><th>Last login</th><th>Status</th><th /></tr></thead><tbody>{users.data?.users?.map((user: User) => <tr key={user.username}><td><div className="user-cell"><div className="avatar">{user.username[0].toUpperCase()}</div><div><strong>{user.display_name || user.username}</strong><small>{user.email || `@${user.username}`}</small></div></div></td><td><Badge>{user.auth_source.toUpperCase()}</Badge></td><td>{user.groups?.map(group => <Badge key={group}>{group}</Badge>)}</td><td>{formatDate(user.last_login_at)}</td><td><button className="plain" onClick={() => toggleUser(user)}><Badge tone={user.disabled ? 'danger' : 'safe'}>{user.disabled ? 'Disabled' : 'Active'}</Badge></button></td><td><button className="icon-button" title="Edit user" onClick={() => editUser(user)}><Settings /></button><button className="icon-button danger" title="Delete user" onClick={() => deleteUser(user)}><Trash2 /></button></td></tr>)}</tbody></table></div></>}
    {tab === 'groups' && <><div className="section-actions"><div><h2>Groups & shared memory</h2><p>Group grants add scoped main-vault access and tool policy.</p></div><button className="button primary" onClick={addGroup}><Plus />New group</button></div><div className="card-list">{groups.data?.groups?.map((group: any) => <section className="panel group-card" key={group.name}><div className="server-icon"><Users /></div><div className="grow"><h3>{group.name} <Badge>{group.source}</Badge></h3><p>{group.members.length} members · {group.members.join(', ') || 'none'}</p><div><small>READ</small>{group.scopes.length ? group.scopes.map((scope: string) => <code key={scope}>{scope}</code>) : <span className="muted"> No shared scopes</span>}</div><div><small>WRITE</small>{group.write_scopes?.length ? group.write_scopes.map((scope: string) => <code key={scope}>{scope}</code>) : <span className="muted"> No shared writes</span>}</div></div><div className="header-actions"><button className="button" onClick={() => editGroup(group)}><Settings />Scopes</button><button className="button" onClick={() => addMember(group)}><UserPlus />Add</button>{group.members.length > 0 && <button className="button" onClick={() => removeMember(group)}><Trash2 />Remove</button>}</div></section>)}</div></>}
    {tab === 'ldap' && <div className="two-column"><section className="panel content-card"><div className="card-icon"><Database /></div><h2>Directory connection</h2><p>{ldap.data?.configured ? ldap.data.server_uri : 'LDAP is not configured. Local identities remain fully available.'}</p><Badge tone={ldap.data?.configured ? 'safe' : ''}>{ldap.data?.configured ? 'Configured' : 'Off'}</Badge>{ldap.data?.configured && <><p><strong>JIT provisioning:</strong> {ldap.data.jit_provisioning ? 'on' : 'off'}</p><div className="tool-chips">{Object.entries(ldap.data.group_mappings || {}).map(([source, target]) => <code key={source}>{source} → {String(target)}</code>)}</div><button className="button" onClick={editLdapPolicy}><Settings />Edit policy</button></>}</section><section className="panel content-card"><h2>Synchronize identities</h2><p>Preview additions, updates, disables, and mapped group changes before applying them. Connection secrets remain environment-only; JIT and mapping policy is persisted in SQLite.</p><button className="button" disabled={!ldap.data?.configured} onClick={async () => { const preview = await api<any>('/ldap/sync?dry_run=true', { method: 'POST' }, csrf); alert(JSON.stringify(preview, null, 2)) }}><RefreshCw />Dry-run preview</button><button className="button primary" disabled={!ldap.data?.configured} onClick={async () => { if (confirm('Apply directory synchronization?')) { await api('/ldap/sync', { method: 'POST' }, csrf); await users.reload(); await groups.reload() } }}><Database />Sync now</button></section></div>}
    {tab === 'tokens' && <div className="table-panel panel"><table><thead><tr><th>Owner</th><th>Name</th><th>Prefix</th><th>Last used</th><th>Status</th><th /></tr></thead><tbody>{tokens.data?.tokens?.map((token: any) => <tr key={token.id}><td>{token.owner}</td><td>{token.name}</td><td><code>{token.token_prefix}…</code></td><td>{formatDate(token.last_used_at)}</td><td><Badge tone={token.revoked_at ? 'danger' : 'safe'}>{token.revoked_at ? 'Revoked' : 'Active'}</Badge></td><td>{!token.revoked_at && <button className="icon-button danger" title="Revoke token" onClick={() => revokeAdminToken(token.id)}><Trash2 /></button>}</td></tr>)}</tbody></table></div>}
  </>
}

function AdminVaults() {
  const { csrf } = useAuth(); const vaults = useLoad(() => api<any>('/vaults'), []); const janitor = useLoad(() => api<any>('/admin/janitor'), [])
  const archive = async (id: string) => { if (!confirm(`Archive vault “${id}”? It will be moved intact and access removed.`)) return; await api(`/admin/vaults/${encodeURIComponent(id)}/archive`, { method: 'POST' }, csrf); await vaults.reload() }
  const repair = async (id: string) => { await api(`/admin/vaults/${encodeURIComponent(id)}/repair`, { method: 'POST' }, csrf); await vaults.reload() }
  return <><div className="stats-grid"><Stat label="Vaults" value={vaults.data?.vaults?.length || 0} icon={Vault} /><Stat label="Notes" value={vaults.data?.vaults?.reduce((sum: number, vault: any) => sum + vault.note_count, 0) || 0} icon={FileText} /><Stat label="Stored" value={formatBytes(vaults.data?.vaults?.reduce((sum: number, vault: any) => sum + vault.size_bytes, 0) || 0)} icon={Database} /></div>
    <div className="card-list">{vaults.data?.vaults?.map((vault: any) => <section className="panel vault-admin-card" key={vault.id}><div className="server-icon"><Vault /></div><div className="grow"><div className="section-actions"><div><h3>{vault.id} <Badge>{vault.relation}</Badge></h3><p>{vault.note_count} notes · {formatBytes(vault.size_bytes)} · {vault.sync_adapter} sync</p></div><Badge tone={vault.head_commit ? 'safe' : 'danger'}>{vault.head_commit ? 'Git healthy' : 'No commit'}</Badge></div><div className="progress"><span style={{ width: `${Math.min(100, (vault.index_note_count / Math.max(1, vault.note_count)) * 100)}%` }} /></div><small>Indexed {vault.index_note_count} / {vault.note_count} notes · refreshed {formatDate(vault.last_indexed_iso)}</small></div><Link className="button" to={`/vault?vault=${vault.id}`}><BookOpen />Browse</Link><button className="icon-button" title="Repair repository and index" onClick={() => repair(vault.id)}><RefreshCw /></button>{vault.id !== 'main' && <button className="icon-button danger" title="Archive vault" onClick={() => archive(vault.id)}><Archive /></button>}</section>)}</div><section className="panel content-card"><div className="section-actions"><div><p className="eyebrow">JANITOR</p><h2>Report-first maintenance</h2><p>{janitor.data?.enabled ? `Runs every ${janitor.data.interval_seconds} seconds` : 'Disabled in configuration'}</p></div><Badge tone={janitor.data?.enabled && janitor.data?.dry_run ? 'safe' : ''}>{janitor.data?.dry_run ? 'Dry run' : janitor.data?.enabled ? 'Write mode' : 'Off'}</Badge></div><p>Allowed: {(janitor.data?.allowed_paths || []).join(', ') || 'none'} · Forbidden: {(janitor.data?.forbidden_paths || []).join(', ') || 'none'}</p><div className="janitor-reports">{janitor.data?.reports?.length ? janitor.data.reports.slice(0, 8).map((report: any) => <div className="mini-event" key={report.id}><div><Badge>{report.vault}</Badge><Badge tone={report.dry_run ? 'safe' : ''}>{report.dry_run ? 'dry run' : 'applied'}</Badge></div><strong>{report.summary}</strong><small>{formatDate(report.created_at)}</small></div>) : <small>No maintenance reports yet.</small>}</div></section></>
}

function AdminGateway() {
  const { csrf } = useAuth(); const [tab, setTab] = useState<'servers' | 'permissions'>('servers')
  const [previewUser, setPreviewUser] = useState('')
  const servers = useLoad(() => api<any>('/mcp/servers'), []); const users = useLoad(() => api<any>('/users'), []); const groups = useLoad(() => api<any>('/groups'), []); const permissions = useLoad(() => api<any>(`/admin/permissions${previewUser ? `?user=${encodeURIComponent(previewUser)}` : ''}`), [previewUser])
  const add = async () => { const name = prompt('Server namespace'); if (!name) return; const url = prompt('Streamable HTTP endpoint'); if (!url) return; const auth_env = prompt('Bearer token environment variable (optional)') || undefined; await api('/mcp/servers', { method: 'POST', body: JSON.stringify({ name, url, auth_env, global: true }) }, csrf); await servers.reload() }
  const toggleServer = async (server: any) => { await api(`/mcp/servers/${server.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !server.enabled }) }, csrf); await servers.reload() }
  const removeServer = async (server: any) => { if (!confirm(`Remove MCP server “${server.name}” and its permission rules?`)) return; await api(`/mcp/servers/${server.id}`, { method: 'DELETE' }, csrf); await servers.reload(); await permissions.reload() }
  const addRule = async () => { const subject_type = prompt('Subject type: user or group', 'group'); if (!subject_type) return; const subject = prompt('Subject name'); if (!subject) return; const serverName = prompt(`Limit to one server? Enter a namespace or leave blank for all.\nAvailable: cortex, ${(servers.data?.servers || []).map((server: any) => server.name).join(', ')}`, '')?.trim(); if (serverName === undefined) return; const server = serverName && serverName !== 'cortex' ? servers.data?.servers?.find((item: any) => item.name === serverName) : null; if (serverName && serverName !== 'cortex' && !server) { alert('Unknown server namespace.'); return } const tool_pattern = prompt('Tool pattern', serverName ? `${serverName}.*` : '*.*'); if (!tool_pattern) return; const effect = prompt('Effect: allow or deny', 'allow'); if (!effect) return; const body: Json = { subject_type, subject, tool_pattern, effect }; if (server) body.server_id = server.id; await api('/admin/permissions', { method: 'POST', body: JSON.stringify(body) }, csrf); await permissions.reload() }
  return <><div className="tabs"><button className={tab === 'servers' ? 'active' : ''} onClick={() => setTab('servers')}>servers</button><button className={tab === 'permissions' ? 'active' : ''} onClick={() => setTab('permissions')}>permission matrix</button></div>
    {tab === 'servers' && <><div className="section-actions"><div><h2>Global MCP registry</h2><p>Secrets are environment references and never round-trip through this page.</p></div><button className="button primary" onClick={add}><Plus />Register server</button></div><div className="card-list">{servers.data?.servers?.map((server: any) => <section className="panel server-row" key={server.id}><div className="server-icon"><Server /></div><div className="grow"><h3>{server.name} <Badge tone={server.enabled ? 'safe' : 'danger'}>{server.enabled ? 'Online' : 'Needs attention'}</Badge></h3><p>{server.url}</p><div className="tool-chips">{server.tools.slice(0, 8).map((tool: any) => <code key={tool.name}>{tool.name}</code>)}{server.tool_count > 8 && <Badge>+{server.tool_count - 8}</Badge>}</div>{server.last_error && <p className="danger-text">{server.last_error}</p>}</div><button className="button" onClick={async () => { await api(`/mcp/servers/${server.id}/refresh`, { method: 'POST' }, csrf); await servers.reload() }}><RefreshCw />Refresh</button><button className="icon-button" title={server.enabled ? 'Disable server' : 'Enable server'} onClick={() => toggleServer(server)}><ShieldCheck /></button><button className="icon-button danger" title="Remove server" onClick={() => removeServer(server)}><Trash2 /></button></section>)}</div></>}
    {tab === 'permissions' && <><div className="section-actions"><div><h2>Deny-wins permissions</h2><p>Explicit user and group denials are hard boundaries; defaults fill the gaps.</p></div><button className="button primary" onClick={addRule}><Plus />Add rule</button></div><div className="table-panel panel"><table><thead><tr><th>Subject</th><th>Server</th><th>Tool pattern</th><th>Effect</th><th>Created</th><th /></tr></thead><tbody>{permissions.data?.permissions?.map((rule: any) => { const subject = rule.subject_type === 'user' ? users.data?.users?.find((user: any) => user.id === rule.subject_id)?.username : groups.data?.groups?.find((group: any) => group.id === rule.subject_id)?.name; const server = rule.server_id ? servers.data?.servers?.find((item: any) => item.id === rule.server_id)?.name : 'all'; return <tr key={rule.id}><td><Badge>{rule.subject_type}</Badge> {subject || `#${rule.subject_id}`}</td><td>{server || `#${rule.server_id}`}</td><td><code>{rule.tool_pattern}</code></td><td><Badge tone={rule.effect === 'deny' ? 'danger' : 'safe'}>{rule.effect}</Badge></td><td>{formatDate(rule.created_at)}</td><td><button className="icon-button danger" onClick={async () => { await api(`/admin/permissions/${rule.id}`, { method: 'DELETE' }, csrf); await permissions.reload() }}><Trash2 /></button></td></tr> })}</tbody></table></div><div className="section-actions matrix-heading"><div><h2>Effective access preview</h2><p>Computed from defaults plus every matching user, group, server, and tool rule.</p></div><select value={previewUser} onChange={event => setPreviewUser(event.target.value)}><option value="">Choose a user…</option>{users.data?.users?.map((user: any) => <option key={user.id} value={user.username}>{user.username}</option>)}</select></div>{previewUser && <div className="table-panel panel"><table><thead><tr><th>Tool</th><th>Effective</th><th>Matched rules</th></tr></thead><tbody>{permissions.data?.preview?.map((item: any) => <tr key={item.tool_id}><td><code>{item.tool_id}</code></td><td><Badge tone={item.allowed ? 'safe' : 'danger'}>{item.allowed ? 'Allowed' : 'Denied'}</Badge></td><td>{item.rules.length ? item.rules.map((rule: any) => <Badge key={rule.id} tone={rule.effect === 'deny' ? 'danger' : 'safe'}>{rule.effect} {rule.tool_pattern}</Badge>) : <span className="muted">Default policy</span>}</td></tr>)}</tbody></table></div>}</>}
  </>
}

function AdminAudit() {
  const [tab, setTab] = useState<'tools' | 'commits'>('tools')
  const [filters, setFilters] = useState({ user: '', server: '', tool: '', outcome: '', vault: '', actor: '', path: '', from: '', to: '' })
  const query = (kind: 'tools' | 'commits') => { const params = new URLSearchParams({ limit: '500' }); const names = kind === 'tools' ? ['user', 'server', 'tool', 'outcome'] : ['vault', 'actor', 'path']; names.forEach(name => { const value = filters[name as keyof typeof filters]; if (value) params.set(name, value) }); if (filters.from) params.set('from', `${filters.from}T00:00:00Z`); if (filters.to) params.set('to', `${filters.to}T23:59:59Z`); return params.toString() }
  const calls = useLoad(() => api<any>(`/audit/tools?${query('tools')}`), [filters.user, filters.server, filters.tool, filters.outcome, filters.from, filters.to])
  const commits = useLoad(() => api<any>(`/audit/commits?${query('commits')}`), [filters.vault, filters.actor, filters.path, filters.from, filters.to])
  const field = (name: keyof typeof filters, placeholder: string, type = 'text') => <input type={type} placeholder={placeholder} value={filters[name]} onChange={event => setFilters({ ...filters, [name]: event.target.value })} />
  const exportRows = (format: 'json' | 'csv') => { const rows: Json[] = tab === 'tools' ? calls.data?.calls || [] : commits.data?.commits || []; if (format === 'json') { downloadFile(`cortex-${tab}.json`, JSON.stringify(rows, null, 2), 'application/json'); return } const keys: string[] = Array.from(new Set<string>(rows.flatMap(row => Object.keys(row)))); const escape = (value: any) => `"${String(value ?? '').replaceAll('"', '""')}"`; downloadFile(`cortex-${tab}.csv`, [keys.join(','), ...rows.map(row => keys.map(key => escape(row[key])).join(','))].join('\n'), 'text/csv') }
  return <><div className="section-actions"><div className="tabs"><button className={tab === 'tools' ? 'active' : ''} onClick={() => setTab('tools')}>tool calls</button><button className={tab === 'commits' ? 'active' : ''} onClick={() => setTab('commits')}>vault commits</button></div><div className="header-actions"><button className="button" onClick={() => exportRows('csv')}><Download />CSV</button><button className="button" onClick={() => exportRows('json')}><Download />JSON</button></div></div>
    <div className="filter-bar panel">{tab === 'tools' ? <>{field('user', 'User')}{field('server', 'Server')}{field('tool', 'Tool')}<select value={filters.outcome} onChange={event => setFilters({ ...filters, outcome: event.target.value })}><option value="">Any outcome</option><option>allowed</option><option>denied</option><option>error</option></select></> : <>{field('vault', 'Vault')}{field('actor', 'Actor / user')}{field('path', 'Note path')}</>}{field('from', 'From', 'date')}{field('to', 'To', 'date')}<button className="button" onClick={() => setFilters({ user: '', server: '', tool: '', outcome: '', vault: '', actor: '', path: '', from: '', to: '' })}>Clear</button></div>
    {tab === 'tools' ? <AuditTable rows={calls.data?.calls || []} loading={calls.loading} /> : <div className="timeline">{commits.data?.commits?.map((commit: any) => <article className="timeline-item" key={`${commit.vault}-${commit.sha}`}><span /><div className="panel"><div><Badge>{commit.vault}</Badge><code>{commit.sha.slice(0, 10)}</code><time>{formatDate(commit.date)}</time></div><h3>{commit.subject}</h3><p>{commit.actor}</p><small>{commit.diff?.file_count || 0} files · +{commit.diff?.insertions || 0} / -{commit.diff?.deletions || 0}</small></div></article>)}</div>}
  </>
}

function AuditTable({ rows, loading }: { rows: any[]; loading?: boolean }) {
  if (loading) return <Loading />
  if (!rows.length) return <Empty icon={Activity} title="No activity yet" text="Calls through Cortex will appear here—allowed, denied, and failed." />
  return <div className="table-panel panel"><table><thead><tr><th>When</th><th>Identity</th><th>Tool</th><th>Vault</th><th>Outcome</th><th>Latency</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td>{formatDate(row.ts)}</td><td>{row.subject}</td><td><code>{row.server}.{row.tool}</code></td><td>{row.vault || '—'}</td><td><Badge tone={row.decision === 'allowed' ? 'safe' : 'danger'}>{row.decision}</Badge></td><td>{row.duration_ms ?? 0} ms</td></tr>)}</tbody></table></div>
}

function formatDate(value?: string | number | null) {
  if (!value) return 'Never'
  const date = new Date(typeof value === 'number' ? value * 1000 : value)
  return Number.isNaN(date.valueOf()) ? 'Unknown' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
function formatBytes(value: number) {
  if (!value) return '0 B'; const units = ['B', 'KB', 'MB', 'GB']; const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}

function downloadFile(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click()
  URL.revokeObjectURL(url)
}

export default App

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
import rehypeHighlight from 'rehype-highlight'
import rehypeSanitize from 'rehype-sanitize'
import remarkGfm from 'remark-gfm'
import {
  Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate,
  useParams, useSearchParams,
} from 'react-router-dom'
import { ConfirmDialog, Dialog } from './components/Dialog'

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
  const auth = useAuth(); const navigate = useNavigate(); const location = useLocation(); const [mobile, setMobile] = useState(false)
  const [theme, setTheme] = useState(() => localStorage.getItem('cortex-theme') || 'dark')
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('cortex-theme', theme) }, [theme])
  useEffect(() => { setMobile(false) }, [location.pathname, location.search])
  useEffect(() => {
    document.body.classList.toggle('nav-open', mobile)
    return () => document.body.classList.remove('nav-open')
  }, [mobile])
  useEffect(() => { const shortcut = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); navigate('/vault'); setTimeout(() => window.dispatchEvent(new Event('cortex-focus-search')), 0) } if (event.key === 'Escape') setMobile(false) }; window.addEventListener('keydown', shortcut); return () => window.removeEventListener('keydown', shortcut) }, [navigate])
  const navLink = (to: string, Icon: any, label: string) => <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}><Icon /><span>{label}</span></NavLink>
  return <div className="app-shell">
    {mobile && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobile(false)} />}
    <aside id="primary-navigation" className={`sidebar ${mobile ? 'open' : ''}`} aria-label="Primary navigation">
      <Link className="brand-lockup compact" to="/vault"><div className="brand-mark"><Network /></div><span>CORTEX</span></Link>
      <nav><p className="nav-label">WORKSPACE</p>{primaryNav.map(([to, Icon, label]) => navLink(to, Icon, label))}
        {auth.user?.is_admin && <><p className="nav-label">ADMINISTRATION</p>{adminNav.map(([to, Icon, label]) => navLink(to, Icon, label))}</>}
      </nav>
      <div className="sidebar-foot"><button className="icon-button" aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`} title={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun /> : <Moon />}</button>
        <div className="avatar">{(auth.user?.display_name || auth.user?.username || '?')[0].toUpperCase()}</div><div><strong>{auth.user?.display_name || auth.user?.username}</strong><small>{auth.user?.is_admin ? 'Administrator' : auth.user?.auth_source === 'ldap' ? 'Directory user' : 'Member'}</small></div>
        <button className="icon-button" aria-label="Log out" title="Log out" onClick={() => void auth.logout()}><LogOut /></button></div>
    </aside>
    <main className="workspace"><header className="mobile-bar"><button aria-controls="primary-navigation" aria-expanded={mobile} aria-label="Open navigation" onClick={() => setMobile(!mobile)}><Menu /></button><Link to="/vault"><span>CORTEX</span></Link><button className="mobile-theme" aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`} onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <Sun /> : <Moon />}</button></header>
      <Routes>
        <Route path="/vault/*" element={<VaultPage />} /><Route path="/tokens" element={<TokensPage />} /><Route path="/mcp" element={<McpPage />} />
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
    .replace(/^> \[!([\w-]+)\](?:[+-])?\s*(.*)$/gm, (_m, kind, title) => `> **${String(kind).toUpperCase()}${title ? ` · ${title}` : ''}**`)
    .replace(/!\[\[([^\]|]+)(?:\|[^\]]+)?\]\]/g, (_m, target) => `![${target}](/api/v1/vaults/${encodeURIComponent(vault)}/assets/${target.split('/').map(encodeURIComponent).join('/')})`)
    .replace(/\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|([^\]]+))?\]\]/g, (_m, target, alias) => `[${alias || target}](/vault?vault=${encodeURIComponent(vault)}&path=${encodeURIComponent(target.endsWith('.md') ? target : `${target}.md`)})`)
}

function VaultPage() {
  const location = useLocation(); const navigate = useNavigate(); const [params, setParams] = useSearchParams(); const vaultParam = params.get('vault')
  const routePath = decodeURIComponent(location.pathname.replace(/^\/vault\/?/, ''))
  const notePath = routePath && routePath !== 'tags' ? routePath : params.get('path')
  const vaults = useLoad(() => api<{ vaults: any[] }>('/vaults'), [])
  const selectedVault = vaultParam || vaults.data?.vaults[0]?.id
  const tree = useLoad(() => selectedVault ? api<{ tree: TreeNode }>(`/vaults/${encodeURIComponent(selectedVault)}/tree`) : Promise.resolve({ tree: { name: '', type: 'folder', children: [] } as TreeNode }), [selectedVault])
  const note = useLoad(() => selectedVault && notePath ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/notes/${notePath.split('/').map(encodeURIComponent).join('/')}`) : Promise.resolve(null), [selectedVault, notePath])
  const links = useLoad(() => selectedVault && notePath ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/links/${notePath.split('/').map(encodeURIComponent).join('/')}`) : Promise.resolve(null), [selectedVault, notePath])
  const tags = useLoad(() => selectedVault ? api<any>(`/vaults/${encodeURIComponent(selectedVault)}/tags`) : Promise.resolve({ tags: [] }), [selectedVault]); const [activeTag, setActiveTag] = useState<string | null>(null)
  const [noteTab, setNoteTab] = useState<'note' | 'history'>('note'); const history = useLoad(() => selectedVault ? api<any>(`/audit/commits?vault=${encodeURIComponent(selectedVault)}&limit=12${notePath ? `&path=${encodeURIComponent(notePath)}` : ''}`) : Promise.resolve({ commits: [] }), [selectedVault, notePath])
  const searchInput = useRef<HTMLInputElement>(null); const [query, setQuery] = useState(''); const [folderFilter, setFolderFilter] = useState(''); const [tagFilter, setTagFilter] = useState(''); const [results, setResults] = useState<any[]>([]); const [searching, setSearching] = useState(false); const [selectedResult, setSelectedResult] = useState(0)
  useEffect(() => { const focus = () => searchInput.current?.focus(); window.addEventListener('cortex-focus-search', focus); return () => window.removeEventListener('cortex-focus-search', focus) }, [])
  useEffect(() => { const handle = setTimeout(async () => { if (!query.trim() || !selectedVault) { setResults([]); return } setSearching(true); try { const params = new URLSearchParams({ q: query }); if (folderFilter) params.set('folder', folderFilter); if (tagFilter) params.set('tag', tagFilter); const data = await api<{ results: any[] }>(`/vaults/${selectedVault}/search?${params}`); setResults(data.results); setSelectedResult(0) } finally { setSearching(false) } }, 180); return () => clearTimeout(handle) }, [query, selectedVault, folderFilter, tagFilter])
  const open = (path: string) => navigate(`/vault/${path.split('/').map(encodeURIComponent).join('/')}?vault=${encodeURIComponent(selectedVault!)}`)
  if (vaults.loading) return <Loading />
  if (vaults.error) return <ErrorState message={vaults.error} retry={vaults.reload} />
  return <div className="vault-page">
    <PageHeader eyebrow="MEMORY WORKSPACE" title="Your vault" description="Search, browse, and verify the knowledge available to this identity." actions={<label className="vault-picker"><span>Vault</span><select value={selectedVault} onChange={e => setParams({ vault: e.target.value })}>{vaults.data?.vaults.map(v => <option key={v.id} value={v.id}>{v.id}{v.relation === 'owner' ? ' · mine' : ''}</option>)}</select></label>} />
    <div className="vault-layout">
      <aside className="vault-tree panel"><div className="search-box"><Search aria-hidden="true" /> <input ref={searchInput} aria-label="Search this vault" placeholder="Search notes…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={event => { if (event.key === 'ArrowDown') { event.preventDefault(); setSelectedResult(Math.min(results.length - 1, selectedResult + 1)) } if (event.key === 'ArrowUp') { event.preventDefault(); setSelectedResult(Math.max(0, selectedResult - 1)) } if (event.key === 'Enter' && results[selectedResult]) { open(results[selectedResult].path); setQuery('') } if (event.key === 'Escape') setQuery('') }} />{query ? <button className="search-clear" aria-label="Clear search" onClick={() => setQuery('')}>×</button> : <kbd>⌘K</kbd>}</div><div className="search-filters"><label><span>Folder</span><input placeholder="Any folder" value={folderFilter} onChange={event => setFolderFilter(event.target.value)} /></label><label><span>Tag</span><input placeholder="Any tag" value={tagFilter} onChange={event => setTagFilter(event.target.value)} /></label></div>
        {query && <div className="search-popover">{searching && <small>Searching…</small>}{results.map((result, index) => <button className={index === selectedResult ? 'selected' : ''} key={`${result.path}-${result.line}`} onMouseEnter={() => setSelectedResult(index)} onClick={() => { open(result.path); setQuery('') }}><strong>{result.path}</strong><span><HighlightedSnippet text={result.snippet} query={query} /></span></button>)}{!searching && !results.length && <small>No visible matches.</small>}</div>}
        <div className="tree-heading"><span>FILES</span><small>{vaults.data?.vaults.find(v => v.id === selectedVault)?.note_count || 0} notes</small></div>
        <div className="tree-scroll">{tree.loading ? <Loading /> : tree.data && <TreeBranch node={tree.data.tree} active={notePath || undefined} onOpen={open} />}</div>
      </aside>
      <article className="note-panel panel">{!notePath ? <Empty icon={BookOpen} title="Choose a note" text="Select a note from the tree or search across your visible memory." /> : note.loading ? <Loading /> : note.error ? <ErrorState message={note.error} retry={note.reload} /> : note.data && <>
        <div className="note-title"><div><p className="breadcrumb">{note.data.path.split('/').slice(0, -1).join(' / ') || selectedVault}</p><h1>{note.data.frontmatter?.title || note.data.path.split('/').pop()?.replace(/\.markdown?$/, '')}</h1></div><Badge tone="safe"><ShieldCheck /> Scoped</Badge></div>
        {Object.keys(note.data.frontmatter || {}).length > 0 && <div className="properties"><p><Settings /> PROPERTIES</p><dl>{Object.entries(note.data.frontmatter).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{Array.isArray(value) ? value.map(item => key.toLowerCase() === 'tags' ? <button className="tag-chip" key={String(item)} onClick={() => { setActiveTag(String(item).replace(/^#/, '')); setTagFilter(String(item).replace(/^#/, '')) }}><Badge>#{String(item).replace(/^#/, '')}</Badge></button> : <Badge key={String(item)}>{String(item)}</Badge>) : String(value)}</dd></div>)}</dl></div>}
        <div className="tabs note-tabs"><button className={noteTab === 'note' ? 'active' : ''} onClick={() => setNoteTab('note')}>note</button><button className={noteTab === 'history' ? 'active' : ''} onClick={() => setNoteTab('history')}>history</button></div>{noteTab === 'note' ? <div className="markdown"><ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize, rehypeHighlight]} components={{ a: ({ href, children }) => { if (href?.startsWith('/vault?')) { const requested = new URL(href, window.location.origin).searchParams.get('path') || ''; const match = links.data?.outbound?.find((link: any) => [link.target, `${link.target}.md`].some(candidate => candidate.toLowerCase() === requested.toLowerCase())); if (!match?.path) return <span className="broken-link" title="Missing or outside your scope">{children}</span>; const resolved = `/vault/${match.path.split('/').map(encodeURIComponent).join('/')}?vault=${encodeURIComponent(selectedVault!)}`; return <a href={resolved} onClick={event => { event.preventDefault(); open(match.path) }}>{children}</a> } return <a href={href}>{children}</a> } }}>{obsidianMarkdown(note.data.markdown, selectedVault!)}</ReactMarkdown></div> : <div className="timeline note-history">{history.data?.commits?.map((commit: any) => <article className="timeline-item" key={commit.sha}><span /><div className="panel"><div><code>{commit.sha.slice(0, 10)}</code><time>{formatDate(commit.date)}</time></div><h3>{commit.subject}</h3><p>{commit.actor}</p><small>{commit.diff?.file_count || 0} files · +{commit.diff?.insertions || 0} / -{commit.diff?.deletions || 0}</small></div></article>)}</div>}
      </>}</article>
      <aside className="context-panel"><section className="panel"><p className="panel-label"><Link2 /> BACKLINKS</p>{links.data?.inbound?.length ? links.data.inbound.map((path: string) => <button key={path} onClick={() => open(path)}><FileText />{path}</button>) : <small>No visible backlinks.</small>}</section><section className="panel"><p className="panel-label"><Boxes /> TAGS</p><div className="tool-chips">{tags.data?.tags?.slice(0, 20).map((tag: any) => <button key={tag.name} onClick={() => setActiveTag(activeTag === tag.name ? null : tag.name)}>#{tag.name} · {tag.count}</button>)}</div>{activeTag && tags.data?.tags?.find((tag: any) => tag.name === activeTag)?.paths.map((path: string) => <button key={path} onClick={() => open(path)}><FileText />{path}</button>)}</section>
        <section className="panel"><p className="panel-label"><Activity /> {notePath ? 'HISTORY' : 'RECENT'}</p>{history.data?.commits?.length ? history.data.commits.slice(0, 6).map((commit: any) => <div className="mini-event" key={commit.sha}><strong>{commit.subject}</strong><small>{formatDate(commit.date)} · {commit.sha.slice(0, 8)}</small></div>) : <small>No visible commits.</small>}</section><section className="panel"><p className="panel-label"><Activity /> FRESHNESS</p><dl className="mini-stats"><div><dt>Last commit</dt><dd>{formatDate(vaults.data?.vaults.find(v => v.id === selectedVault)?.last_commit_iso)}</dd></div><div><dt>Index</dt><dd>{formatDate(vaults.data?.vaults.find(v => v.id === selectedVault)?.last_indexed_iso)}</dd></div></dl></section></aside>
    </div>
  </div>
}

function TokensPage() {
  const { csrf } = useAuth()
  const tokens = useLoad(() => api<{ tokens: any[] }>('/tokens'), [])
  const [created, setCreated] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [pendingRevoke, setPendingRevoke] = useState<any | null>(null)
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const [notice, setNotice] = useState('')

  const create = async (event: FormEvent) => {
    event.preventDefault(); setFormError('')
    if (!name.trim()) { setFormError('Give this token a recognizable name.'); return }
    setBusy(true)
    try {
      const data = await api<any>('/tokens', { method: 'POST', body: JSON.stringify({ name: name.trim() }) }, csrf)
      setCreated(data.token); setName(''); setShowCreate(false); setNotice('Token created. Copy it before leaving this page.'); await tokens.reload()
    } catch (error) { setFormError(error instanceof Error ? error.message : 'Token creation failed.') }
    finally { setBusy(false) }
  }
  const revoke = async () => {
    if (!pendingRevoke) return
    setBusy(true); setFormError('')
    try { await api(`/tokens/${pendingRevoke.id}`, { method: 'DELETE' }, csrf); setNotice(`Revoked ${pendingRevoke.name}.`); setPendingRevoke(null); await tokens.reload() }
    catch (error) { setFormError(error instanceof Error ? error.message : 'Token revocation failed.') }
    finally { setBusy(false) }
  }
  const openCreate = () => { setFormError(''); setShowCreate(true) }
  return <div className="page"><PageHeader eyebrow="CREDENTIALS" title="My tokens" description="Issue separate, revocable credentials for each AI client." actions={<button className="button primary" onClick={openCreate}><Plus />New token</button>} />
    {notice && <p className="notice success" role="status">{notice}</p>}
    {created && <section className="secret-reveal panel"><ShieldCheck /><div><strong>Copy this token now</strong><p>It cannot be shown again.</p><code>{created}</code></div><button className="button" onClick={async () => { try { await navigator.clipboard.writeText(created); setNotice('Token copied to the clipboard.') } catch { setNotice('Clipboard access failed. Select and copy the token manually.') } }}><Copy />Copy</button><button className="icon-button" aria-label="Dismiss token" onClick={() => setCreated(null)}>×</button></section>}
    {tokens.loading ? <Loading /> : tokens.error ? <ErrorState message={tokens.error} retry={tokens.reload} /> : !tokens.data?.tokens.length ? <Empty icon={KeyRound} title="No tokens yet" text="Create one for every AI or script you connect." action={<button className="button primary" onClick={openCreate}>Create token</button>} /> : <div className="table-panel panel"><table><thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Status</th><th /></tr></thead><tbody>{tokens.data.tokens.map(token => <tr key={token.id}><td><strong>{token.name}</strong></td><td><code>{token.token_prefix}…</code></td><td>{formatDate(token.last_used_at)}</td><td><Badge tone={token.revoked_at ? 'danger' : 'safe'}>{token.revoked_at ? 'Revoked' : 'Active'}</Badge></td><td>{!token.revoked_at && <button className="icon-button danger" aria-label={`Revoke ${token.name}`} onClick={() => { setFormError(''); setPendingRevoke(token) }}><Trash2 /></button>}</td></tr>)}</tbody></table></div>}
    <Dialog open={showCreate} onClose={() => setShowCreate(false)} title="Create token" description="Use a separate credential for each AI client or integration."><form className="dialog-form" onSubmit={create}><label>Token name<input autoComplete="off" required value={name} onChange={event => setName(event.target.value)} placeholder="Claude Desktop" /></label>{formError && <p className="form-error" role="alert">{formError}</p>}<div className="dialog-actions"><button type="button" className="button" onClick={() => setShowCreate(false)} disabled={busy}>Cancel</button><button className="button primary" disabled={busy}>{busy ? 'Creating…' : 'Create token'}</button></div></form></Dialog>
    <ConfirmDialog open={Boolean(pendingRevoke)} onClose={() => setPendingRevoke(null)} title="Revoke token?" description={`Connected clients using “${pendingRevoke?.name || ''}” will immediately lose access.`} confirmLabel="Revoke token" danger busy={busy} error={formError} onConfirm={revoke} />
  </div>
}

function McpPage() {
  const { csrf } = useAuth(); const [tab, setTab] = useState<'connect' | 'tools' | 'servers' | 'activity'>('connect')
  const [activityFilters, setActivityFilters] = useState({ tool: '', outcome: '', from: '', to: '' })
  const [showAddServer, setShowAddServer] = useState(false)
  const [serverDraft, setServerDraft] = useState({ name: '', url: '' })
  const [serverError, setServerError] = useState('')
  const [serverBusy, setServerBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const tools = useLoad(() => api<{ tools: any[] }>('/mcp/tools'), [])
  const servers = useLoad(() => api<any>('/mcp/servers'), [])
  const activityQuery = () => { const params = new URLSearchParams(); Object.entries(activityFilters).forEach(([name, value]) => { if (value) params.set(name, name === 'from' ? `${value}T00:00:00Z` : name === 'to' ? `${value}T23:59:59Z` : value) }); return params.toString() }
  const activity = useLoad(() => api<{ calls: any[] }>(`/audit/tools?${activityQuery()}`), [activityFilters.tool, activityFilters.outcome, activityFilters.from, activityFilters.to])
  const tokenConfig = `{
  "mcpServers": {
    "cortex": {
      "url": "${location.origin}/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}`
  const addServer = async (event: FormEvent) => {
    event.preventDefault(); setServerError(''); setServerBusy(true)
    try {
      await api('/mcp/servers', { method: 'POST', body: JSON.stringify({ name: serverDraft.name.trim(), url: serverDraft.url.trim(), global: false }) }, csrf)
      setServerDraft({ name: '', url: '' }); setShowAddServer(false); setNotice('Personal MCP server registered.'); await servers.reload()
    } catch (error) { setServerError(error instanceof Error ? error.message : 'Server registration failed.') }
    finally { setServerBusy(false) }
  }
  return <div className="page"><PageHeader eyebrow="ONE GOVERNED ENDPOINT" title="MCP gateway" description="Cortex exposes only the tools your identity may use—and records every call." />
    <div className="tabs">{(['connect', 'tools', 'servers', 'activity'] as const).map(value => <button key={value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{value}</button>)}</div>
    {tab === 'connect' && <div className="two-column"><section className="panel content-card"><div className="card-icon"><Network /></div><h2>Connect your AI once</h2><p>Give the client Cortex as its only MCP. The token determines which vaults and upstream tools appear.</p><pre><code>{tokenConfig}</code></pre><button className="button" onClick={() => navigator.clipboard.writeText(tokenConfig)}><Copy />Copy configuration</button></section><section className="panel trust-card"><ShieldCheck /><h3>The gateway contract</h3><ul><li>Upstream secrets never reach your AI.</li><li>Denied tools are invisible and uncallable.</li><li>Arguments are audited by shape, not content.</li><li>Dead upstreams cannot stall the whole session.</li></ul><Link className="button primary" to="/tokens">Create a token</Link></section></div>}
    {tab === 'tools' && (tools.loading ? <Loading /> : <div className="tool-grid">{tools.data?.tools.map(tool => <article className="panel tool-card" key={tool.id}><div><Badge>{tool.server}</Badge><Wrench /></div><h3>{tool.name}</h3><p>{tool.description || 'Cortex governed tool'}</p><code>{tool.id}</code></article>)}</div>)}
    {tab === 'servers' && <><div className="section-actions"><div><h2>Registered servers</h2><p>Personal servers remain usable only by you.</p></div>{servers.data?.allow_user_servers && <button className="button primary" onClick={() => { setServerError(''); setShowAddServer(true) }}><Plus />Add server</button>}</div>{servers.loading ? <Loading /> : !servers.data?.servers?.length ? <Empty icon={Server} title="No upstream servers" text={servers.data?.allow_user_servers ? 'Add a personal MCP server to bring its tools through Cortex.' : 'Personal server registration is disabled by your administrator.'} /> : <div className="card-list">{servers.data.servers.map((server: any) => <section className="panel server-row" key={server.id}><div className="server-icon"><Server /></div><div><h3>{server.name} <Badge tone={server.enabled ? 'safe' : 'danger'}>{server.enabled ? 'Connected' : 'Disabled'}</Badge></h3><p>{server.url}</p><small>{server.tool_count} tools · {formatDate(server.last_checked_at)}</small>{server.last_error && <p className="danger-text">{server.last_error}</p>}</div><button className="icon-button" title="Refresh inventory" onClick={async () => { await api(`/mcp/servers/${server.id}/refresh`, { method: 'POST' }, csrf); await servers.reload() }}><RefreshCw /></button></section>)}</div>}</>}
    {tab === 'activity' && <><div className="filter-bar panel"><input placeholder="Tool" value={activityFilters.tool} onChange={event => setActivityFilters({ ...activityFilters, tool: event.target.value })} /><select value={activityFilters.outcome} onChange={event => setActivityFilters({ ...activityFilters, outcome: event.target.value })}><option value="">Any outcome</option><option>allowed</option><option>denied</option><option>error</option></select><input aria-label="Activity from date" type="date" value={activityFilters.from} onChange={event => setActivityFilters({ ...activityFilters, from: event.target.value })} /><input aria-label="Activity to date" type="date" value={activityFilters.to} onChange={event => setActivityFilters({ ...activityFilters, to: event.target.value })} /><button className="button" onClick={() => setActivityFilters({ tool: '', outcome: '', from: '', to: '' })}>Clear</button></div><AuditTable rows={activity.data?.calls || []} loading={activity.loading} /></>}
    {notice && <p className="notice success" role="status">{notice}</p>}
    <Dialog open={showAddServer} onClose={() => setShowAddServer(false)} title="Add personal MCP server" description="Register a Streamable HTTP endpoint for your identity only."><form className="dialog-form" onSubmit={addServer}><label>Namespace<input required pattern="[A-Za-z0-9_-]+" value={serverDraft.name} onChange={event => setServerDraft({ ...serverDraft, name: event.target.value })} placeholder="home-assistant" /></label><label>Endpoint URL<input required type="url" value={serverDraft.url} onChange={event => setServerDraft({ ...serverDraft, url: event.target.value })} placeholder="https://mcp.example.net/mcp" /></label>{serverError && <p className="form-error" role="alert">{serverError}</p>}<div className="dialog-actions"><button type="button" className="button" onClick={() => setShowAddServer(false)} disabled={serverBusy}>Cancel</button><button className="button primary" disabled={serverBusy}>{serverBusy ? 'Registering…' : 'Add server'}</button></div></form></Dialog>
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
  const [dialog, setDialog] = useState<any | null>(null)
  const [form, setForm] = useState<any>({})
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const [notice, setNotice] = useState('')
  const [pageError, setPageError] = useState('')
  const [preview, setPreview] = useState<any | null>(null)
  const open = (kind: string, data: any = {}, values: any = {}) => { setFormError(''); setForm(values); setDialog({ kind, ...data }) }
  const addUser = () => open('add-user', {}, { username: '', password: '' })
  const editUser = (user: User) => open('edit-user', { user }, { display_name: user.display_name || '', email: user.email || '', is_admin: user.is_admin, password: '' })
  const toggleUser = async (user: User) => { setPageError(''); try { await api(`/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', body: JSON.stringify({ disabled: !user.disabled }) }, csrf); setNotice(`${user.username} is now ${user.disabled ? 'active' : 'disabled'}.`); await users.reload() } catch (error) { setPageError(error instanceof Error ? error.message : 'User update failed.') } }
  const deleteUser = (user: User) => open('delete-user', { user })
  const addGroup = () => open('add-group', {}, { name: '' })
  const editGroup = (group: any) => open('edit-group', { group }, { scopes: group.scopes.join(', '), write_scopes: (group.write_scopes || []).join(', ') })
  const deleteGroup = (group: any) => open('delete-group', { group })
  const addMember = (group: any) => open('add-member', { group }, { username: '' })
  const removeMember = (group: any) => open('remove-member', { group }, { username: group.members[0] || '' })
  const revokeAdminToken = (id: number) => open('revoke-token', { token: tokens.data?.tokens?.find((item: any) => item.id === id) })
  const editLdapPolicy = () => { if (ldap.data?.configured) open('ldap-policy', {}, { jit_provisioning: Boolean(ldap.data.jit_provisioning), group_mappings: JSON.stringify(ldap.data.group_mappings || {}, null, 2) }) }
  const dryRun = async () => { setBusy(true); setPageError(''); try { setPreview(await api<any>('/ldap/sync?dry_run=true', { method: 'POST' }, csrf)) } catch (error) { setPageError(error instanceof Error ? error.message : 'Directory preview failed.') } finally { setBusy(false) } }
  const syncNow = () => open('sync-ldap')
  const closeDialog = () => { if (!busy) { setDialog(null); setFormError('') } }
  const perform = async (event?: FormEvent) => {
    event?.preventDefault(); if (!dialog) return; setBusy(true); setFormError('')
    try {
      if (dialog.kind === 'add-user') await api('/users', { method: 'POST', body: JSON.stringify({ username: form.username.trim(), password: form.password }) }, csrf)
      if (dialog.kind === 'edit-user') { const body: Json = { display_name: form.display_name.trim() || dialog.user.username, is_admin: Boolean(form.is_admin) }; if (form.email.trim()) body.email = form.email.trim(); if (form.password) body.password = form.password; await api(`/users/${encodeURIComponent(dialog.user.username)}`, { method: 'PATCH', body: JSON.stringify(body) }, csrf) }
      if (dialog.kind === 'delete-user') await api(`/users/${encodeURIComponent(dialog.user.username)}`, { method: 'DELETE' }, csrf)
      if (dialog.kind === 'add-group') await api('/groups', { method: 'POST', body: JSON.stringify({ name: form.name.trim(), scopes: [], write_scopes: [] }) }, csrf)
      if (dialog.kind === 'edit-group') await api(`/groups/${encodeURIComponent(dialog.group.name)}`, { method: 'PATCH', body: JSON.stringify({ scopes: form.scopes.split(',').map((value: string) => value.trim()).filter(Boolean), write_scopes: form.write_scopes.split(',').map((value: string) => value.trim()).filter(Boolean) }) }, csrf)
      if (dialog.kind === 'delete-group') await api(`/groups/${encodeURIComponent(dialog.group.name)}`, { method: 'DELETE' }, csrf)
      if (dialog.kind === 'add-member') await api(`/groups/${encodeURIComponent(dialog.group.name)}/members`, { method: 'POST', body: JSON.stringify({ username: form.username.trim() }) }, csrf)
      if (dialog.kind === 'remove-member') await api(`/groups/${encodeURIComponent(dialog.group.name)}/members/${encodeURIComponent(form.username)}`, { method: 'DELETE' }, csrf)
      if (dialog.kind === 'revoke-token') await api(`/tokens/${dialog.token.id}`, { method: 'DELETE' }, csrf)
      if (dialog.kind === 'ldap-policy') { let group_mappings: Json; try { group_mappings = JSON.parse(form.group_mappings) } catch { throw new Error('Group mappings must be valid JSON.') } await api('/ldap/status', { method: 'PATCH', body: JSON.stringify({ jit_provisioning: Boolean(form.jit_provisioning), group_mappings }) }, csrf) }
      if (dialog.kind === 'sync-ldap') await api('/ldap/sync', { method: 'POST' }, csrf)
      setNotice('Change saved successfully.'); setPageError(''); setDialog(null); await Promise.all([users.reload(), groups.reload(), ldap.reload(), tokens.reload()])
    } catch (error) { setFormError(error instanceof Error ? error.message : 'The change could not be saved.') }
    finally { setBusy(false) }
  }
  return <><div className="tabs">{(['users', 'groups', 'ldap', 'tokens'] as const).map(value => <button className={tab === value ? 'active' : ''} onClick={() => setTab(value)} key={value}>{value}</button>)}</div>
    {tab === 'users' && <><div className="section-actions"><div><h2>People</h2><p>Local and directory identities share one policy model.</p></div><button className="button primary" onClick={addUser}><UserPlus />New local user</button></div><div className="table-panel panel"><table><thead><tr><th>User</th><th>Source</th><th>Groups</th><th>Last login</th><th>Status</th><th /></tr></thead><tbody>{users.data?.users?.map((user: User) => <tr key={user.username}><td><div className="user-cell"><Link className="avatar" title={`Browse ${user.username}’s vault`} to={`/vault?vault=${encodeURIComponent(user.username)}`}>{user.username[0].toUpperCase()}</Link><div><strong>{user.display_name || user.username}</strong><small>{user.email || `@${user.username}`}</small></div></div></td><td><Badge>{user.auth_source.toUpperCase()}</Badge></td><td>{user.groups?.map(group => <Badge key={group}>{group}</Badge>)}</td><td>{formatDate(user.last_login_at)}</td><td><button className="plain" onClick={() => toggleUser(user)}><Badge tone={user.disabled ? 'danger' : 'safe'}>{user.disabled ? 'Disabled' : 'Active'}</Badge></button></td><td><button className="icon-button" title="Edit user" onClick={() => editUser(user)}><Settings /></button><button className="icon-button danger" title="Delete user" onClick={() => deleteUser(user)}><Trash2 /></button></td></tr>)}</tbody></table></div></>}
    {tab === 'groups' && <><div className="section-actions"><div><h2>Groups & shared memory</h2><p>Group grants add scoped main-vault access and tool policy.</p></div><button className="button primary" onClick={addGroup}><Plus />New group</button></div><div className="card-list">{groups.data?.groups?.map((group: any) => <section className="panel group-card" key={group.name}><div className="server-icon"><Users /></div><div className="grow"><h3>{group.name} <Badge>{group.source}</Badge></h3><p>{group.members.length} members · {group.members.join(', ') || 'none'}</p><div><small>READ</small>{group.scopes.length ? group.scopes.map((scope: string) => <code key={scope}>{scope}</code>) : <span className="muted"> No shared scopes</span>}</div><div><small>WRITE</small>{group.write_scopes?.length ? group.write_scopes.map((scope: string) => <code key={scope}>{scope}</code>) : <span className="muted"> No shared writes</span>}</div></div><div className="header-actions"><button className="button" onClick={() => editGroup(group)}><Settings />Scopes</button><button className="button" onClick={() => addMember(group)}><UserPlus />Add</button>{group.members.length > 0 && <button className="button" onClick={() => removeMember(group)}><Trash2 />Remove</button>}<button className="icon-button danger" title="Delete group" onClick={() => deleteGroup(group)}><Trash2 /></button></div></section>)}</div></>}
    {tab === 'ldap' && <div className="two-column"><section className="panel content-card"><div className="card-icon"><Database /></div><h2>Directory connection</h2><p>{ldap.data?.configured ? ldap.data.server_uri : 'LDAP is not configured. Local identities remain fully available.'}</p><Badge tone={ldap.data?.configured ? 'safe' : ''}>{ldap.data?.configured ? 'Configured' : 'Off'}</Badge>{ldap.data?.configured && <><p><strong>JIT provisioning:</strong> {ldap.data.jit_provisioning ? 'on' : 'off'}</p><div className="tool-chips">{Object.entries(ldap.data.group_mappings || {}).map(([source, target]) => <code key={source}>{source} → {String(target)}</code>)}</div><button className="button" onClick={editLdapPolicy}><Settings />Edit policy</button></>}</section><section className="panel content-card"><h2>Synchronize identities</h2><p>Preview additions, updates, disables, and mapped group changes before applying them. Connection secrets remain environment-only; JIT and mapping policy is persisted in SQLite.</p><button className="button" disabled={!ldap.data?.configured || busy} onClick={dryRun}><RefreshCw />{busy ? 'Loading…' : 'Dry-run preview'}</button><button className="button primary" disabled={!ldap.data?.configured} onClick={syncNow}><Database />Sync now</button></section></div>}
    {tab === 'tokens' && <div className="table-panel panel"><table><thead><tr><th>Owner</th><th>Name</th><th>Prefix</th><th>Last used</th><th>Status</th><th /></tr></thead><tbody>{tokens.data?.tokens?.map((token: any) => <tr key={token.id}><td>{token.owner}</td><td>{token.name}</td><td><code>{token.token_prefix}…</code></td><td>{formatDate(token.last_used_at)}</td><td><Badge tone={token.revoked_at ? 'danger' : 'safe'}>{token.revoked_at ? 'Revoked' : 'Active'}</Badge></td><td>{!token.revoked_at && <button className="icon-button danger" title="Revoke token" onClick={() => revokeAdminToken(token.id)}><Trash2 /></button>}</td></tr>)}</tbody></table></div>}
    {notice && <p className="notice success" role="status">{notice}</p>}
    {pageError && <p className="form-error" role="alert">{pageError}</p>}
    <Dialog open={Boolean(dialog && !['delete-user', 'delete-group', 'revoke-token', 'sync-ldap'].includes(dialog.kind))} onClose={closeDialog} title={({ 'add-user': 'Create local user', 'edit-user': `Edit ${dialog?.user?.username || 'user'}`, 'add-group': 'Create group', 'edit-group': `Edit ${dialog?.group?.name || 'group'} scopes`, 'add-member': `Add member to ${dialog?.group?.name || 'group'}`, 'remove-member': `Remove member from ${dialog?.group?.name || 'group'}`, 'ldap-policy': 'Edit LDAP policy' } as Record<string, string>)[dialog?.kind] || 'Edit'} description={dialog?.kind === 'remove-member' ? 'Select the member to remove. Their shared-vault grants through this group will be revoked immediately.' : 'Review the values before saving. API validation remains authoritative.'}><form className="dialog-form" onSubmit={perform}>
      {dialog?.kind === 'add-user' && <><label>Username<input required autoComplete="off" value={form.username || ''} onChange={event => setForm({ ...form, username: event.target.value })} /></label><label>Temporary password<input required type="password" autoComplete="new-password" value={form.password || ''} onChange={event => setForm({ ...form, password: event.target.value })} /></label></>}
      {dialog?.kind === 'edit-user' && <><label>Display name<input value={form.display_name || ''} onChange={event => setForm({ ...form, display_name: event.target.value })} /></label><label>Email<input type="email" value={form.email || ''} onChange={event => setForm({ ...form, email: event.target.value })} /></label><label className="checkbox-field"><input type="checkbox" checked={Boolean(form.is_admin)} onChange={event => setForm({ ...form, is_admin: event.target.checked })} />Administrator</label>{dialog.user.auth_source === 'local' && <label>New password <small>Leave blank to keep the current password.</small><input type="password" autoComplete="new-password" value={form.password || ''} onChange={event => setForm({ ...form, password: event.target.value })} /></label>}</>}
      {dialog?.kind === 'add-group' && <label>Group name<input required value={form.name || ''} onChange={event => setForm({ ...form, name: event.target.value })} /></label>}
      {dialog?.kind === 'edit-group' && <><label>Read scopes <small>Comma separated</small><textarea value={form.scopes || ''} onChange={event => setForm({ ...form, scopes: event.target.value })} /></label><label>Write scopes <small>Comma separated</small><textarea value={form.write_scopes || ''} onChange={event => setForm({ ...form, write_scopes: event.target.value })} /></label></>}
      {dialog?.kind === 'add-member' && <label>User<select required value={form.username || ''} onChange={event => setForm({ ...form, username: event.target.value })}><option value="">Choose a user…</option>{users.data?.users?.filter((user: User) => !dialog.group.members.includes(user.username)).map((user: User) => <option key={user.username} value={user.username}>{user.username}</option>)}</select></label>}
      {dialog?.kind === 'remove-member' && <label>Member<select required value={form.username || ''} onChange={event => setForm({ ...form, username: event.target.value })}>{dialog.group.members.map((username: string) => <option key={username}>{username}</option>)}</select></label>}
      {dialog?.kind === 'ldap-policy' && <><label className="checkbox-field"><input type="checkbox" checked={Boolean(form.jit_provisioning)} onChange={event => setForm({ ...form, jit_provisioning: event.target.checked })} />Enable just-in-time provisioning</label><label>LDAP group mapping JSON<textarea className="code-input" rows={10} value={form.group_mappings || ''} onChange={event => setForm({ ...form, group_mappings: event.target.value })} /></label></>}
      {formError && <p className="form-error" role="alert">{formError}</p>}<div className="dialog-actions"><button type="button" className="button" onClick={closeDialog} disabled={busy}>Cancel</button><button className={`button ${dialog?.kind === 'remove-member' ? 'danger-button' : 'primary'}`} disabled={busy}>{busy ? 'Saving…' : dialog?.kind === 'remove-member' ? 'Remove member' : 'Save'}</button></div>
    </form></Dialog>
    <ConfirmDialog open={Boolean(dialog && ['delete-user', 'delete-group', 'revoke-token', 'sync-ldap'].includes(dialog.kind))} onClose={closeDialog} title={dialog?.kind === 'sync-ldap' ? 'Apply directory synchronization?' : dialog?.kind === 'delete-user' ? `Delete ${dialog.user.username}?` : dialog?.kind === 'delete-group' ? `Delete ${dialog.group.name}?` : 'Revoke token?'} description={dialog?.kind === 'sync-ldap' ? 'This applies the current directory additions, updates, disables, and group mappings.' : dialog?.kind === 'delete-user' ? 'The account will be removed. Its vault remains until explicitly archived.' : dialog?.kind === 'delete-group' ? 'Memberships and shared-vault grants will be removed.' : 'The connected client will immediately lose access.'} confirmLabel={dialog?.kind === 'sync-ldap' ? 'Sync now' : dialog?.kind === 'revoke-token' ? 'Revoke token' : 'Delete'} danger={dialog?.kind !== 'sync-ldap'} busy={busy} error={formError} onConfirm={() => perform()} />
    <Dialog open={Boolean(preview)} onClose={() => setPreview(null)} title="Directory sync preview" description="No directory changes have been applied."><pre className="preview-json"><code>{JSON.stringify(preview, null, 2)}</code></pre><div className="dialog-actions"><button className="button primary" onClick={() => setPreview(null)}>Done</button></div></Dialog>
  </>
}

function AdminVaults() {
  const { csrf } = useAuth(); const vaults = useLoad(() => api<any>('/vaults'), []); const janitor = useLoad(() => api<any>('/admin/janitor'), [])
  const [pendingArchive, setPendingArchive] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const archive = async () => { if (!pendingArchive) return; setBusy(true); setError(''); try { await api(`/admin/vaults/${encodeURIComponent(pendingArchive)}/archive`, { method: 'POST' }, csrf); setNotice(`Archived ${pendingArchive}.`); setPendingArchive(null); await vaults.reload() } catch (caught) { setError(caught instanceof Error ? caught.message : 'Vault archive failed.') } finally { setBusy(false) } }
  const repair = async (id: string) => { setError(''); try { await api(`/admin/vaults/${encodeURIComponent(id)}/repair`, { method: 'POST' }, csrf); setNotice(`Repaired ${id} and refreshed its index.`); await vaults.reload() } catch (caught) { setNotice(''); setError(caught instanceof Error ? caught.message : 'Vault repair failed.') } }
  return <><div className="stats-grid"><Stat label="Vaults" value={vaults.data?.vaults?.length || 0} icon={Vault} /><Stat label="Notes" value={vaults.data?.vaults?.reduce((sum: number, vault: any) => sum + vault.note_count, 0) || 0} icon={FileText} /><Stat label="Stored" value={formatBytes(vaults.data?.vaults?.reduce((sum: number, vault: any) => sum + vault.size_bytes, 0) || 0)} icon={Database} /></div>
    <div className="card-list">{vaults.data?.vaults?.map((vault: any) => <section className="panel vault-admin-card" key={vault.id}><div className="server-icon"><Vault /></div><div className="grow"><div className="section-actions"><div><h3>{vault.id} <Badge>{vault.relation}</Badge></h3><p>{vault.note_count} notes · {formatBytes(vault.size_bytes)} · {vault.sync_adapter} sync</p></div><Badge tone={vault.head_commit ? 'safe' : 'danger'}>{vault.head_commit ? 'Git healthy' : 'No commit'}</Badge></div><div className="progress"><span style={{ width: `${Math.min(100, (vault.index_note_count / Math.max(1, vault.note_count)) * 100)}%` }} /></div><small>Indexed {vault.index_note_count} / {vault.note_count} notes · refreshed {formatDate(vault.last_indexed_iso)}</small></div><Link className="button" to={`/vault?vault=${vault.id}`}><BookOpen />Browse</Link><button className="icon-button" title="Repair repository and index" onClick={() => repair(vault.id)}><RefreshCw /></button>{vault.id !== 'main' && <button className="icon-button danger" title="Archive vault" onClick={() => { setError(''); setPendingArchive(vault.id) }}><Archive /></button>}</section>)}</div><section className="panel content-card"><div className="section-actions"><div><p className="eyebrow">JANITOR</p><h2>Report-first maintenance</h2><p>{janitor.data?.enabled ? `Runs every ${janitor.data.interval_seconds} seconds` : 'Disabled in configuration'}</p></div><Badge tone={janitor.data?.enabled && janitor.data?.dry_run ? 'safe' : ''}>{janitor.data?.dry_run ? 'Dry run' : janitor.data?.enabled ? 'Write mode' : 'Off'}</Badge></div><p>Allowed: {(janitor.data?.allowed_paths || []).join(', ') || 'none'} · Forbidden: {(janitor.data?.forbidden_paths || []).join(', ') || 'none'}</p><div className="janitor-reports">{janitor.data?.reports?.length ? janitor.data.reports.slice(0, 8).map((report: any) => <div className="mini-event" key={report.id}><div><Badge>{report.vault}</Badge><Badge tone={report.dry_run ? 'safe' : ''}>{report.dry_run ? 'dry run' : 'applied'}</Badge></div><strong>{report.summary}</strong><small>{formatDate(report.created_at)}</small></div>) : <small>No maintenance reports yet.</small>}</div></section>
    {notice && <p className="notice success" role="status">{notice}</p>}
    {error && !pendingArchive && <p className="form-error" role="alert">{error}</p>}
    <ConfirmDialog open={Boolean(pendingArchive)} onClose={() => setPendingArchive(null)} title={`Archive ${pendingArchive || 'vault'}?`} description="The vault will be moved intact to the archive location and its active access grants removed." confirmLabel="Archive vault" danger busy={busy} error={error} onConfirm={archive} />
  </>
}

function AdminGateway() {
  const { csrf } = useAuth(); const [tab, setTab] = useState<'servers' | 'permissions'>('servers')
  const [showAdd, setShowAdd] = useState(false)
  const [draft, setDraft] = useState({ name: '', description: '', transport: 'streamable-http', url: '', auth_env: '', command: '', args: '', cwd: '', env_refs: '' })
  const [formError, setFormError] = useState('')
  const [pendingRemove, setPendingRemove] = useState<any | null>(null)
  const [pendingRuleDelete, setPendingRuleDelete] = useState<any | null>(null)
  const [showRule, setShowRule] = useState(false)
  const [ruleDraft, setRuleDraft] = useState({ subject_type: 'group', subject: '', server_name: '', tool_pattern: '*.*', effect: 'allow' })
  const [actionBusy, setActionBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [params] = useSearchParams()
  const [previewUser, setPreviewUser] = useState(params.get('user') || '')
  const servers = useLoad(() => api<any>('/mcp/servers'), []); const users = useLoad(() => api<any>('/users'), []); const groups = useLoad(() => api<any>('/groups'), []); const permissions = useLoad(() => api<any>(`/admin/permissions${previewUser ? `?user=${encodeURIComponent(previewUser)}` : ''}`), [previewUser])
  const add = async (event: FormEvent) => { event.preventDefault(); setFormError(''); try { const body: Json = { name: draft.name, description: draft.description || undefined, transport: draft.transport, global: true }; if (draft.transport === 'stdio-cmd') { body.command = draft.command; body.args = draft.args.split('\n').filter(Boolean); body.cwd = draft.cwd || undefined; body.env_refs = Object.fromEntries(draft.env_refs.split('\n').filter(Boolean).map(line => { const at = line.indexOf('='); if (at < 1) throw new Error('Environment references must use CHILD_NAME=PARENT_NAME.'); return [line.slice(0, at).trim(), line.slice(at + 1).trim()] })) } else { body.url = draft.url; body.auth_env = draft.auth_env || undefined } await api('/mcp/servers', { method: 'POST', body: JSON.stringify(body) }, csrf); setShowAdd(false); setDraft({ name: '', description: '', transport: 'streamable-http', url: '', auth_env: '', command: '', args: '', cwd: '', env_refs: '' }); await servers.reload() } catch (err) { setFormError(err instanceof Error ? err.message : 'Registration failed') } }
  const toggleServer = async (server: any) => { await api(`/mcp/servers/${server.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !server.enabled }) }, csrf); setNotice(`${server.name} ${server.enabled ? 'disabled' : 'enabled'}.`); await servers.reload() }
  const removeServer = (server: any) => { setFormError(''); setPendingRemove(server) }
  const confirmRemoveServer = async () => { if (!pendingRemove) return; setActionBusy(true); setFormError(''); try { await api(`/mcp/servers/${pendingRemove.id}`, { method: 'DELETE' }, csrf); setNotice(`Removed ${pendingRemove.name}.`); setPendingRemove(null); await servers.reload(); await permissions.reload() } catch (error) { setFormError(error instanceof Error ? error.message : 'Server removal failed.') } finally { setActionBusy(false) } }
  const addRule = () => { setFormError(''); setRuleDraft({ subject_type: 'group', subject: '', server_name: '', tool_pattern: '*.*', effect: 'allow' }); setShowRule(true) }
  const submitRule = async (event: FormEvent) => { event.preventDefault(); setActionBusy(true); setFormError(''); try { const server = ruleDraft.server_name && ruleDraft.server_name !== 'cortex' ? servers.data?.servers?.find((item: any) => item.name === ruleDraft.server_name) : null; const body: Json = { subject_type: ruleDraft.subject_type, subject: ruleDraft.subject, tool_pattern: ruleDraft.tool_pattern, effect: ruleDraft.effect }; if (server) body.server_id = server.id; await api('/admin/permissions', { method: 'POST', body: JSON.stringify(body) }, csrf); setShowRule(false); setNotice('Permission rule added.'); await permissions.reload() } catch (error) { setFormError(error instanceof Error ? error.message : 'Permission rule could not be added.') } finally { setActionBusy(false) } }
  const deleteRule = async () => { if (!pendingRuleDelete) return; setActionBusy(true); setFormError(''); try { await api(`/admin/permissions/${pendingRuleDelete.id}`, { method: 'DELETE' }, csrf); setPendingRuleDelete(null); setNotice('Permission rule removed.'); await permissions.reload() } catch (error) { setFormError(error instanceof Error ? error.message : 'Permission rule removal failed.') } finally { setActionBusy(false) } }
  return <><div className="tabs"><button className={tab === 'servers' ? 'active' : ''} onClick={() => setTab('servers')}>servers</button><button className={tab === 'permissions' ? 'active' : ''} onClick={() => setTab('permissions')}>permission matrix</button></div>
    {tab === 'servers' && <><div className="section-actions"><div><h2>Global MCP registry</h2><p>Secrets are environment references and never round-trip through this page.</p></div><button className="button primary" onClick={() => setShowAdd(!showAdd)}><Plus />Register server</button></div>{showAdd && <form className="panel content-card gateway-form" onSubmit={add}><h3>Register MCP upstream</h3><label>Namespace<input required value={draft.name} onChange={e => setDraft({...draft, name:e.target.value})} /></label><label>Description<input value={draft.description} onChange={e => setDraft({...draft, description:e.target.value})} /></label><label>Transport<select value={draft.transport} onChange={e => setDraft({...draft, transport:e.target.value})}><option value="streamable-http">Streamable HTTP</option>{servers.data?.allow_stdio_servers && <option value="stdio-cmd">Local stdio</option>}</select></label>{draft.transport === 'stdio-cmd' ? <><p className="warning">Local MCP servers execute an allowlisted program as the Cortex service user.</p><label>Absolute executable path<input required value={draft.command} onChange={e => setDraft({...draft, command:e.target.value})} /></label><label>Arguments (one literal argument per line)<textarea value={draft.args} onChange={e => setDraft({...draft, args:e.target.value})} /></label><label>Working directory (optional)<input value={draft.cwd} onChange={e => setDraft({...draft, cwd:e.target.value})} /></label><label>Environment references (CHILD_NAME=PARENT_NAME, one per line)<textarea value={draft.env_refs} onChange={e => setDraft({...draft, env_refs:e.target.value})} /></label><small>Enter variable names only. Configure secret values in the Cortex service environment.</small></> : <><label>Streamable HTTP URL<input required type="url" value={draft.url} onChange={e => setDraft({...draft, url:e.target.value})} /></label><label>Bearer token environment variable (optional)<input value={draft.auth_env} onChange={e => setDraft({...draft, auth_env:e.target.value})} /></label></>}{formError && <p className="danger-text">{formError}</p>}<div className="header-actions"><button type="button" className="button" onClick={() => setShowAdd(false)}>Cancel</button><button className="button primary">Test and register</button></div></form>}<div className="card-list">{servers.data?.servers?.map((server: any) => <section className="panel server-row" key={server.id}><div className="server-icon"><Server /></div><div className="grow"><h3>{server.name} <Badge>{server.transport === 'stdio-cmd' ? 'Local stdio' : 'HTTP'}</Badge> <Badge tone={server.enabled ? 'safe' : 'danger'}>{server.enabled ? 'Online' : 'Needs attention'}</Badge></h3><p>{server.transport === 'stdio-cmd' ? server.command : server.url}</p>{server.cwd && <small>Working directory: {server.cwd}</small>}<div className="tool-chips">{server.tools.slice(0, 8).map((tool: any) => <code key={tool.name}>{tool.name}</code>)}{server.tool_count > 8 && <Badge>+{server.tool_count - 8}</Badge>}</div>{server.last_error && <p className="danger-text">{server.last_error}</p>}</div><button className="button" onClick={async () => { await api(`/mcp/servers/${server.id}/refresh`, { method: 'POST' }, csrf); await servers.reload() }}><RefreshCw />Refresh</button><button className="icon-button" title={server.enabled ? 'Disable server' : 'Enable server'} onClick={() => toggleServer(server)}><ShieldCheck /></button><button className="icon-button danger" title="Remove server" onClick={() => removeServer(server)}><Trash2 /></button></section>)}</div></>}
    {tab === 'permissions' && <><div className="section-actions"><div><h2>Deny-wins permissions</h2><p>Explicit user and group denials are hard boundaries; defaults fill the gaps.</p></div><button className="button primary" onClick={addRule}><Plus />Add rule</button></div><div className="table-panel panel"><table><thead><tr><th>Subject</th><th>Server</th><th>Tool pattern</th><th>Effect</th><th>Created</th><th /></tr></thead><tbody>{permissions.data?.permissions?.map((rule: any) => { const subject = rule.subject_type === 'user' ? users.data?.users?.find((user: any) => user.id === rule.subject_id)?.username : groups.data?.groups?.find((group: any) => group.id === rule.subject_id)?.name; const server = rule.server_id ? servers.data?.servers?.find((item: any) => item.id === rule.server_id)?.name : 'all'; return <tr key={rule.id}><td><Badge>{rule.subject_type}</Badge> {subject || `#${rule.subject_id}`}</td><td>{server || `#${rule.server_id}`}</td><td><code>{rule.tool_pattern}</code></td><td><Badge tone={rule.effect === 'deny' ? 'danger' : 'safe'}>{rule.effect}</Badge></td><td>{formatDate(rule.created_at)}</td><td><button className="icon-button danger" aria-label="Remove permission rule" onClick={() => { setFormError(''); setPendingRuleDelete(rule) }}><Trash2 /></button></td></tr> })}</tbody></table></div><div className="section-actions matrix-heading"><div><h2>Effective access preview</h2><p>Computed from defaults plus every matching user, group, server, and tool rule.</p></div><select value={previewUser} onChange={event => setPreviewUser(event.target.value)}><option value="">Choose a user…</option>{users.data?.users?.map((user: any) => <option key={user.id} value={user.username}>{user.username}</option>)}</select></div>{previewUser && <div className="table-panel panel"><table><thead><tr><th>Tool</th><th>Effective</th><th>Matched rules</th></tr></thead><tbody>{permissions.data?.preview?.map((item: any) => <tr key={item.tool_id}><td><code>{item.tool_id}</code></td><td><Badge tone={item.allowed ? 'safe' : 'danger'}>{item.allowed ? 'Allowed' : 'Denied'}</Badge></td><td>{item.rules.length ? item.rules.map((rule: any) => <Badge key={rule.id} tone={rule.effect === 'deny' ? 'danger' : 'safe'}>{rule.effect} {rule.tool_pattern}</Badge>) : <span className="muted">Default policy</span>}</td></tr>)}</tbody></table></div>}</>}
    {notice && <p className="notice success" role="status">{notice}</p>}
    <Dialog open={showRule} onClose={() => setShowRule(false)} title="Add permission rule" description="Deny rules win when multiple rules match."><form className="dialog-form" onSubmit={submitRule}><label>Subject type<select value={ruleDraft.subject_type} onChange={event => setRuleDraft({ ...ruleDraft, subject_type: event.target.value, subject: '' })}><option value="group">Group</option><option value="user">User</option></select></label><label>Subject<select required value={ruleDraft.subject} onChange={event => setRuleDraft({ ...ruleDraft, subject: event.target.value })}><option value="">Choose…</option>{ruleDraft.subject_type === 'user' ? users.data?.users?.map((user: any) => <option key={user.username} value={user.username}>{user.username}</option>) : groups.data?.groups?.map((group: any) => <option key={group.name} value={group.name}>{group.name}</option>)}</select></label><label>Server<select value={ruleDraft.server_name} onChange={event => { const server_name = event.target.value; setRuleDraft({ ...ruleDraft, server_name, tool_pattern: server_name ? `${server_name}.*` : '*.*' }) }}><option value="">All servers</option><option value="cortex">cortex</option>{servers.data?.servers?.map((server: any) => <option key={server.id} value={server.name}>{server.name}</option>)}</select></label><label>Tool pattern<input required value={ruleDraft.tool_pattern} onChange={event => setRuleDraft({ ...ruleDraft, tool_pattern: event.target.value })} /></label><label>Effect<select value={ruleDraft.effect} onChange={event => setRuleDraft({ ...ruleDraft, effect: event.target.value })}><option value="allow">Allow</option><option value="deny">Deny</option></select></label>{formError && <p className="form-error" role="alert">{formError}</p>}<div className="dialog-actions"><button type="button" className="button" onClick={() => setShowRule(false)} disabled={actionBusy}>Cancel</button><button className="button primary" disabled={actionBusy}>{actionBusy ? 'Adding…' : 'Add rule'}</button></div></form></Dialog>
    <ConfirmDialog open={Boolean(pendingRemove)} onClose={() => setPendingRemove(null)} title={`Remove ${pendingRemove?.name || 'MCP server'}?`} description="The upstream server and all permission rules tied to it will be removed." confirmLabel="Remove server" danger busy={actionBusy} error={formError} onConfirm={confirmRemoveServer} />
    <ConfirmDialog open={Boolean(pendingRuleDelete)} onClose={() => setPendingRuleDelete(null)} title="Remove permission rule?" description="Effective access may change immediately for the affected user or group." confirmLabel="Remove rule" danger busy={actionBusy} error={formError} onConfirm={deleteRule} />
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
    {tab === 'tools' ? <AuditTable rows={calls.data?.calls || []} loading={calls.loading} permissionLinks /> : <div className="timeline">{commits.data?.commits?.map((commit: any) => <article className="timeline-item" key={`${commit.vault}-${commit.sha}`}><span /><div className="panel"><div><Badge>{commit.vault}</Badge><code>{commit.sha.slice(0, 10)}</code><time>{formatDate(commit.date)}</time></div><h3>{commit.subject}</h3><p>{commit.actor}</p><small>{commit.diff?.file_count || 0} files · +{commit.diff?.insertions || 0} / -{commit.diff?.deletions || 0}</small></div></article>)}</div>}
  </>
}

function AuditTable({ rows, loading, permissionLinks = false }: { rows: any[]; loading?: boolean; permissionLinks?: boolean }) {
  if (loading) return <Loading />
  if (!rows.length) return <Empty icon={Activity} title="No activity yet" text="Calls through Cortex will appear here—allowed, denied, and failed." />
  return <div className="table-panel panel"><table><thead><tr><th>When</th><th>Identity</th><th>Tool</th><th>Vault</th><th>Outcome</th><th>Latency</th>{permissionLinks && <th>Policy</th>}</tr></thead><tbody>{rows.map(row => { const username = String(row.subject || '').startsWith('user:') ? String(row.subject).slice(5) : ''; return <tr key={row.id}><td>{formatDate(row.ts)}</td><td>{row.subject}</td><td><code>{row.server}.{row.tool}</code></td><td>{row.vault || '—'}</td><td><Badge tone={row.decision === 'allowed' ? 'safe' : 'danger'}>{row.decision}</Badge></td><td>{row.duration_ms ?? 0} ms</td>{permissionLinks && <td>{username ? <Link className="button" to={`/admin/gateway?user=${encodeURIComponent(username)}`}>Review effective rules</Link> : <span className="muted">Static policy</span>}</td>}</tr> })}</tbody></table></div>
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

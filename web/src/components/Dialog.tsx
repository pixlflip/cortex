import { type ReactNode, useEffect, useId, useRef } from 'react'

type DialogProps = {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  children: ReactNode
  closeLabel?: string
}

const focusable = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

export function Dialog({ open, onClose, title, description, children, closeLabel = 'Close dialog' }: DialogProps) {
  const titleId = useId()
  const descriptionId = useId()
  const panel = useRef<HTMLDivElement>(null)
  const previousFocus = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!open) return
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const originalOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const timer = window.setTimeout(() => {
      const first = panel.current?.querySelector<HTMLElement>('.dialog-body input:not([disabled]), .dialog-body select:not([disabled]), .dialog-body textarea:not([disabled]), .dialog-body button:not([disabled]), .dialog-body [tabindex]:not([tabindex="-1"])') || panel.current?.querySelector<HTMLElement>(focusable)
      ;(first || panel.current)?.focus()
    })
    return () => {
      window.clearTimeout(timer)
      document.body.style.overflow = originalOverflow
      previousFocus.current?.focus()
    }
  }, [open])

  if (!open) return null

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      onClose()
      return
    }
    if (event.key !== 'Tab' || !panel.current) return
    const items = Array.from(panel.current.querySelectorAll<HTMLElement>(focusable))
    if (!items.length) {
      event.preventDefault()
      return
    }
    const first = items[0]
    const last = items[items.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  return <div className="dialog-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}>
    <div ref={panel} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={description ? descriptionId : undefined} tabIndex={-1} onKeyDown={handleKeyDown}>
      <header className="dialog-header"><div><h2 id={titleId}>{title}</h2>{description && <p id={descriptionId}>{description}</p>}</div><button type="button" className="icon-button" aria-label={closeLabel} onClick={onClose}>×</button></header>
      <div className="dialog-body">{children}</div>
    </div>
  </div>
}

type ConfirmDialogProps = {
  open: boolean
  title: string
  description: string
  confirmLabel: string
  danger?: boolean
  busy?: boolean
  error?: string
  onClose: () => void
  onConfirm: () => void
}

export function ConfirmDialog({ open, title, description, confirmLabel, danger, busy, error, onClose, onConfirm }: ConfirmDialogProps) {
  return <Dialog open={open} onClose={onClose} title={title} description={description}>
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className="dialog-actions"><button type="button" className="button" onClick={onClose} disabled={busy}>Cancel</button><button type="button" className={`button ${danger ? 'danger-button' : 'primary'}`} onClick={onConfirm} disabled={busy}>{busy ? 'Working…' : confirmLabel}</button></div>
  </Dialog>
}

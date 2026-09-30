// Resolve at call time so a change to DSH's default model also changes the
// background memory model without editing this plugin or restarting it.
export function resolveModelRoute(ctx, fallback = {}) {
  try {
    const selected = ctx.get('agentDefaultModel')?.currentSelection?.()
    if (selected?.provider && selected?.model) return { provider: selected.provider, model: selected.model }
  } catch {}
  try {
    const settings = ctx.get('settings')
    const selected = typeof settings?.get === 'function'
      ? settings.get('agent-default-model')
      : settings?.describe?.().find((item) => item.ns === 'agent-default-model')?.value
    if (selected?.provider && selected?.model) return { provider: selected.provider, model: selected.model }
  } catch {}
  if (fallback.provider && fallback.model) return { provider: fallback.provider, model: fallback.model }
  return null
}

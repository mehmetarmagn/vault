# DESIGN.md — Secure Vault visual decisions

This file is the product's design system. Anyone producing UI (human/AI) follows it.

## Idea (point of view)

It should feel like a bank vault hall: quiet, heavy, mechanical. No decoration;
what inspires trust is not ornament but **precision**: aligned numbers, honest
states, an interface that answers every click.

## Dials

ENERGY 2 / RHYTHM 2 / MOTION 2 — warm welcome, asymmetric lock screen, overlay
mount animations + press micro-effect + spinning vault-wheel motif. List content
appears without animation (content visible by default).

## Tokens

- Ground: `#14120f` (warm dark), panel `#1c1a16`, hairline `rgba(255,255,255,.08)`
- Single accent: amber `#e8a33d` — ONLY primary action + "open file" dot + focus ring
- Meaning colors: success `#4caf7d`, danger `#d4573e` (only where relevant)
- FORBIDDEN: purple/blue gradients, glassmorphic cards, glow, emoji icons, 16px radius everywhere
- Type: UI `Segoe UI Variable`, brand/empty-state headings `Georgia` serif, ids/sizes/status bar `Cascadia Mono, Consolas` mono + tabular numbers
- Radius: controls 8px, cards 10px. Row heights: list 40px, command palette 36px
- Motion: soft 150–200ms hover/focus transitions with ease-out curve, press scale .97.
  No entrance animation (content visible by default).
  `prefers-reduced-motion` disables transitions.

## Patterns

- List first: files as table rows (icon + name + mono size + relative time + hover actions)
- Command palette (`Ctrl+K`): files + actions, keyboard navigation — the power-user backbone
- Designed empty states: serif heading + single sentence + single action button
- Every button: default / hover / focus-visible / active / disabled states
- Copy is short and concrete: claims, not categories ("locks after 10 idle minutes")

```markdown
# Visual Design & UI System

This document outlines the visual design language, design tokens, layout grid, responsive behavior, and accessibility standards across the application.

---

## 1. Design Tokens & Color Palette

### Primary & Accent Colors
* **Primary / Brand**: `#0F172A` (Slate 900)
* **Accent / Interactive**: `#3B82F6` (Blue 500)
* **Hover State**: `#2563EB` (Blue 600)

### Surface & Background Colors
* **Background Light**: `#F8FAFC` (Slate 50)
* **Background Dark**: `#090D16` (Custom Dark)
* **Card Surface**: `#FFFFFF` / `#1E293B`

### Feedback Indicators
* **Success**: `#22C55E` (Emerald 500)
* **Warning**: `#F59E0B` (Amber 500)
* **Error**: `#EF4444` (Red 500)

---

## 2. Responsive Grid & Breakpoints

The layout uses a standard 12-column flex/grid system:

| Breakpoint Target | Minimum Width | Column Count | Container Margin |
| :--- | :--- | :--- | :--- |
| **Mobile (`sm`)** | `640px` | 4 columns | `16px` |
| **Tablet (`md`)** | `768px` | 8 columns | `24px` |
| **Desktop (`lg`)** | `1024px` | 12 columns | `32px` |
| **Wide (`xl`)** | `1280px` | 12 columns | Max width `1280px` auto-centered |

---

## 3. Accessibility Standards (WCAG 2.1 AA)

* **Contrast Ratios**: Body text maintains a minimum contrast ratio of `4.5:1` against background surfaces.
* **Keyboard Navigation**: All interactive elements (buttons, inputs, links) display an explicit `focus-visible` focus ring (`2px solid #3B82F6`).
* **Screen Reader Support**: Semantic HTML tags (`<main>`, `<nav>`, `<header>`, `<footer>`) are used throughout, paired with explicit `aria-label` attributes where visual text is absent.

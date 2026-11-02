# UI & Design System Specification — Vult

**Product**: Vult  
**Version**: 1.0.0 $\rightarrow$ 2.0.0  
**Author**: Kurados  

---

## 1. Design Philosophy: Native macOS-Style Dark Glassmorphism

Vult is engineered with an aesthetic inspired by macOS Sonoma and dark glassmorphic design principles:
- **Depth & Translucency**: Subtle multi-layered background cards (`#18181B`, `#222227`) resting over an ultra-deep charcoal backdrop (`#101012`), enhanced by selective backdrop filters (`blur(8px)`).
- **Vibrant Accentuation**: Clean electric blue accent (`#0A84FF`) with calibrated neon cyan glowing drop-shadows (`box-shadow: 0 8px 28px rgba(10, 132, 255, 0.32)`).
- **High-Readability Typography**: System font stack leveraging `Inter`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, and monospace fonts for secrets (`Consolas`, `JetBrains Mono`).
- **Compact Window Framing**: Strictly constrained to **400 × 620 pixels** to provide an agile, companion utility that stays out of the user's way.

---

## 2. Design Tokens & Color Palette

```css
:root {
  /* Surfaces */
  --bg-app: #101012;               /* Ultra-deep dark base */
  --bg-card: #18181B;              /* Primary elevation card */
  --bg-card-hover: #222227;        /* Interactive card hover */
  --bg-input: #1C1C20;             /* Form input backgrounds */
  --bg-modal: rgba(22, 22, 26, 0.94); /* Frosted dark modal */

  /* Borders & Dividers */
  --border-subtle: rgba(255, 255, 255, 0.07);
  --border-focused: #0A84FF;
  --border-card: rgba(255, 255, 255, 0.1);

  /* Typography Colors */
  --text-primary: #FFFFFF;         /* Headings & primary labels */
  --text-secondary: #9E9EA8;       /* Metadata & subtitles */
  --text-tertiary: #63636E;        /* Timestamps & placeholders */

  /* Brand Accents */
  --accent: #0A84FF;               /* Primary Vult Electric Blue */
  --accent-hover: #0070E0;         /* Button active / hover */
  --accent-glow: rgba(10, 132, 255, 0.35);

  /* Status Colors */
  --success: #30D158;              /* Strong passwords / valid check */
  --warning: #FFD60A;              /* Fair passwords / recovery warnings */
  --destructive: #FF453A;          /* Wipe data / deletion / errors */

  /* Dimensions & Spacing */
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 16px;
  --radius-xl: 20px;
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 14px;
  --space-lg: 20px;
  --space-xl: 28px;
}
```

---

## 3. Core Screen Layouts & Specifications

### 3.1 Lock & Authentication Screen (`src/styles/lock-screen.css`)
- **Logo Container**: Centered $68 \times 68\text{px}$ rounded squircle ($18\text{px}$ radius), background gradient `linear-gradient(135deg, #1C3E68 0%, #0F2038 100%)`, border `rgba(10, 132, 255, 0.4)`, with glowing drop-shadow.
- **PIN Keypad**:
  - $3 \times 4$ numeric grid of tactile dark buttons.
  - Active PIN progress indicators (dynamic number of dots corresponding to configured PIN length: $4$ to $8$ dots).
  - Dots smoothly fill with `--accent` on keystroke and shake on invalid input.
- **Biometric Action**: Single-click "Unlock with Windows Hello" button with Windows icon.

### 3.2 Dashboard Screen (`src/styles/dashboard.css`)
- **Fixed Header**: Sticky top navigation with Vult logo, active search input, and Quick Action buttons (New Secret $+$, Password Generator $\mathbf{\circlearrowright}$, Settings $\mathbf{\Phi}$).
- **Horizontal Category Pills**: Scrollable row of category chips with count badges (`All`, `Logins`, `Recovery Codes`, `API Tokens`, `Cards`, `Crypto`).
- **Secret Cards**:
  - Compact cards displaying Service Name, Category Icon, Identity/Username snippet, and a discrete quick-copy button.
  - Hover states reveal frosted highlight with subtle $1\text{px}$ transform lift.

### 3.3 Dynamic Entry Form (`src/styles/entry-form.css`)
- **Polymorphic Fields**: Input schema changes dynamically based on selected Category (e.g. Card Number + Expiry for Cards; Seed Phrase length for Crypto; Code textarea for Recovery Codes).
- **Auto-Detection Pill**: When pasting recovery codes, a subtle glowing blue badge dynamically pops up:
  `✨ Detected: Google 2FA Backup Codes (10 codes)`

### 3.4 Modal Dialogs (`src/styles/main.css`)
- **Backdrop**: Translucent black overlay with CSS `backdrop-filter: blur(8px)`.
- **Card**: Contained modal box with smooth slide-up animation.
- **Inputs**: Show/hide eye toggle buttons, smart <kbd>Enter</kbd> progression, and inline red warning banners (zero ugly browser prompts).

---

## 4. Version 2.0.0 Design Enhancements

### 4.1 The 2FA Recovery Code Lifeboat UI
- **Single-Code Chips**: Each backup code renders as an interactive card chip.
- **Strikethrough / Used State**:
  - Unused code: Crisp monospace text (`1481 9401`), copy icon, status "Ready".
  - Click to use: Strikethrough style (`~~1481 9401~~`), opacity lowered to $0.45$, badge updates to `"Consumed"`.
- **Remaining Counter Header**:
  - `Progress bar`: Displays filled green/blue bar representing remaining codes.
  - `Warning alert`: When remaining count drops to $\le 2$, progress bar turns amber and an alert banner appears: *"Low backup codes remaining for Google. Generate a new set soon."*

### 4.2 Developer `.env` Snippet Viewer
- In the Secret Detail screen for API Tokens or Server Keys:
  - Tab 1: **Standard View** (Key, Secret, Service, Notes).
  - Tab 2: **Developer Syntax** (Preformatted code box with `export STRIPE_KEY="..."`, `curl -H "Authorization: Bearer ..."`, or `.env` format with one-click copy).

### 4.3 Plausible Deniability Decoy Mode
- To maintain plausible deniability, the Decoy Vault UI looks **100% identical** to the primary vault.
- There are no visible watermarks, warning banners, or indicators saying "Decoy Active", ensuring zero leakage during coerced inspection.

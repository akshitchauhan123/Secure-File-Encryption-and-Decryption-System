# SecureVault

A web-based file encryption tool built with Next.js, offering AES-256-GCM encryption for files and text with a clean, password-protected interface.

**Live Demo:** [https://securevault-ks.vercel.app/]

## Features

- **Single File Encryption/Decryption** — Encrypt or decrypt individual files using a master password
- **Batch Processing** — [Confirm: process multiple files at once in a single operation]
- **Encrypted Notes** — Securely store and encrypt text-based notes
- **Steganography** — [Confirm: hide encrypted files/data inside images]
- Drag-and-drop file upload interface
- AES-256-GCM encryption for strong, authenticated encryption

## Tech Stack

- **Framework:** Next.js (React, TypeScript)
- **Encryption:** AES-256-GCM
- **Styling:** [Add your CSS framework, e.g. Tailwind CSS if used]

## Getting Started

1. Clone the repository
   ```bash
   git clone https://github.com/KumarSamratSingh1/SecureVault.git
   cd SecureVault
   ```

2. Install dependencies
   ```bash
   npm install
   ```

3. Run the development server
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser

## How It Works

1. Enter a master password
2. Drop a file (or select Batch / Encrypted Notes / Steganography mode)
3. Click **Encrypt** to secure your file, or **Decrypt** to recover it using the same password

## Security Notes

- Encryption uses AES-256-GCM for authenticated encryption, protecting both confidentiality and integrity of data
- [Add: whether encryption happens client-side in the browser, or via server/API routes — this matters for anyone auditing how their password/data is handled]

## License

[Add a license if you want one, e.g. MIT]

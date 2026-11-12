"use client";

import { useState, useRef, useCallback, useEffect } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────
type Tab = "file" | "batch" | "notes" | "steg";
type Status = "idle" | "processing" | "success" | "error";

interface BatchFile {
  id: string;
  file: File;
  status: "pending" | "processing" | "done" | "error";
  hash?: string;
  resultBlob?: Blob;
  outputName?: string;
  size: string;
}

interface Note {
  id: string;
  title: string;
  content: string;
  createdAt: number;
  encrypted: boolean;
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    km,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBuffer(data: ArrayBuffer, password: string): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0); result.set(iv, 16);
  result.set(new Uint8Array(encrypted), 28);
  return result;
}

async function decryptBuffer(data: Uint8Array, password: string): Promise<ArrayBuffer> {
  const salt = data.slice(0, 16), iv = data.slice(16, 28), cipher = data.slice(28);
  const key = await deriveKey(password, salt);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
}

async function encryptFile(file: File, password: string): Promise<{ blob: Blob; outputName: string }> {
  const fileBuffer = await file.arrayBuffer();
  const enc = new TextEncoder();
  const meta = enc.encode(JSON.stringify({ name: file.name, type: file.type }));
  const metaLen = new Uint8Array(4);
  new DataView(metaLen.buffer).setUint32(0, meta.length);
  const combined = new Uint8Array(4 + meta.length + fileBuffer.byteLength);
  combined.set(metaLen, 0); combined.set(meta, 4);
  combined.set(new Uint8Array(fileBuffer), 4 + meta.length);
  const encrypted = await encryptBuffer(combined.buffer, password);
  return { blob: new Blob([encrypted]), outputName: file.name + ".vault" };
}

async function decryptFile(file: File, password: string): Promise<{ blob: Blob; filename: string }> {
  const buf = await file.arrayBuffer();
  const dec = await decryptBuffer(new Uint8Array(buf), password);
  const decArr = new Uint8Array(dec);
  const metaLen = new DataView(dec).getUint32(0);
  const meta = JSON.parse(new TextDecoder().decode(decArr.slice(4, 4 + metaLen)));
  const fileData = decArr.slice(4 + metaLen);
  return { blob: new Blob([fileData], { type: meta.type }), filename: meta.name };
}

async function sha256(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const hashBuf = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function passwordStrength(pw: string): { score: number; label: string; color: string } {
  if (!pw) return { score: 0, label: "", color: "#333" };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 1) return { score, label: "Weak", color: "#ff4444" };
  if (score <= 2) return { score, label: "Fair", color: "#ff9800" };
  if (score <= 3) return { score, label: "Good", color: "#ffeb3b" };
  if (score <= 4) return { score, label: "Strong", color: "#00e676" };
  return { score, label: "Excellent", color: "#00e5ff" };
}

const NOTES_KEY = "sv_encrypted_notes";
function loadNotes(): Note[] {
  try { return JSON.parse(localStorage.getItem(NOTES_KEY) || "[]"); } catch { return []; }
}
function saveNotes(notes: Note[]) {
  localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
}

// ─── Steganography helpers ────────────────────────────────────────────────────
async function hideTextInImage(imageFile: File, secret: string): Promise<Blob> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(imageFile);
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const pixels = imageData.data;

      const enc = new TextEncoder();
      const msgBytes = enc.encode(secret);
      const totalLen = msgBytes.length;
      const header = new Uint8Array(4);
      new DataView(header.buffer).setUint32(0, totalLen);
      const payload = new Uint8Array(4 + totalLen);
      payload.set(header, 0);
      payload.set(msgBytes, 4);

      const bitsNeeded = payload.length * 8;
      const pixelsNeeded = Math.ceil(bitsNeeded / 2);
      if (pixelsNeeded * 4 > pixels.length) {
        reject(new Error("Image too small to hold this message"));
        return;
      }

      let bitIdx = 0;
      for (let i = 0; i < payload.length; i++) {
        for (let b = 7; b >= 0; b--) {
          const bit = (payload[i] >> b) & 1;
          const pixelOffset = bitIdx * 4;
          pixels[pixelOffset] = (pixels[pixelOffset] & 0xfe) | bit;
          bitIdx++;
        }
      }

      ctx.putImageData(imageData, 0, 0);
      canvas.toBlob(
        blob => blob ? resolve(blob) : reject(new Error("Canvas export failed")),
        "image/png"
      );
    };
    img.onerror = () => reject(new Error("Failed to load image"));
    img.src = url;
  });
}

async function extractTextFromImage(imageFile: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(imageFile);
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);

      const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;

      let lengthBits = "";
      for (let i = 0; i < 32; i++) {
        lengthBits += (pixels[i * 4] & 1).toString();
      }
      const msgLen = parseInt(lengthBits, 2);

      if (msgLen <= 0 || msgLen > 10_000_000) {
        reject(new Error("No hidden message found (or wrong image)"));
        return;
      }

      const totalBits = (4 + msgLen) * 8;
      if ((totalBits / 2) * 4 > pixels.length) {
        reject(new Error("Image is too small — data may be corrupted"));
        return;
      }

      const msgBytes = new Uint8Array(msgLen);
      for (let i = 0; i < msgLen; i++) {
        let byte = 0;
        for (let b = 7; b >= 0; b--) {
          const bitIdx = 32 + i * 8 + (7 - b);
          byte |= (pixels[bitIdx * 4] & 1) << b;
        }
        msgBytes[i] = byte;
      }

      resolve(new TextDecoder().decode(msgBytes));
    };
    img.onerror = () => reject(new Error("Failed to load image"));
    img.src = url;
  });
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const Icon = {
  Shield: () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>,
  Lock: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  Unlock: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>,
  File: ({ s = 32 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  Download: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  Eye: ({ open, s = 16 }: { open: boolean; s?: number }) => open
    ? <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
    : <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
  Trash: ({ s = 15 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>,
  Hash: ({ s = 14 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>,
  Plus: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Check: ({ s = 14 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
  X: ({ s = 14 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  Copy: ({ s = 14 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
  Layers: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>,
  Note: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>,
  Image: ({ s = 16 }: { s?: number }) => <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>,
};

// ─── Main Component ───────────────────────────────────────────────────────────
export default function SecureVault() {
  const [tab, setTab] = useState<Tab>("file");

  // Single file
  const [singleFile, setSingleFile] = useState<File | null>(null);
  const [singleHash, setSingleHash] = useState<string>("");
  const [singleStatus, setSingleStatus] = useState<Status>("idle");
  const [singleResult, setSingleResult] = useState<{ blob: Blob; name: string; size: string } | null>(null);
  const [singleDragging, setSingleDragging] = useState(false);
  const singleRef = useRef<HTMLInputElement>(null);

  // Batch
  const [batchFiles, setBatchFiles] = useState<BatchFile[]>([]);
  const [batchDragging, setBatchDragging] = useState(false);
  const batchRef = useRef<HTMLInputElement>(null);
  const [batchMode, setBatchMode] = useState<"encrypt" | "decrypt">("encrypt");

  // Notes
  const [notes, setNotes] = useState<Note[]>([]);
  const [activeNote, setActiveNote] = useState<Note | null>(null);
  const [noteTitle, setNoteTitle] = useState("");
  const [noteContent, setNoteContent] = useState("");
  const [noteMode, setNoteMode] = useState<"list" | "edit" | "view">("list");
  const [decryptedNoteContent, setDecryptedNoteContent] = useState("");
  const [decryptionOk, setDecryptionOk] = useState(false);
  const [noteSaveMsg, setNoteSaveMsg] = useState<"" | "saved" | "error">("");

  // Steganography
  const [stegFile, setStegFile] = useState<File | null>(null);
  const [stegMessage, setStegMessage] = useState("");
  const [stegExtracted, setStegExtracted] = useState("");
  const [stegStatus, setStegStatus] = useState<Status>("idle");
  const [stegResult, setStegResult] = useState<{ blob: Blob; name: string } | null>(null);
  const [stegDragging, setStegDragging] = useState(false);
  const [stegErrorMsg, setStegErrorMsg] = useState("");
  const [stegPreviewUrl, setStegPreviewUrl] = useState<string>("");
  const [copiedSteg, setCopiedSteg] = useState(false);
  const stegRef = useRef<HTMLInputElement>(null);

  // Shared
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const pwStrength = passwordStrength(password);

  useEffect(() => { setNotes(loadNotes()); }, []);

  // Cleanup steg preview URL on unmount or file change
  useEffect(() => {
    return () => { if (stegPreviewUrl) URL.revokeObjectURL(stegPreviewUrl); };
  }, [stegPreviewUrl]);

  // ── Single File ──
  const handleSingleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault(); setSingleDragging(false);
    const f = e.dataTransfer.files[0];
    if (!f) return;
    setSingleFile(f); setSingleStatus("idle"); setSingleResult(null); setSingleHash("");
    const h = await sha256(f); setSingleHash(h);
  }, []);

  const handleSingleChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f) return;
    setSingleFile(f); setSingleStatus("idle"); setSingleResult(null); setSingleHash("");
    const h = await sha256(f); setSingleHash(h);
  };

  const handleSingleEncrypt = async () => {
    if (!singleFile || !password) return;
    setSingleStatus("processing");
    try {
      const { blob, outputName } = await encryptFile(singleFile, password);
      setSingleResult({ blob, name: outputName, size: formatSize(blob.size) });
      setSingleStatus("success");
    } catch { setSingleStatus("error"); }
  };

  const handleSingleDecrypt = async () => {
    if (!singleFile || !password) return;
    setSingleStatus("processing");
    try {
      const { blob, filename } = await decryptFile(singleFile, password);
      const verifyHash = await sha256(new File([blob], filename));
      setSingleResult({ blob, name: filename, size: formatSize(blob.size) });
      setSingleHash(verifyHash);
      setSingleStatus("success");
    } catch { setSingleStatus("error"); }
  };

  const downloadBlob = (blob: Blob, name: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
  };

  // ── Batch ──
  const addBatchFiles = async (files: FileList | File[]) => {
    const arr = Array.from(files);
    const newItems: BatchFile[] = await Promise.all(arr.map(async (f) => ({
      id: Math.random().toString(36).slice(2),
      file: f, status: "pending" as const,
      hash: await sha256(f),
      size: formatSize(f.size),
    })));
    setBatchFiles(prev => [...prev, ...newItems]);
  };

  const handleBatchDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setBatchDragging(false);
    addBatchFiles(e.dataTransfer.files);
  }, []);

  const processBatch = async () => {
    if (!password || batchFiles.length === 0) return;
    const updated = [...batchFiles];
    for (let i = 0; i < updated.length; i++) {
      if (updated[i].status === "done") continue;
      updated[i] = { ...updated[i], status: "processing" };
      setBatchFiles([...updated]);
      try {
        if (batchMode === "encrypt") {
          const { blob, outputName } = await encryptFile(updated[i].file, password);
          updated[i] = { ...updated[i], status: "done", resultBlob: blob, outputName };
        } else {
          const { blob, filename } = await decryptFile(updated[i].file, password);
          updated[i] = { ...updated[i], status: "done", resultBlob: blob, outputName: filename };
        }
      } catch {
        updated[i] = { ...updated[i], status: "error" };
      }
      setBatchFiles([...updated]);
    }
  };

  const downloadBatchItem = (item: BatchFile) => {
    if (item.resultBlob && item.outputName) downloadBlob(item.resultBlob, item.outputName);
  };

  const downloadAllBatch = () => {
    batchFiles.filter(f => f.status === "done").forEach(f => downloadBatchItem(f));
  };

  // ── Notes ──
  const createNote = () => {
    setActiveNote(null);
    setNoteTitle("");
    setNoteContent("");
    setDecryptionOk(false);
    setNoteMode("edit");
  };

  const saveNote = async (titleOverride?: string, contentOverride?: string) => {
    const finalTitle = (titleOverride ?? noteTitle).trim();
    const finalContent = contentOverride ?? noteContent;
    if (!finalTitle) return;

    let storedContent = finalContent;
    let encrypted = false;

    if (password) {
      try {
        const enc = new TextEncoder();
        const buf = await encryptBuffer(enc.encode(finalContent).buffer, password);
        storedContent = btoa(String.fromCharCode(...buf));
        encrypted = true;
      } catch {
        setNoteSaveMsg("error");
        setTimeout(() => setNoteSaveMsg(""), 2500);
        return;
      }
    }

    const note: Note = {
      id: activeNote?.id || Math.random().toString(36).slice(2),
      title: finalTitle,
      content: storedContent,
      encrypted,
      createdAt: activeNote?.createdAt || Date.now(),
    };

    const updated = activeNote
      ? notes.map(n => n.id === activeNote.id ? note : n)
      : [...notes, note];

    setNotes(updated);
    saveNotes(updated);
    setNoteSaveMsg("saved");
    setTimeout(() => setNoteSaveMsg(""), 2000);
    setNoteMode("list");
  };

  const viewNote = async (note: Note) => {
    setActiveNote(note);
    setDecryptionOk(false);

    if (note.encrypted) {
      if (!password) {
        setDecryptedNoteContent("🔒 Enter the master password above to decrypt this note.");
        setNoteMode("view");
        return;
      }
      try {
        const bytes = Uint8Array.from(atob(note.content), c => c.charCodeAt(0));
        const dec = await decryptBuffer(bytes, password);
        setDecryptedNoteContent(new TextDecoder().decode(dec));
        setDecryptionOk(true);
      } catch {
        setDecryptedNoteContent("❌ Wrong password — cannot decrypt this note.");
        setDecryptionOk(false);
      }
    } else {
      setDecryptedNoteContent(note.content);
      setDecryptionOk(true);
    }
    setNoteMode("view");
  };

  const editNote = () => {
    if (!activeNote) return;
    if (activeNote.encrypted && !decryptionOk) return;
    setNoteTitle(activeNote.title);
    setNoteContent(decryptedNoteContent);
    setNoteMode("edit");
  };

  const deleteNote = (id: string) => {
    const updated = notes.filter(n => n.id !== id);
    setNotes(updated);
    saveNotes(updated);
    if (activeNote?.id === id) {
      setActiveNote(null);
      setNoteMode("list");
    }
  };

  const copyHash = () => {
    navigator.clipboard.writeText(singleHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // ── Steganography ──
  const handleStegDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setStegDragging(false);
    const f = e.dataTransfer.files[0];
    if (!f) return;
    setStegFile(f);
    setStegStatus("idle");
    setStegResult(null);
    setStegExtracted("");
    setStegErrorMsg("");
    if (stegPreviewUrl) URL.revokeObjectURL(stegPreviewUrl);
    setStegPreviewUrl(URL.createObjectURL(f));
  }, [stegPreviewUrl]);

  const handleStegFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f) return;
    setStegFile(f);
    setStegStatus("idle");
    setStegResult(null);
    setStegExtracted("");
    setStegErrorMsg("");
    if (stegPreviewUrl) URL.revokeObjectURL(stegPreviewUrl);
    setStegPreviewUrl(URL.createObjectURL(f));
  };

  const handleStegHide = async () => {
    if (!stegFile || !stegMessage.trim()) return;
    setStegStatus("processing");
    setStegErrorMsg("");
    setStegExtracted("");
    try {
      const blob = await hideTextInImage(stegFile, stegMessage);
      const outName = stegFile.name.replace(/\.[^.]+$/, "") + "_steg.png";
      setStegResult({ blob, name: outName });
      setStegStatus("success");
    } catch (e: any) {
      setStegErrorMsg(e?.message || "Failed to hide message in image.");
      setStegStatus("error");
    }
  };

  const handleStegExtract = async () => {
    if (!stegFile) return;
    setStegStatus("processing");
    setStegErrorMsg("");
    setStegResult(null);
    try {
      const text = await extractTextFromImage(stegFile);
      setStegExtracted(text);
      setStegStatus("success");
    } catch (e: any) {
      setStegErrorMsg(e?.message || "No hidden message found, or image is unsupported.");
      setStegStatus("error");
    }
  };

  const copyStegText = () => {
    navigator.clipboard.writeText(stegExtracted);
    setCopiedSteg(true);
    setTimeout(() => setCopiedSteg(false), 2000);
  };

  const batchDone = batchFiles.filter(f => f.status === "done").length;
  const batchTotal = batchFiles.length;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        .sv { min-height: 100vh; background: #060810; font-family: 'Outfit', sans-serif; color: #fff; display: flex; align-items: flex-start; justify-content: center; padding: 2rem 1rem; position: relative; overflow-x: hidden; }

        .sv-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(0,200,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,200,255,0.025) 1px, transparent 1px); background-size: 50px 50px; pointer-events: none; }
        .sv-glow1 { position: fixed; width: 700px; height: 700px; border-radius: 50%; background: radial-gradient(circle, rgba(0,200,255,0.07) 0%, transparent 65%); top: -250px; left: -200px; pointer-events: none; }
        .sv-glow2 { position: fixed; width: 600px; height: 600px; border-radius: 50%; background: radial-gradient(circle, rgba(120,0,255,0.07) 0%, transparent 65%); bottom: -200px; right: -150px; pointer-events: none; }

        .sv-wrap { position: relative; width: 100%; max-width: 600px; z-index: 1; }

        /* Header */
        .sv-head { text-align: center; margin-bottom: 2rem; }
        .sv-badge { display: inline-flex; align-items: center; gap: 6px; background: rgba(0,200,255,0.08); border: 1px solid rgba(0,200,255,0.2); border-radius: 100px; padding: 5px 14px 5px 10px; font-size: 0.72rem; font-weight: 600; color: rgba(0,200,255,0.9); letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 1rem; }
        .sv-badge-dot { width: 6px; height: 6px; border-radius: 50%; background: #00c8ff; box-shadow: 0 0 8px #00c8ff; animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.4} }
        .sv-title { font-size: 2.2rem; font-weight: 800; letter-spacing: -0.03em; line-height: 1.1; margin-bottom: 0.5rem; }
        .sv-title-main { color: #fff; }
        .sv-title-accent { color: #00c8ff; }
        .sv-desc { font-size: 0.875rem; color: rgba(255,255,255,0.35); font-weight: 300; }

        /* Card */
        .sv-card { background: rgba(255,255,255,0.028); border: 1px solid rgba(255,255,255,0.07); border-radius: 20px; overflow: hidden; backdrop-filter: blur(24px); }

        /* Nav tabs */
        .sv-nav { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; border-bottom: 1px solid rgba(255,255,255,0.06); }
        .sv-nav-btn { display: flex; align-items: center; justify-content: center; gap: 7px; padding: 0.9rem 0.5rem; background: none; border: none; font-family: 'Outfit', sans-serif; font-size: 0.78rem; font-weight: 500; color: rgba(255,255,255,0.35); cursor: pointer; transition: all 0.2s; position: relative; letter-spacing: 0.01em; }
        .sv-nav-btn:hover { color: rgba(255,255,255,0.65); background: rgba(255,255,255,0.03); }
        .sv-nav-btn.active { color: #00c8ff; }
        .sv-nav-btn.active::after { content: ''; position: absolute; bottom: 0; left: 20%; right: 20%; height: 2px; background: #00c8ff; border-radius: 2px 2px 0 0; box-shadow: 0 0 10px rgba(0,200,255,0.6); }

        /* Body */
        .sv-body { padding: 1.75rem; }

        /* Password row */
        .sv-pw-section { margin-bottom: 1.5rem; }
        .sv-label { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: rgba(255,255,255,0.35); margin-bottom: 0.5rem; display: block; }
        .sv-input-row { position: relative; }
        .sv-input { width: 100%; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 0.72rem 2.8rem 0.72rem 1rem; color: #fff; font-family: 'Outfit', sans-serif; font-size: 0.9rem; font-weight: 400; outline: none; transition: border-color 0.2s, background 0.2s; }
        .sv-input:focus { border-color: rgba(0,200,255,0.4); background: rgba(0,200,255,0.03); }
        .sv-input::placeholder { color: rgba(255,255,255,0.18); }
        .sv-eye { position: absolute; right: 0.8rem; top: 50%; transform: translateY(-50%); background: none; border: none; color: rgba(255,255,255,0.3); cursor: pointer; display: flex; transition: color 0.2s; padding: 2px; }
        .sv-eye:hover { color: rgba(255,255,255,0.6); }

        /* Strength meter */
        .sv-strength { margin-top: 0.5rem; display: flex; align-items: center; gap: 8px; }
        .sv-strength-bars { display: flex; gap: 3px; flex: 1; }
        .sv-strength-bar { height: 3px; flex: 1; border-radius: 2px; background: rgba(255,255,255,0.08); transition: background 0.3s; }
        .sv-strength-label { font-size: 0.72rem; font-weight: 600; min-width: 58px; text-align: right; }

        /* Drop zone */
        .sv-drop { border: 1.5px dashed rgba(255,255,255,0.09); border-radius: 12px; padding: 1.75rem 1.25rem; text-align: center; cursor: pointer; transition: all 0.25s; margin-bottom: 1.25rem; }
        .sv-drop:hover, .sv-drop.drag { border-color: rgba(0,200,255,0.4); background: rgba(0,200,255,0.04); }
        .sv-drop.has { border-style: solid; border-color: rgba(0,200,255,0.3); background: rgba(0,200,255,0.03); }
        .sv-drop-icon { color: rgba(255,255,255,0.15); margin-bottom: 0.6rem; transition: color 0.2s; }
        .sv-drop:hover .sv-drop-icon, .sv-drop.drag .sv-drop-icon, .sv-drop.has .sv-drop-icon { color: rgba(0,200,255,0.7); }
        .sv-drop-main { font-size: 0.875rem; font-weight: 500; color: rgba(255,255,255,0.6); margin-bottom: 0.25rem; }
        .sv-drop-sub { font-size: 0.78rem; color: rgba(255,255,255,0.25); font-weight: 300; }
        .sv-fname { font-size: 0.875rem; font-weight: 600; color: #00c8ff; margin-bottom: 0.2rem; word-break: break-all; }
        .sv-fsize { font-size: 0.78rem; color: rgba(255,255,255,0.35); }

        /* Hash box */
        .sv-hash { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 0.65rem 0.85rem; margin-bottom: 1.25rem; display: flex; align-items: center; gap: 8px; }
        .sv-hash-label { font-size: 0.68rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: rgba(0,200,255,0.6); white-space: nowrap; display: flex; align-items: center; gap: 4px; }
        .sv-hash-val { font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: rgba(255,255,255,0.4); word-break: break-all; flex: 1; line-height: 1.4; }
        .sv-hash-copy { background: none; border: none; color: rgba(255,255,255,0.3); cursor: pointer; display: flex; flex-shrink: 0; transition: color 0.2s; padding: 2px; }
        .sv-hash-copy:hover { color: #00c8ff; }

        /* Action buttons */
        .sv-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 1rem; }
        .sv-btn { display: flex; align-items: center; justify-content: center; gap: 7px; padding: 0.72rem 1rem; border-radius: 9px; font-family: 'Outfit', sans-serif; font-size: 0.85rem; font-weight: 600; cursor: pointer; border: none; transition: all 0.2s; letter-spacing: 0.01em; }
        .sv-btn:disabled { opacity: 0.3; cursor: not-allowed; transform: none !important; }
        .sv-btn-primary { background: linear-gradient(135deg, #00b4d8, #0077b6); color: #fff; box-shadow: 0 4px 16px rgba(0,180,216,0.25); }
        .sv-btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,180,216,0.35); }
        .sv-btn-ghost { background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.6); border: 1px solid rgba(255,255,255,0.09); }
        .sv-btn-ghost:hover:not(:disabled) { background: rgba(255,255,255,0.09); color: #fff; }
        .sv-btn-green { background: linear-gradient(135deg, #00b894, #00796b); color: #fff; box-shadow: 0 4px 16px rgba(0,184,148,0.2); }
        .sv-btn-green:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,184,148,0.3); }
        .sv-btn-red { background: rgba(255,68,68,0.1); color: #ff6b6b; border: 1px solid rgba(255,68,68,0.2); }
        .sv-btn-red:hover:not(:disabled) { background: rgba(255,68,68,0.18); }
        .sv-btn-purple { background: linear-gradient(135deg, #7c3aed, #4f46e5); color: #fff; box-shadow: 0 4px 16px rgba(124,58,237,0.25); }
        .sv-btn-purple:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(124,58,237,0.35); }
        .sv-btn-full { width: 100%; margin-bottom: 8px; }
        .sv-btn-sm { padding: 0.45rem 0.75rem; font-size: 0.78rem; border-radius: 7px; }

        /* Status alerts */
        .sv-alert { display: flex; align-items: center; gap: 9px; padding: 0.75rem 1rem; border-radius: 9px; font-size: 0.85rem; font-weight: 500; margin-bottom: 1.25rem; }
        .sv-alert-success { background: rgba(0,184,148,0.1); border: 1px solid rgba(0,184,148,0.25); color: #00e5b0; }
        .sv-alert-error { background: rgba(255,68,68,0.09); border: 1px solid rgba(255,68,68,0.22); color: #ff6b6b; }
        .sv-alert-info { background: rgba(0,200,255,0.07); border: 1px solid rgba(0,200,255,0.18); color: rgba(0,200,255,0.85); }
        .sv-alert-warn { background: rgba(255,152,0,0.08); border: 1px solid rgba(255,152,0,0.25); color: #ffb74d; }
        .sv-alert-purple { background: rgba(124,58,237,0.08); border: 1px solid rgba(124,58,237,0.25); color: rgba(167,139,250,0.9); }
        .sv-spinner { width: 15px; height: 15px; border: 2px solid rgba(0,200,255,0.2); border-top-color: #00c8ff; border-radius: 50%; animation: spin 0.7s linear infinite; flex-shrink: 0; }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Result card */
        .sv-result { background: rgba(0,184,148,0.06); border: 1px solid rgba(0,184,148,0.2); border-radius: 12px; padding: 1.25rem; text-align: center; margin-bottom: 1rem; }
        .sv-result-icon { color: #00c8ff; margin-bottom: 0.6rem; }
        .sv-result-title { font-size: 0.975rem; font-weight: 700; color: #fff; margin-bottom: 0.35rem; }
        .sv-result-meta { font-size: 0.78rem; color: rgba(255,255,255,0.38); line-height: 1.7; }

        /* Batch */
        .sv-batch-toggle { display: grid; grid-template-columns: 1fr 1fr; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.07); border-radius: 9px; padding: 3px; gap: 2px; margin-bottom: 1.25rem; }
        .sv-toggle-btn { padding: 0.5rem; border-radius: 7px; border: none; background: transparent; font-family: 'Outfit', sans-serif; font-size: 0.82rem; font-weight: 500; color: rgba(255,255,255,0.4); cursor: pointer; transition: all 0.2s; }
        .sv-toggle-btn.active { background: rgba(0,200,255,0.12); color: #00c8ff; border: 1px solid rgba(0,200,255,0.2); }

        .sv-batch-list { display: flex; flex-direction: column; gap: 6px; margin-bottom: 1.25rem; max-height: 260px; overflow-y: auto; }
        .sv-batch-list::-webkit-scrollbar { width: 4px; }
        .sv-batch-list::-webkit-scrollbar-track { background: transparent; }
        .sv-batch-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

        .sv-batch-item { display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 9px; padding: 0.65rem 0.85rem; }
        .sv-batch-item.done { border-color: rgba(0,184,148,0.2); }
        .sv-batch-item.error { border-color: rgba(255,68,68,0.2); }
        .sv-batch-item.processing { border-color: rgba(0,200,255,0.2); }
        .sv-batch-fname { flex: 1; font-size: 0.8rem; color: rgba(255,255,255,0.7); word-break: break-all; line-height: 1.3; }
        .sv-batch-size { font-size: 0.72rem; color: rgba(255,255,255,0.3); white-space: nowrap; }
        .sv-batch-status { flex-shrink: 0; }
        .sv-status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .sv-status-dot.pending { background: rgba(255,255,255,0.2); }
        .sv-status-dot.done { background: #00b894; }
        .sv-status-dot.error { background: #ff4444; }

        .sv-batch-progress { background: rgba(255,255,255,0.05); border-radius: 100px; height: 4px; overflow: hidden; margin-bottom: 1rem; }
        .sv-batch-bar { height: 100%; background: linear-gradient(90deg, #00b4d8, #00b894); border-radius: 100px; transition: width 0.4s ease; }

        /* Notes */
        .sv-notes-list { display: flex; flex-direction: column; gap: 8px; margin-bottom: 1.25rem; max-height: 300px; overflow-y: auto; }
        .sv-notes-list::-webkit-scrollbar { width: 4px; }
        .sv-notes-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

        .sv-note-item { display: flex; align-items: flex-start; gap: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 0.85rem 1rem; cursor: pointer; transition: all 0.2s; }
        .sv-note-item:hover { background: rgba(255,255,255,0.055); border-color: rgba(0,200,255,0.18); }
        .sv-note-icon { color: rgba(0,200,255,0.5); flex-shrink: 0; margin-top: 1px; }
        .sv-note-body { flex: 1; min-width: 0; }
        .sv-note-title { font-size: 0.875rem; font-weight: 600; color: rgba(255,255,255,0.85); margin-bottom: 0.2rem; }
        .sv-note-preview { font-size: 0.76rem; color: rgba(255,255,255,0.3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .sv-note-lock { font-size: 0.65rem; color: #00c8ff; background: rgba(0,200,255,0.1); border: 1px solid rgba(0,200,255,0.2); border-radius: 4px; padding: 1px 5px; margin-left: 6px; }
        .sv-note-del { background: none; border: none; color: rgba(255,255,255,0.2); cursor: pointer; display: flex; flex-shrink: 0; transition: color 0.2s; padding: 2px; }
        .sv-note-del:hover { color: #ff6b6b; }
        .sv-note-empty { text-align: center; padding: 2rem; color: rgba(255,255,255,0.2); font-size: 0.875rem; }

        .sv-note-view-title { font-size: 1.1rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem; }
        .sv-note-view-meta { font-size: 0.75rem; color: rgba(255,255,255,0.3); margin-bottom: 1rem; }
        .sv-note-view-body { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 9px; padding: 1rem; font-size: 0.875rem; color: rgba(255,255,255,0.7); white-space: pre-wrap; line-height: 1.7; max-height: 220px; overflow-y: auto; margin-bottom: 1rem; }
        .sv-textarea { width: 100%; min-height: 130px; resize: vertical; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 9px; padding: 0.75rem 1rem; color: #fff; font-family: 'Outfit', sans-serif; font-size: 0.875rem; outline: none; transition: border-color 0.2s; }
        .sv-textarea:focus { border-color: rgba(0,200,255,0.35); }
        .sv-textarea::placeholder { color: rgba(255,255,255,0.18); }

        .sv-note-actions { display: flex; gap: 8px; }
        .sv-section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
        .sv-section-title { font-size: 0.82rem; font-weight: 600; color: rgba(255,255,255,0.4); letter-spacing: 0.08em; text-transform: uppercase; }

        .sv-divider { height: 1px; background: rgba(255,255,255,0.06); margin: 1.25rem 0; }

        /* Steganography */
        .sv-steg-preview { width: 100%; max-height: 180px; object-fit: contain; border-radius: 10px; border: 1px solid rgba(255,255,255,0.07); margin-bottom: 1rem; background: rgba(0,0,0,0.3); }
        .sv-steg-capacity { display: flex; align-items: center; gap: 8px; background: rgba(124,58,237,0.07); border: 1px solid rgba(124,58,237,0.18); border-radius: 8px; padding: 0.6rem 0.85rem; margin-bottom: 1.25rem; font-size: 0.78rem; color: rgba(167,139,250,0.8); }
        .sv-steg-extracted { background: rgba(0,0,0,0.35); border: 1px solid rgba(124,58,237,0.25); border-radius: 9px; padding: 1rem; font-size: 0.875rem; color: rgba(255,255,255,0.75); white-space: pre-wrap; line-height: 1.7; max-height: 200px; overflow-y: auto; margin-bottom: 0.85rem; font-family: 'JetBrains Mono', monospace; }
        .sv-steg-mode-toggle { display: grid; grid-template-columns: 1fr 1fr; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.07); border-radius: 9px; padding: 3px; gap: 2px; margin-bottom: 1.25rem; }

        @keyframes fadeUp { from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)} }
        .sv-anim { animation: fadeUp 0.3s ease forwards; }

        /* Footer */
        .sv-footer { text-align: center; margin-top: 1.25rem; font-size: 0.72rem; color: rgba(255,255,255,0.18); letter-spacing: 0.05em; }
        .sv-footer span { color: rgba(0,200,255,0.4); }
      `}</style>

      <div className="sv">
        <div className="sv-grid" />
        <div className="sv-glow1" />
        <div className="sv-glow2" />

        <div className="sv-wrap">
          {/* Header */}
          <div className="sv-head">
            <div className="sv-badge"><div className="sv-badge-dot" /><Icon.Shield />AES-256-GCM Secured</div>
            <h1 className="sv-title">
              <span className="sv-title-main">Secure </span>
              <span className="sv-title-accent">Vault</span>
            </h1>
            <p className="sv-desc">Client-side encryption · Zero server contact · Your keys, your data</p>
          </div>

          <div className="sv-card">
            {/* Nav */}
            <div className="sv-nav">
              <button className={`sv-nav-btn${tab === "file" ? " active" : ""}`} onClick={() => setTab("file")}>
                <Icon.Lock s={13} /> Single File
              </button>
              <button className={`sv-nav-btn${tab === "batch" ? " active" : ""}`} onClick={() => setTab("batch")}>
                <Icon.Layers s={13} /> Batch
              </button>
              <button className={`sv-nav-btn${tab === "notes" ? " active" : ""}`} onClick={() => setTab("notes")}>
                <Icon.Note s={13} /> Enc. Notes
              </button>
              <button className={`sv-nav-btn${tab === "steg" ? " active" : ""}`} onClick={() => setTab("steg")}>
                <Icon.Image s={13} /> Steg
              </button>
            </div>

            <div className="sv-body">
              {/* Shared password */}
              <div className="sv-pw-section">
                <label className="sv-label">Master Password</label>
                <div className="sv-input-row">
                  <input className="sv-input" type={showPw ? "text" : "password"} value={password}
                    onChange={e => setPassword(e.target.value)} placeholder="Enter encryption password…" />
                  <button className="sv-eye" onClick={() => setShowPw(!showPw)}><Icon.Eye open={showPw} s={16} /></button>
                </div>
                {password && (
                  <div className="sv-strength">
                    <div className="sv-strength-bars">
                      {[1,2,3,4,5].map(i => (
                        <div key={i} className="sv-strength-bar"
                          style={{ background: i <= pwStrength.score ? pwStrength.color : undefined }} />
                      ))}
                    </div>
                    <span className="sv-strength-label" style={{ color: pwStrength.color }}>{pwStrength.label}</span>
                  </div>
                )}
              </div>

              {/* ── SINGLE FILE TAB ── */}
              {tab === "file" && (
                <div className="sv-anim">
                  {singleStatus !== "success" && (
                    <>
                      <input ref={singleRef} type="file" style={{ display: "none" }} onChange={handleSingleChange} />
                      <div
                        className={`sv-drop${singleDragging ? " drag" : ""}${singleFile ? " has" : ""}`}
                        onClick={() => singleRef.current?.click()}
                        onDragOver={e => { e.preventDefault(); setSingleDragging(true); }}
                        onDragLeave={() => setSingleDragging(false)}
                        onDrop={handleSingleDrop}
                      >
                        <div className="sv-drop-icon"><Icon.File s={34} /></div>
                        {singleFile ? (
                          <><p className="sv-fname">{singleFile.name}</p><p className="sv-fsize">{formatSize(singleFile.size)} · click to change</p></>
                        ) : (
                          <><p className="sv-drop-main">Drop file here or click to browse</p><p className="sv-drop-sub">Any file type · AES-256-GCM encryption</p></>
                        )}
                      </div>
                      {singleHash && (
                        <div className="sv-hash">
                          <span className="sv-hash-label"><Icon.Hash s={12} />SHA-256</span>
                          <span className="sv-hash-val">{singleHash}</span>
                          <button className="sv-hash-copy" onClick={copyHash} title="Copy hash">
                            {copiedHash ? <Icon.Check s={14} /> : <Icon.Copy s={14} />}
                          </button>
                        </div>
                      )}
                    </>
                  )}

                  {singleStatus === "processing" && (
                    <div className="sv-alert sv-alert-info"><div className="sv-spinner" />Processing with AES-256-GCM…</div>
                  )}
                  {singleStatus === "error" && (
                    <div className="sv-alert sv-alert-error"><Icon.X s={15} />Wrong password or corrupted file.</div>
                  )}
                  {singleStatus === "success" && singleResult && (
                    <div className="sv-anim">
                      <div className="sv-alert sv-alert-success"><Icon.Check s={15} />Operation successful!</div>
                      <div className="sv-result">
                        <div className="sv-result-icon"><Icon.Lock s={26} /></div>
                        <p className="sv-result-title">{singleResult.name}</p>
                        <p className="sv-result-meta">Size: {singleResult.size}</p>
                        {singleHash && <p className="sv-result-meta" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.62rem", marginTop: "0.4rem", wordBreak: "break-all" }}>SHA-256: {singleHash}</p>}
                      </div>
                      <button className="sv-btn sv-btn-green sv-btn-full" onClick={() => downloadBlob(singleResult.blob, singleResult.name)}>
                        <Icon.Download s={15} />Download {singleResult.name}
                      </button>
                      <button className="sv-btn sv-btn-ghost sv-btn-full" onClick={() => { setSingleFile(null); setSingleStatus("idle"); setSingleResult(null); setSingleHash(""); }}>
                        Start over
                      </button>
                    </div>
                  )}

                  {singleStatus !== "success" && (
                    <div className="sv-actions">
                      <button className="sv-btn sv-btn-primary" onClick={handleSingleEncrypt}
                        disabled={!singleFile || !password || singleStatus === "processing"}>
                        <Icon.Lock s={15} />Encrypt
                      </button>
                      <button className="sv-btn sv-btn-ghost" onClick={handleSingleDecrypt}
                        disabled={!singleFile || !password || singleStatus === "processing"}>
                        <Icon.Unlock s={15} />Decrypt
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* ── BATCH TAB ── */}
              {tab === "batch" && (
                <div className="sv-anim">
                  <div className="sv-batch-toggle">
                    <button className={`sv-toggle-btn${batchMode === "encrypt" ? " active" : ""}`} onClick={() => setBatchMode("encrypt")}>
                      🔒 Encrypt All
                    </button>
                    <button className={`sv-toggle-btn${batchMode === "decrypt" ? " active" : ""}`} onClick={() => setBatchMode("decrypt")}>
                      🔓 Decrypt All
                    </button>
                  </div>

                  <input ref={batchRef} type="file" multiple style={{ display: "none" }} onChange={e => e.target.files && addBatchFiles(e.target.files)} />
                  <div
                    className={`sv-drop${batchDragging ? " drag" : ""}`}
                    style={{ marginBottom: batchFiles.length ? "1rem" : "1.25rem" }}
                    onClick={() => batchRef.current?.click()}
                    onDragOver={e => { e.preventDefault(); setBatchDragging(true); }}
                    onDragLeave={() => setBatchDragging(false)}
                    onDrop={handleBatchDrop}
                  >
                    <div className="sv-drop-icon"><Icon.Layers s={30} /></div>
                    <p className="sv-drop-main">Drop multiple files or click to browse</p>
                    <p className="sv-drop-sub">All files processed with the same password</p>
                  </div>

                  {batchFiles.length > 0 && (
                    <>
                      {batchDone > 0 && (
                        <div className="sv-batch-progress">
                          <div className="sv-batch-bar" style={{ width: `${(batchDone / batchTotal) * 100}%` }} />
                        </div>
                      )}
                      <div className="sv-section-header">
                        <span className="sv-section-title">{batchTotal} files · {batchDone} done</span>
                        <button className="sv-btn sv-btn-red sv-btn-sm" onClick={() => setBatchFiles([])}>Clear all</button>
                      </div>
                      <div className="sv-batch-list">
                        {batchFiles.map(item => (
                          <div key={item.id} className={`sv-batch-item ${item.status}`}>
                            <div className="sv-batch-status">
                              {item.status === "processing" ? (
                                <div className="sv-spinner" style={{ width: 12, height: 12 }} />
                              ) : (
                                <div className={`sv-status-dot ${item.status}`} />
                              )}
                            </div>
                            <div className="sv-batch-fname">{item.file.name}</div>
                            <div className="sv-batch-size">{item.size}</div>
                            {item.status === "done" && item.resultBlob && (
                              <button className="sv-btn sv-btn-ghost sv-btn-sm" onClick={() => downloadBatchItem(item)}>
                                <Icon.Download s={12} />
                              </button>
                            )}
                            <button className="sv-note-del" onClick={() => setBatchFiles(prev => prev.filter(f => f.id !== item.id))}>
                              <Icon.X s={13} />
                            </button>
                          </div>
                        ))}
                      </div>
                      <div className="sv-actions">
                        <button className="sv-btn sv-btn-primary" onClick={processBatch}
                          disabled={!password || batchFiles.every(f => f.status === "done")}>
                          <Icon.Lock s={15} />{batchMode === "encrypt" ? "Encrypt All" : "Decrypt All"}
                        </button>
                        <button className="sv-btn sv-btn-green" onClick={downloadAllBatch}
                          disabled={batchDone === 0}>
                          <Icon.Download s={15} />Download All
                        </button>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* ── NOTES TAB ── */}
              {tab === "notes" && (
                <div className="sv-anim">

                  {noteMode === "list" && (
                    <>
                      <div className="sv-section-header">
                        <span className="sv-section-title">{notes.length} encrypted note{notes.length !== 1 ? "s" : ""}</span>
                        <button className="sv-btn sv-btn-primary sv-btn-sm" onClick={createNote}>
                          <Icon.Plus s={14} />New Note
                        </button>
                      </div>

                      {!password && (
                        <div className="sv-alert sv-alert-warn" style={{ marginBottom: "1rem" }}>
                          <Icon.Lock s={14} />Set a master password above to encrypt notes.
                        </div>
                      )}

                      {noteSaveMsg === "saved" && (
                        <div className="sv-alert sv-alert-success" style={{ marginBottom: "1rem" }}>
                          <Icon.Check s={14} />Note saved successfully.
                        </div>
                      )}

                      {notes.length === 0 ? (
                        <div className="sv-note-empty">No notes yet. Create your first encrypted note.</div>
                      ) : (
                        <div className="sv-notes-list">
                          {notes.map(note => (
                            <div key={note.id} className="sv-note-item" onClick={() => viewNote(note)}>
                              <div className="sv-note-icon"><Icon.Note s={16} /></div>
                              <div className="sv-note-body">
                                <div className="sv-note-title">
                                  {note.title}
                                  {note.encrypted && <span className="sv-note-lock">🔒 encrypted</span>}
                                </div>
                                <div className="sv-note-preview">
                                  {note.encrypted ? "••••••••••••••••" : note.content.slice(0, 60)}
                                </div>
                              </div>
                              <button className="sv-note-del" onClick={e => { e.stopPropagation(); deleteNote(note.id); }}>
                                <Icon.Trash s={14} />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}

                  {noteMode === "view" && activeNote && (
                    <div className="sv-anim">
                      <p className="sv-note-view-title">{activeNote.title}</p>
                      <p className="sv-note-view-meta">
                        {new Date(activeNote.createdAt).toLocaleString()}
                        {activeNote.encrypted && " · 🔒 Encrypted"}
                      </p>
                      <div className="sv-note-view-body">{decryptedNoteContent}</div>
                      <div className="sv-note-actions">
                        <button
                          className="sv-btn sv-btn-ghost"
                          style={{ flex: 1 }}
                          onClick={editNote}
                          disabled={activeNote.encrypted && !decryptionOk}
                          title={activeNote.encrypted && !decryptionOk ? "Decrypt successfully before editing" : undefined}
                        >
                          <Icon.Note s={14} />Edit
                        </button>
                        <button
                          className="sv-btn sv-btn-red"
                          style={{ flex: 1 }}
                          onClick={() => { deleteNote(activeNote.id); setNoteMode("list"); }}
                        >
                          <Icon.Trash s={14} />Delete
                        </button>
                        <button className="sv-btn sv-btn-ghost" style={{ flex: 1 }} onClick={() => setNoteMode("list")}>
                          ← Back
                        </button>
                      </div>
                    </div>
                  )}

                  {noteMode === "edit" && (
                    <div className="sv-anim">
                      <div className="sv-divider" style={{ margin: "0 0 1rem" }} />

                      {!password && (
                        <div className="sv-alert sv-alert-warn" style={{ marginBottom: "0.85rem" }}>
                          <Icon.Unlock s={14} />No password set — note will be saved as plaintext.
                        </div>
                      )}

                      <div style={{ marginBottom: "0.85rem" }}>
                        <label className="sv-label">Note Title</label>
                        <input
                          className="sv-input"
                          type="text"
                          value={noteTitle}
                          onChange={e => setNoteTitle(e.target.value)}
                          placeholder="Note title…"
                        />
                      </div>

                      <div style={{ marginBottom: "0.85rem" }}>
                        <label className="sv-label">
                          Content{" "}
                          {password
                            ? <span style={{ color: "#00c8ff" }}>· will be encrypted with AES-256-GCM</span>
                            : <span style={{ color: "#ffb74d" }}>· will be stored as plaintext</span>
                          }
                        </label>
                        <textarea
                          className="sv-textarea"
                          value={noteContent}
                          onChange={e => setNoteContent(e.target.value)}
                          placeholder="Write your note here…"
                        />
                      </div>

                      <div className="sv-note-actions">
                        <button
                          className="sv-btn sv-btn-primary"
                          style={{ flex: 2 }}
                          onClick={() => saveNote(noteTitle, noteContent)}
                          disabled={!noteTitle.trim()}
                        >
                          <Icon.Lock s={14} />{password ? "Save Encrypted" : "Save Note"}
                        </button>
                        <button
                          className="sv-btn sv-btn-ghost"
                          style={{ flex: 1 }}
                          onClick={() => setNoteMode(activeNote ? "view" : "list")}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── STEGANOGRAPHY TAB ── */}
              {tab === "steg" && (
                <div className="sv-anim">

                  <div className="sv-alert sv-alert-purple" style={{ marginBottom: "1.25rem" }}>
                    <Icon.Image s={14} />
                    <span>Hide secret text inside PNG images using <strong>LSB encoding</strong>. Invisible to the naked eye. No password needed (or combine with AES above for double protection).</span>
                  </div>

                  {/* Drop zone */}
                  <input
                    ref={stegRef}
                    type="file"
                    accept="image/*"
                    style={{ display: "none" }}
                    onChange={handleStegFileChange}
                  />
                  <div
                    className={`sv-drop${stegDragging ? " drag" : ""}${stegFile ? " has" : ""}`}
                    onClick={() => stegRef.current?.click()}
                    onDragOver={e => { e.preventDefault(); setStegDragging(true); }}
                    onDragLeave={() => setStegDragging(false)}
                    onDrop={handleStegDrop}
                  >
                    <div className="sv-drop-icon"><Icon.Image s={32} /></div>
                    {stegFile ? (
                      <>
                        <p className="sv-fname">{stegFile.name}</p>
                        <p className="sv-fsize">{formatSize(stegFile.size)} · {stegFile.type || "image"} · click to change</p>
                      </>
                    ) : (
                      <>
                        <p className="sv-drop-main">Drop an image here or click to browse</p>
                        <p className="sv-drop-sub">PNG recommended for hiding · any image for extraction</p>
                      </>
                    )}
                  </div>

                  {/* Image preview */}
                  {stegPreviewUrl && stegFile && (
                    <img
                      src={stegPreviewUrl}
                      alt="Preview"
                      className="sv-steg-preview"
                    />
                  )}

                  {/* Capacity hint */}
                  {stegFile && stegFile.type.startsWith("image/") && (
                    <div className="sv-steg-capacity">
                      <Icon.Image s={13} />
                      <span>
                        Max capacity ≈ <strong style={{ color: "#a78bfa" }}>{Math.floor((stegFile.size / 4) / 8 - 4).toLocaleString()} characters</strong> · Output always saved as PNG to preserve LSB data
                      </span>
                    </div>
                  )}

                  {/* Status */}
                  {stegStatus === "processing" && (
                    <div className="sv-alert sv-alert-info">
                      <div className="sv-spinner" />Processing image pixels…
                    </div>
                  )}
                  {stegStatus === "error" && (
                    <div className="sv-alert sv-alert-error">
                      <Icon.X s={15} />{stegErrorMsg || "Operation failed."}
                    </div>
                  )}

                  {/* ── HIDE section ── */}
                  <div style={{ marginBottom: "0.85rem" }}>
                    <label className="sv-label">
                      Secret Message to Hide
                      {stegMessage && (
                        <span style={{ color: "rgba(167,139,250,0.7)", marginLeft: "8px", fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
                          {stegMessage.length} chars
                        </span>
                      )}
                    </label>
                    <textarea
                      className="sv-textarea"
                      style={{ minHeight: 90 }}
                      value={stegMessage}
                      onChange={e => setStegMessage(e.target.value)}
                      placeholder="Type the secret text you want to embed into the image…"
                    />
                  </div>

                  <button
                    className="sv-btn sv-btn-purple sv-btn-full"
                    onClick={handleStegHide}
                    disabled={!stegFile || !stegMessage.trim() || stegStatus === "processing"}
                  >
                    <Icon.Lock s={15} />Hide Message in Image
                  </button>

                  {stegResult && stegStatus === "success" && (
                    <div className="sv-anim" style={{ marginBottom: "0.5rem" }}>
                      <div className="sv-alert sv-alert-success" style={{ marginBottom: "0.75rem" }}>
                        <Icon.Check s={15} />Message successfully hidden in image!
                      </div>
                      <button
                        className="sv-btn sv-btn-green sv-btn-full"
                        onClick={() => downloadBlob(stegResult.blob, stegResult.name)}
                      >
                        <Icon.Download s={15} />Download {stegResult.name}
                      </button>
                    </div>
                  )}

                  <div className="sv-divider" />

                  {/* ── EXTRACT section ── */}
                  <div className="sv-section-header" style={{ marginBottom: "0.85rem" }}>
                    <span className="sv-section-title">Extract Hidden Message</span>
                  </div>

                  <button
                    className="sv-btn sv-btn-ghost sv-btn-full"
                    onClick={handleStegExtract}
                    disabled={!stegFile || stegStatus === "processing"}
                    style={{ marginBottom: stegExtracted ? "0.85rem" : "0" }}
                  >
                    <Icon.Unlock s={15} />Extract Hidden Message from Image
                  </button>

                  {stegExtracted && stegStatus === "success" && (
                    <div className="sv-anim">
                      <div className="sv-alert sv-alert-success" style={{ marginBottom: "0.75rem" }}>
                        <Icon.Check s={15} />Hidden message found!
                      </div>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                        <label className="sv-label" style={{ margin: 0 }}>Extracted Message</label>
                        <button className="sv-btn sv-btn-ghost sv-btn-sm" onClick={copyStegText}>
                          {copiedSteg ? <><Icon.Check s={12} /> Copied</> : <><Icon.Copy s={12} /> Copy</>}
                        </button>
                      </div>
                      <div className="sv-steg-extracted">{stegExtracted}</div>
                    </div>
                  )}

                  {/* Pro tip */}
                  <div style={{ marginTop: "1.25rem", padding: "0.85rem 1rem", background: "rgba(124,58,237,0.05)", border: "1px solid rgba(124,58,237,0.12)", borderRadius: "9px" }}>
                    <p style={{ fontSize: "0.75rem", color: "rgba(167,139,250,0.6)", lineHeight: 1.6 }}>
                      <strong style={{ color: "rgba(167,139,250,0.85)" }}>💡 Pro tip:</strong> For maximum security, encrypt your message using the <em>Single File</em> tab first, then embed the encrypted output as text here — giving you AES-256-GCM + steganography double protection.
                    </p>
                  </div>

                </div>
              )}

            </div>
          </div>

          <p className="sv-footer">All operations run in your browser · <span>Zero data transmitted</span></p>
        </div>
      </div>
    </>
  );
}
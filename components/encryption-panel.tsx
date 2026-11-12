"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { encryptFile, encryptText, decryptFile } from "@/lib/crypto"
import { AlertCircle, Check, Loader2, Lock, Eye, Download, FileText, File, X } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface EncryptionPanelProps {
  file: File | null
  text: string
  inputType: "file" | "text"
  encryptedData: ArrayBuffer | null
  decryptedData: ArrayBuffer | null
  originalFileName: string
  viewMode: "input" | "encrypted" | "decrypted"
  onEncryptedData: (data: ArrayBuffer) => void
  onDecryptedData: (data: ArrayBuffer, fileName: string) => void
  onViewModeChange: (mode: "input" | "encrypted" | "decrypted") => void
  onReset: () => void
}

export function EncryptionPanel({
  file,
  text,
  inputType,
  encryptedData,
  decryptedData,
  originalFileName,
  viewMode,
  onEncryptedData,
  onDecryptedData,
  onViewModeChange,
  onReset,
}: EncryptionPanelProps) {
  const [password, setPassword] = useState("")
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [mode, setMode] = useState<"encrypt" | "decrypt">("encrypt")

  // Reset password when operation is successful
  useEffect(() => {
    if (success) {
      // Clear password after 2 seconds
      const timer = setTimeout(() => {
        setPassword("")
      }, 2000)

      return () => clearTimeout(timer)
    }
  }, [success])

  const handleEncrypt = async () => {
    if ((!file && !text) || !password) {
      setError("Please provide input and enter a password")
      return
    }

    try {
      setIsProcessing(true)
      setError(null)
      setSuccess(false)
      setMode("encrypt")

      let encryptedData: ArrayBuffer

      if (inputType === "file" && file) {
        encryptedData = await encryptFile(file, password)
      } else if (inputType === "text" && text) {
        encryptedData = await encryptText(text, password)
      } else {
        throw new Error("Invalid input")
      }

      onEncryptedData(encryptedData)
      setSuccess(true)
    } catch (err) {
      setError("Encryption failed: " + (err instanceof Error ? err.message : String(err)))
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDecrypt = async () => {
    if ((!file && !text) || !password) {
      setError("Please provide input and enter a password")
      return
    }

    try {
      setIsProcessing(true)
      setError(null)
      setSuccess(false)
      setMode("decrypt")

      if (inputType === "file" && file) {
        try {
          const result = await decryptFile(file, password)
          onDecryptedData(result.decryptedData, result.originalFileName)
        } catch (err) {
          throw new Error("Decryption failed: Incorrect password or corrupted file")
        }
      } else if (inputType === "text" && text) {
        try {
          // Create a binary array from the text
          const textBytes = []
          for (let i = 0; i < text.length; i++) {
            textBytes.push(text.charCodeAt(i))
          }
          const textData = new Uint8Array(textBytes)
          const textBlob = new Blob([textData])
          const textFile = new File([textBlob], "encrypted.txt")

          const result = await decryptFile(textFile, password)
          onDecryptedData(result.decryptedData, result.originalFileName)
        } catch (err) {
          throw new Error("Decryption failed: Incorrect password or invalid format")
        }
      } else {
        throw new Error("Invalid input")
      }

      setSuccess(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDownload = () => {
    if (!encryptedData && !decryptedData) return

    const dataToDownload = viewMode === "encrypted" ? encryptedData : decryptedData
    const fileName =
      viewMode === "encrypted"
        ? inputType === "file" && file
          ? `${file.name}.encrypted`
          : "encrypted.txt"
        : originalFileName || "decrypted.txt"

    // Create a blob from the data
    const blob = new Blob([dataToDownload as ArrayBuffer], {
      type: viewMode === "encrypted" ? "application/octet-stream" : "application/octet-stream",
    })

    // Create a download link
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = fileName
    document.body.appendChild(a)
    a.click()

    // Clean up
    URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }

  const handleCancel = () => {
    setIsProcessing(false)
    setError(null)
    setSuccess(false)
    setPassword("")
    onReset()
  }

  const renderContent = () => {
    if (viewMode === "input") {
      return (
        <div className="text-center text-cyan-300 p-4">
          {inputType === "file" ? (
            <File className="h-16 w-16 mx-auto mb-2" />
          ) : (
            <FileText className="h-16 w-16 mx-auto mb-2" />
          )}
          <p className="text-lg">
            {inputType === "file"
              ? file
                ? `Ready to process: ${file.name}`
                : "No file selected"
              : text
                ? "Text ready to process"
                : "No text entered"}
          </p>
        </div>
      )
    } else if (viewMode === "encrypted") {
      return (
        <div className="text-center text-cyan-300 p-4">
          <Lock className="h-16 w-16 mx-auto mb-2" />
          <p className="text-lg">Data encrypted successfully</p>
          <p className="text-sm text-cyan-400/70 mt-2">
            {encryptedData ? `Size: ${(encryptedData.byteLength / 1024).toFixed(2)} KB` : ""}
          </p>
        </div>
      )
    } else if (viewMode === "decrypted") {
      if (inputType === "text" && decryptedData) {
        const decoder = new TextDecoder()
        const decryptedText = decoder.decode(decryptedData)
        return (
          <div className="text-cyan-300 p-4">
            <h3 className="text-lg font-medium mb-2">Decrypted Text:</h3>
            <div className="bg-black/40 p-4 rounded border border-cyan-500/30 max-h-40 overflow-auto">
              <pre className="whitespace-pre-wrap break-words text-sm">{decryptedText}</pre>
            </div>
          </div>
        )
      } else {
        return (
          <div className="text-center text-cyan-300 p-4">
            <FileText className="h-16 w-16 mx-auto mb-2" />
            <p className="text-lg">File decrypted successfully</p>
            <p className="text-sm text-cyan-400/70 mt-2">
              {decryptedData ? `Size: ${(decryptedData.byteLength / 1024).toFixed(2)} KB` : ""}
            </p>
            <p className="text-sm text-cyan-400/70">
              {originalFileName ? `Original filename: ${originalFileName}` : ""}
            </p>
          </div>
        )
      }
    }
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="password" className="text-cyan-300">
          Password
        </Label>
        <div className="relative">
          <Input
            id="password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password for encryption/decryption"
            className="bg-black/30 border-cyan-500/50 text-cyan-100 placeholder-cyan-300/50 pr-10"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-0 top-0 h-full text-cyan-400 hover:text-cyan-300 hover:bg-transparent"
            onClick={() => setShowPassword(!showPassword)}
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? (
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="lucide lucide-eye-off"
              >
                <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path>
                <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path>
                <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path>
                <line x1="2" x2="22" y1="2" y2="22"></line>
              </svg>
            ) : (
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="lucide lucide-eye"
              >
                <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            )}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive" className="bg-red-900/30 border-red-500/50 text-red-200">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert className="bg-green-900/30 border-green-500/50 text-green-200">
          <Check className="h-4 w-4" />
          <AlertDescription>
            {mode === "encrypt" ? "Encryption successful!" : "Decryption successful!"}
          </AlertDescription>
        </Alert>
      )}

      <div className="bg-black/40 rounded-lg border border-cyan-500/30 p-4 min-h-[200px] flex items-center justify-center">
        {renderContent()}
      </div>

      <div className="grid grid-cols-4 gap-4">
        <Button
          className="bg-cyan-700 hover:bg-cyan-600 text-white border border-cyan-500/50"
          onClick={handleEncrypt}
          disabled={isProcessing || (!file && !text) || !password}
        >
          {isProcessing && mode === "encrypt" ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Encrypting...
            </>
          ) : (
            <>
              <Lock className="mr-2 h-4 w-4" />
              Encrypt
            </>
          )}
        </Button>

        <Button
          className="bg-cyan-700 hover:bg-cyan-600 text-white border border-cyan-500/50"
          onClick={handleDecrypt}
          disabled={isProcessing || (!file && !text) || !password}
        >
          {isProcessing && mode === "decrypt" ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Decrypting...
            </>
          ) : (
            <>
              <Eye className="mr-2 h-4 w-4" />
              Decrypt
            </>
          )}
        </Button>

        <Button
          className="bg-cyan-700 hover:bg-cyan-600 text-white border border-cyan-500/50"
          onClick={handleDownload}
          disabled={!encryptedData && !decryptedData}
        >
          <Download className="mr-2 h-4 w-4" />
          Download
        </Button>

        <Button className="bg-red-700 hover:bg-red-600 text-white border border-red-500/50" onClick={handleCancel}>
          <X className="mr-2 h-4 w-4" />
          Cancel
        </Button>
      </div>
    </div>
  )
}


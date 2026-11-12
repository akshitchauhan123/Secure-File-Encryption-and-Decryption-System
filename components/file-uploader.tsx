"use client"

import type React from "react"

import { useRef } from "react"
import { Upload } from "lucide-react"

interface FileUploaderProps {
  onFileSelect: (file: File) => void
  label: string
  file: File | null
}

export function FileUploader({ onFileSelect, label, file }: FileUploaderProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      onFileSelect(selectedFile)
    }
  }

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()

    const droppedFile = e.dataTransfer.files?.[0]
    if (droppedFile) {
      onFileSelect(droppedFile)
    }
  }

  return (
    <div className="w-full mb-6">
      {!file ? (
        <div
          className="border-2 border-dashed border-cyan-500/50 rounded-lg p-8 flex flex-col items-center justify-center cursor-pointer hover:border-cyan-400 transition-colors bg-black/30"
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <Upload className="h-12 w-12 text-cyan-400 mb-4" />
          <p className="text-lg text-cyan-100 text-center mb-2">Drag and drop your file here</p>
          <p className="text-sm text-cyan-300/70 text-center">or click to select a file</p>
          <input type="file" className="hidden" ref={fileInputRef} onChange={handleFileChange} />
        </div>
      ) : (
        <div
          className="border border-cyan-500/50 rounded-lg p-4 flex items-center justify-between bg-black/30 cursor-pointer"
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="truncate w-full">
            <p className="text-lg font-medium text-cyan-100">{file.name}</p>
            <p className="text-sm text-cyan-300/70">{(file.size / 1024).toFixed(2)} KB</p>
            <p className="text-xs text-cyan-400/50 mt-1">Click to change file</p>
          </div>
          <input type="file" className="hidden" ref={fileInputRef} onChange={handleFileChange} />
        </div>
      )}
    </div>
  )
}


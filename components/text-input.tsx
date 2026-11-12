"use client"

interface TextInputProps {
  value: string
  onChange: (value: string) => void
}

export function TextInput({ value, onChange }: TextInputProps) {
  return (
    <div className="w-full mb-6">
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Enter text to encrypt or decrypt..."
        className="w-full h-40 p-4 rounded-lg border border-cyan-500/50 bg-black/30 text-cyan-100 placeholder-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 resize-none"
      />
    </div>
  )
}


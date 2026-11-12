export async function encryptFile(file: File, password: string) {
  const fileData = new Uint8Array(await file.arrayBuffer())

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const key = await deriveKey(password, salt)

  // Store the original filename
  const encoder = new TextEncoder()
  const filenameData = encoder.encode(file.name)
  const filenameLength = new Uint8Array([filenameData.length])

  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileData)

  const encryptedBlob = new Uint8Array([
    ...salt,
    ...iv,
    ...filenameLength,
    ...filenameData,
    ...new Uint8Array(encrypted),
  ])

  return encryptedBlob.buffer
}

export async function decryptFile(file: File, password: string) {
  const data = new Uint8Array(await file.arrayBuffer())

  const salt = data.slice(0, 16)
  const iv = data.slice(16, 28)

  // Extract filename
  const filenameLength = data[28]
  const filenameData = data.slice(29, 29 + filenameLength)
  const decoder = new TextDecoder()
  const originalFileName = decoder.decode(filenameData)

  const encrypted = data.slice(29 + filenameLength)

  const key = await deriveKey(password, salt)

  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted)

    return {
      decryptedData: new Uint8Array(decrypted),
      originalFileName: originalFileName || file.name.replace(".encrypted", ""),
    }
  } catch (error) {
    throw new Error("Incorrect password or corrupted file")
  }
}

async function deriveKey(password: string, salt: Uint8Array) {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"])

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

export async function encryptText(text: string, password: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(text)

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const key = await deriveKey(password, salt)

  // Store a marker to identify this as text data
  const filenameData = encoder.encode("text.txt")
  const filenameLength = new Uint8Array([filenameData.length])

  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)

  const encryptedBlob = new Uint8Array([
    ...salt,
    ...iv,
    ...filenameLength,
    ...filenameData,
    ...new Uint8Array(encrypted),
  ])

  return encryptedBlob.buffer
}

export async function decryptText(encryptedText: string, password: string) {
  // Create a binary array from the text
  const textBytes = []
  for (let i = 0; i < encryptedText.length; i++) {
    textBytes.push(encryptedText.charCodeAt(i))
  }
  const data = new Uint8Array(textBytes)

  const salt = data.slice(0, 16)
  const iv = data.slice(16, 28)

  // Extract filename
  const filenameLength = data[28]
  const filenameData = data.slice(29, 29 + filenameLength)
  const decoder = new TextDecoder()
  const originalFileName = decoder.decode(filenameData)

  const encrypted = data.slice(29 + filenameLength)

  const key = await deriveKey(password, salt)

  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted)

    return {
      decryptedData: new Uint8Array(decrypted),
      originalFileName: originalFileName || "decrypted.txt",
    }
  } catch (error) {
    throw new Error("Incorrect password or corrupted data")
  }
}


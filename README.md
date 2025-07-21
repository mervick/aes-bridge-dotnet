# AesBridge .NET

![NuGet Version](https://img.shields.io/nuget/v/AesBridge.svg)
![Build Status](https://github.com/mervick/aes-bridge-dotnet/actions/workflows/dotnet-tests.yml/badge.svg)

**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.

This is the **.NET implementation** of the core project.  
👉 Main repository: https://github.com/mervick/aes-bridge

## Features

- 🔐 **AES-256** encryption in **GCM** (recommended) and **CBC** modes
- 🌍 Unified cross-language design
- 📦 Compact binary format or **Base64** output
- ✅ **HMAC Integrity**: **CBC** mode includes **HMAC** verification
- 🔄 Backward Compatible: Supports legacy **AES Everywhere** format

## Installation

Install the package via NuGet Package Manager Console:

```powershell
Install-Package AesBridge
```

or via .NET CLI:

```bash
dotnet add package AesBridge
```

## Usage

```csharp
using AesBridge;

// AES-GCM (recommended)
string gcmCiphertext = AesBridge.Gcm.Encrypt("My secret data", "MyStrongPass");
byte[] gcmPlaintext = AesBridge.Gcm.Decrypt(gcmCiphertext, "MyStrongPass");

// AES-CBC with HMAC validation
string cbcCiphertext = AesBridge.Cbc.Encrypt("My secret data", "MyStrongPass");
byte[] cbcPlaintext = AesBridge.Cbc.Decrypt(cbcCiphertext, "MyStrongPass");
```

---

## API Reference

All core functions are available through the module `AesBridge` namespase.


### GCM Mode 

**Galois/Counter Mode - AES 256 with Tag**

---

<a name="api-gcm-encrypt"></a>
#### `AesBridge.Gcm.Encrypt (data, passphrase)`

Encrypts data using a given passphrase, returning the encrypted result as a **base64**-encoded string

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `string` - the encrypted data as a **Base64**-encoded string.

---

<a name="api-gcm-encrypt-bin"></a>
#### `AesBridge.Gcm.EncryptBin (data, passphrase)`

Encrypts data using a given passphrase, returning binary encrypted data

**Parameters:**  
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - encrypted data in binary format: `salt + nonce + ciphertext + tag`

---

<a name="api-gcm-decrypt"></a>
#### `AesBridge.Gcm.Decrypt (data, passphrase)`

Decrypts **Base64**-encoded data using a given passphrase

**Parameters:**  
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - decrypted data 

---

<a name="api-gcm-decrypt-bin"></a>
#### `AesBridge.Gcm.DecryptBin (data, passphrase)`

Decrypts binary data using a given passphrase

**Parameters:**
- `data`: `byte[]` - Data to decrypt in binary format: `salt + nonce + ciphertext + tag`
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` – decrypted data in binary form.

---

### CBC Mode 

**Cipher Block Chaining with HMAC Verification - AES 256**

---

<a name="api-cbc-encrypt"></a>
#### `AesBridge.Cbc.Encrypt (data, passphrase)`

Encrypts data using a given passphrase, returning the encrypted result as a **base64**-encoded string

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `string` - the encrypted data as a **Base64**-encoded string.

---

<a name="api-cbc-encrypt-bin"></a>
#### `AesBridge.Cbc.EncryptBin (data, passphrase)`

Encrypts data using a given passphrase, returning binary encrypted data

**Parameters:**  
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - encrypted data in binary format: `salt + nonce + ciphertext + tag`

---

<a name="api-cbc-decrypt"></a>
#### `AesBridge.Cbc.Decrypt (data, passphrase)`

Decrypts **Base64**-encoded data using a given passphrase

**Parameters:**  
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - decrypted data 

---

<a name="api-cbc-decrypt-bin"></a>
#### `AesBridge.Cbc.DecryptBin (data, passphrase)`

Decrypts binary data using a given passphrase

**Parameters:**
- `data`: `byte[]` - Data to decrypt in binary format: `salt + nonce + ciphertext + tag`
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` – decrypted data in binary form.

---

### Legacy mode

⚠️ These functions are maintained solely for compatibility with older systems. While they remain fully compatible with the legacy **AES Everywhere** implementation, their use is strongly discouraged in new applications due to potential security limitations compared to GCM or CBC with HMAC.

---

<a name="api-legacy-encrypt"></a>
#### `AesBridge.Legacy.Encrypt (data, passphrase)`

Encrypts data using a given passphrase.

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt.
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `string` - Encrypted data.

---

<a name="api-legacy-decrypt"></a>
#### `AesBridge.Legacy.Decrypt (data, passphrase)`

Decrypts **string** data using a given passphrase.

**Parameters:**
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `string` - Decrypted data.

---

<a name="api-legacy-decrypt-to-bytes"></a>
#### `AesBridge.Legacy.DecryptToBytes (data, passphrase)`

Decrypts **string** data to a byte array using a given passphrase.

**Parameters:**
- `data`: `string`  or `byte[]`- Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `byte[]` - Decrypted data as a byte array.


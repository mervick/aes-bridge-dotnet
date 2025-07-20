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

Or via .NET CLI:

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

#### `AesBridge.Gcm.Encrypt`

Encrypts data using a given passphrase, returning the encrypted result as a **base64**-encoded string

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `string` - the encrypted data as a **Base64**-encoded string.

**Overloads:**
* `public static string Encrypt(byte[] data, byte[] passphrase)`
* `public static string Encrypt(byte[] data, string passphrase)`
* `public static string Encrypt(string data, byte[] passphrase)`
* `public static string Encrypt(string data, string passphrase)`

---

#### `AesBridge.Gcm.EncryptBin`

Encrypts data using a given passphrase, returning binary encrypted data

**Parameters:**  
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - encrypted data in binary format: `salt + nonce + ciphertext + tag`

**Overloads:**
* `public static byte[] EncryptBin(byte[] data, byte[] passphrase)`
* `public static byte[] EncryptBin(byte[] data, string passphrase)`
* `public static byte[] EncryptBin(string data, byte[] passphrase)`
* `public static byte[] EncryptBin(string data, string passphrase)`

---

#### `AesBridge.Gcm.Decrypt`

Decrypts **Base64**-encoded data using a given passphrase

**Parameters:**  
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - decrypted data 

**Overloads:**
* `public static byte[] Decrypt(byte[] data, byte[] passphrase)`
* `public static byte[] Decrypt(byte[] data, string passphrase)`
* `public static byte[] Decrypt(string data, byte[] passphrase)`
* `public static byte[] Decrypt(string data, string passphrase)`

---

### CBC Mode 

**Cipher Block Chaining with HMAC Verification - AES 256**

---

#### `AesBridge.Cbc.Encrypt`

Encrypts data using a given passphrase, returning the encrypted result as a **base64**-encoded string

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `string` - the encrypted data as a **Base64**-encoded string.

**Overloads:**
* `public static string Encrypt(byte[] data, byte[] passphrase)`
* `public static string Encrypt(byte[] data, string passphrase)`
* `public static string Encrypt(string data, byte[] passphrase)`
* `public static string Encrypt(string data, string passphrase)`

---

#### `AesBridge.Cbc.EncryptBin`

Encrypts data using a given passphrase, returning binary encrypted data

**Parameters:**  
- `data`: `string` or `byte[]` - Data to encrypt
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - encrypted data in binary format: `salt + nonce + ciphertext + tag`

**Overloads:**
* `public static byte[] EncryptBin(byte[] data, byte[] passphrase)`
* `public static byte[] EncryptBin(byte[] data, string passphrase)`
* `public static byte[] EncryptBin(string data, byte[] passphrase)`
* `public static byte[] EncryptBin(string data, string passphrase)`

---

#### `AesBridge.Cbc.Decrypt`

Decrypts **Base64**-encoded data using a given passphrase

**Parameters:**  
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` - decrypted data 

**Overloads:**
* `public static byte[] Decrypt(byte[] data, byte[] passphrase)`
* `public static byte[] Decrypt(byte[] data, string passphrase)`
* `public static byte[] Decrypt(string data, byte[] passphrase)`
* `public static byte[] Decrypt(string data, string passphrase)`

---

#### `AesBridge.Cbc.DecryptBin`

Decrypts binary data using a given passphrase

**Parameters:**
- `data`: `string` or `byte[]` - Data to decrypt in binary format: `salt + nonce + ciphertext + tag`
- `passphrase`: `string` or `byte[]` - Encryption passphrase

**Returns:** `byte[]` – decrypted data in binary form.

**Overloads:**
* `public static byte[] DecryptBin(byte[] data, byte[] passphrase)`
* `public static byte[] DecryptBin(byte[] data, string passphrase)`

---

### Legacy mode

⚠️ These functions are maintained solely for compatibility with older systems. While they remain fully compatible with the legacy **AES Everywhere** implementation, their use is strongly discouraged in new applications due to potential security limitations compared to GCM or CBC with HMAC.

---

#### `AesBridge.Legacy.Encrypt`

Encrypts data using a given passphrase.

**Parameters:**
- `data`: `string` or `byte[]` - Data to encrypt.
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `string` - Encrypted data.

**Overloads:**
* `public static string Encrypt(byte[] data, byte[] passphrase)`
* `public static string Encrypt(byte[] data, string passphrase)`
* `public static string Encrypt(string data, byte[] passphrase)`
* `public static string Encrypt(string data, string passphrase)`
---

#### `AesBridge.Legacy.Decrypt`

Decrypts **string** data using a given passphrase.

**Parameters:**
- `data`: `string` or `byte[]` - Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `string` - Decrypted data.

**Overloads:**
* `public static string Decrypt(byte[] data, byte[] passphrase)`
* `public static string Decrypt(byte[] data, string passphrase)`
* `public static string Decrypt(string data, byte[] passphrase)`
* `public static string Decrypt(string data, string passphrase)`

---

#### `AesBridge.Legacy.DecryptToBytes`

Decrypts **string** data to a byte array using a given passphrase.

**Parameters:**
- `data`: `string`  or `byte[]`- Data to decrypt in **base64**-encoded format
- `passphrase`: `string` or `byte[]` - Encryption passphrase.

**Returns:** `byte[]` - Decrypted data as a byte array.

**Overloads:**
* `public static byte[] DecryptToBytes(byte[] data, byte[] passphrase)`
* `public static byte[] DecryptToBytes(byte[] data, string passphrase)`
* `public static byte[] DecryptToBytes(string data, byte[] passphrase)`
* `public static byte[] DecryptToBytes(string data, string passphrase)`


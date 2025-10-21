
using System.Security.Cryptography;

public class SymmetricEncryption
{
    private const int KeySize = 256; // Розмір ключа в бітах
    private const int NonceSize = 12; // 96 біт, рекомендовано для GCM
    private const int TagSize = 16; // 128 біт
    private const int SaltSize = 16; // 128 біт

    /// <summary>
    ///     Генерує криптографічно стійкий ключ та salt.
    ///     Документація: Ключі генеруються за допомогою RandomNumberGenerator, що є криптографічно стійким
    ///     генератором псевдовипадкових чисел. Для запобігання повторному використанню ключів
    ///     протягом тривалого періоду рекомендується їх періодична ротація (наприклад, кожні 90 днів).
    /// </summary>
    public static (byte[] key, byte[] salt) GenerateKeyAndSalt()
    {
        var key = new byte[KeySize / 8];
        RandomNumberGenerator.Fill(key);

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        return (key, salt);
    }

    /// <summary>
    ///     Шифрування за допомогою AES-GCM.
    /// </summary>
    public static byte[] EncryptAesGcm(byte[] dataToEncrypt, byte[] key)
    {
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var tag = new byte[TagSize];
        var cipherText = new byte[dataToEncrypt.Length];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Encrypt(nonce, dataToEncrypt, cipherText, tag);
        }

        var result = new byte[nonce.Length + tag.Length + cipherText.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherText, 0, result, nonce.Length + tag.Length, cipherText.Length);

        return result;
    }

    /// <summary>
    ///     Дешифрування за допомогою AES-GCM.
    /// </summary>
    public static byte[] DecryptAesGcm(byte[] encryptedData, byte[] key)
    {
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var cipherText = new byte[encryptedData.Length - NonceSize - TagSize];

        Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(encryptedData, nonce.Length, tag, 0, tag.Length);
        Buffer.BlockCopy(encryptedData, nonce.Length + tag.Length, cipherText, 0, cipherText.Length);

        var decryptedData = new byte[cipherText.Length];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Decrypt(nonce, cipherText, tag, decryptedData);
        }

        return decryptedData;
    }

    /// <summary>
    ///     Шифрування AES-CBC з HMAC для контролю цілісності.
    /// </summary>
    public static byte[] EncryptAesCbc(byte[] dataToEncrypt, byte[] key)
    {
        byte[] iv;
        byte[] encrypted;
        using (var aes = Aes.Create())
        {
            aes.KeySize = KeySize;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.GenerateIV();
            iv = aes.IV;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                }

                encrypted = ms.ToArray();
            }
        }

        using (var hmac = new HMACSHA256(key))
        {
            var hmacHash = hmac.ComputeHash(iv
                .Concat(encrypted)
                .ToArray());
            return iv
                .Concat(hmacHash)
                .Concat(encrypted)
                .ToArray();
        }
    }

    /// <summary>
    ///     Дешифрування AES-CBC з перевіркою HMAC.
    /// </summary>
    public static byte[] DecryptAesCbc(byte[] encryptedData, byte[] key)
    {
        using (var hmac = new HMACSHA256(key))
        {
            var iv = encryptedData
                .Take(16)
                .ToArray();
            var hmacHash = encryptedData
                .Skip(16)
                .Take(32)
                .ToArray();
            var encrypted = encryptedData
                .Skip(16 + 32)
                .ToArray();

            var computedHmac = hmac.ComputeHash(iv
                .Concat(encrypted)
                .ToArray());

            if (!hmacHash.SequenceEqual(computedHmac)) throw new CryptographicException();

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(encrypted))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    var decrypted = new byte[encrypted.Length];
                    var bytesRead = cs.Read(decrypted, 0, decrypted.Length);
                    return decrypted
                        .Take(bytesRead)
                        .ToArray();
                }
            }
        }
    }
}
 
using System.Security.Cryptography;

public class AsymmetricEncryption
{
    /// <summary>
    /// Генерує пару ключів RSA (публічний та приватний).
    /// </summary>
    public static (string publicKey, string privateKey) GenerateKeys(int keySize = 2048)
    {
        using (var rsa = RSA.Create(keySize))
        {
            return (rsa.ExportRSAPublicKeyPem(), rsa.ExportRSAPrivateKeyPem());
        }
    }

    /// <summary>
    /// Шифрування даних за допомогою публічного ключа RSA.
    /// </summary>
    public static byte[] Encrypt(byte[] dataToEncrypt, string publicKeyPem)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportFromPem(publicKeyPem);
            return rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
        }
    }

    /// <summary>
    /// Дешифрування даних за допомогою приватного ключа RSA.
    /// </summary>
    public static byte[] Decrypt(byte[] dataToDecrypt, string privateKeyPem)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportFromPem(privateKeyPem);
            return rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
        }
    }

    /// <summary>
    /// Створення цифрового підпису для даних.
    /// </summary>
    public static byte[] SignData(byte[] dataToSign, string privateKeyPem)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportFromPem(privateKeyPem);
            return rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    /// <summary>
    /// Перевірка цифрового підпису.
    /// </summary>
    public static bool VerifySignature(byte[] data, byte[] signature, string publicKeyPem)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportFromPem(publicKeyPem);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
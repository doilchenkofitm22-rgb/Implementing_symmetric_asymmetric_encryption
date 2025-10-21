 
public class HybridEncryption
{
    public static (byte[] encryptedData, byte[] encryptedSymmetricKey) Encrypt(byte[] data, string publicKeyPem)
    {
        // 1. Генеруємо випадковий симетричний ключ AES
        var (symmetricKey, _) = SymmetricEncryption.GenerateKeyAndSalt();

        // 2. Шифруємо дані за допомогою AES-GCM
        var encryptedData = SymmetricEncryption.EncryptAesGcm(data, symmetricKey);

        // 3. Шифруємо симетричний ключ за допомогою публічного ключа RSA
        var encryptedSymmetricKey = AsymmetricEncryption.Encrypt(symmetricKey, publicKeyPem);

        return (encryptedData, encryptedSymmetricKey);
    }

    public static byte[] Decrypt(byte[] encryptedData, byte[] encryptedSymmetricKey, string privateKeyPem)
    {
        // 1. Дешифруємо симетричний ключ за допомогою приватного ключа RSA
        var symmetricKey = AsymmetricEncryption.Decrypt(encryptedSymmetricKey, privateKeyPem);

        // 2. Дешифруємо дані за допомогою симетричного ключа AES-GCM
        var decryptedData = SymmetricEncryption.DecryptAesGcm(encryptedData, symmetricKey);

        return decryptedData;
    }
}
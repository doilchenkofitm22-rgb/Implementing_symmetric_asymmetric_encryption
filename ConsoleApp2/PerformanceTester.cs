
using System.Diagnostics;
using System.Text;

public static class PerformanceTester
{
    public static void RunTests()
    {
        
        var dataSizes = new[] { 1 * 1024, 10 * 1024, 100 * 1024 }; // 1KB, 10KB, 100KB
        var rsaKeySizes = new[] { 2048, 4096 };

        Console.WriteLine("| Розмір даних | Режим AES | Розмір ключа RSA | Час шифрування (мс) | Час розшифрування (мс) |");
        Console.WriteLine("|--------------|-----------|------------------|---------------------|------------------------|");

        foreach (var size in dataSizes)
        {
            var data = new byte[size];
            new Random().NextBytes(data);

           
            var (aesKey, _) = SymmetricEncryption.GenerateKeyAndSalt();
            var stopwatch = Stopwatch.StartNew();
            var encryptedGcm = SymmetricEncryption.EncryptAesGcm(data, aesKey);
            stopwatch.Stop();
            var encryptTimeGcm = stopwatch.Elapsed.TotalMilliseconds;

            stopwatch.Restart();
            SymmetricEncryption.DecryptAesGcm(encryptedGcm, aesKey);
            stopwatch.Stop();
            var decryptTimeGcm = stopwatch.Elapsed.TotalMilliseconds;
            Console.WriteLine($"| {size / 1024,5} KB | AES-GCM   | N/A          | {encryptTimeGcm,17:F4} | {decryptTimeGcm,17:F4} |");

             
            stopwatch.Restart();
            var encryptedCbc = SymmetricEncryption.EncryptAesCbc(data, aesKey);
            stopwatch.Stop();
            var encryptTimeCbc = stopwatch.Elapsed.TotalMilliseconds;

            stopwatch.Restart();
            SymmetricEncryption.DecryptAesCbc(encryptedCbc, aesKey);
            stopwatch.Stop();
            var decryptTimeCbc = stopwatch.Elapsed.TotalMilliseconds;
            Console.WriteLine($"| {size / 1024,5} KB | AES-CBC   | N/A          | {encryptTimeCbc,17:F4} | {decryptTimeCbc,17:F4} |");
        }

        foreach (var rsaKeySize in rsaKeySizes)
        {
            var (publicKey, privateKey) = AsymmetricEncryption.GenerateKeys(rsaKeySize);
            var smallData = Encoding.UTF8.GetBytes("Короткий текст для тесту RSA.");
            
            var stopwatch = Stopwatch.StartNew();
            var encryptedRsa = AsymmetricEncryption.Encrypt(smallData, publicKey);
            stopwatch.Stop();
            var encryptTimeRsa = stopwatch.Elapsed.TotalMilliseconds;

            stopwatch.Restart();
            AsymmetricEncryption.Decrypt(encryptedRsa, privateKey);
            stopwatch.Stop();
            var decryptTimeRsa = stopwatch.Elapsed.TotalMilliseconds;
            Console.WriteLine($"| {smallData.Length,5} B  | RSA-OAEP  | {rsaKeySize,-12} | {encryptTimeRsa,17:F4} | {decryptTimeRsa,17:F4} |");
        }
        Console.WriteLine("---------------------------\n");
    }
}
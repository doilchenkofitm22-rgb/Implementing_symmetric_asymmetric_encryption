using System.Security.Cryptography;
using System.Text;
 

class Program
{
    private static string GetDataPath(string fileName)
    {
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string dataDirectoryPath = Path.Combine(baseDirectory, "Data");
        Directory.CreateDirectory(dataDirectoryPath);
        return Path.Combine(dataDirectoryPath, fileName);
    }

    private static string GetKeyPath(string fileName)
    {
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string keysDirectoryPath = Path.Combine(baseDirectory, "Keys");
        Directory.CreateDirectory(keysDirectoryPath);
        return Path.Combine(keysDirectoryPath, fileName);
    }

    static void Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("\n--- Криптографічне Меню ---");
            Console.WriteLine("--- Симетричне Шифрування (AES-GCM) ---");
            Console.WriteLine(" 1. Зашифрувати за допомогою AES");
            Console.WriteLine(" 2. Розшифрувати за допомогою AES");
            Console.WriteLine("--- Асиметричне Шифрування (RSA) ---");
            Console.WriteLine(" 3. Згенерувати пару ключів RSA");
            Console.WriteLine(" 4. Зашифрувати публічним ключем RSA");
            Console.WriteLine(" 5. Розшифрувати приватним ключем RSA");
            Console.WriteLine(" 6. Створити цифровий підпис");
            Console.WriteLine(" 7. Перевірити цифровий підпис");
            Console.WriteLine("--- Гібридне Шифрування ---");
            Console.WriteLine(" 8. Зашифрувати за гібридною схемою");
            Console.WriteLine(" 9. Розшифрувати за гібридною схемою");
            Console.WriteLine("--- Інше ---");
            Console.WriteLine(" 10. Запустити тести продуктивності");
            Console.WriteLine(" 11. Вийти");
            Console.Write("Оберіть опцію: ");
            var choice = Console.ReadLine();

            try
            {
                switch (choice)
                {
                    case "1": HandleSymmetricEncrypt(); break;
                    case "2": HandleSymmetricDecrypt(); break;
                    case "3": HandleAsymmetricKeyGen(); break;
                    case "4": HandleAsymmetricEncrypt(); break;
                    case "5": HandleAsymmetricDecrypt(); break;
                    case "6": HandleSignData(); break;
                    case "7": HandleVerifySignature(); break;
                    case "8": HandleHybridEncrypt(); break;
                    case "9": HandleHybridDecrypt(); break;
                    case "10": PerformanceTester.RunTests(); break;
                    case "11": return;
                    default: Console.WriteLine("Невірна опція. Спробуйте ще раз."); break;
                }
            }
            catch (FileNotFoundException ex)
            {
                Logger.Log($"ПОМИЛКА: Файл не знайдено. Переконайтеся, що ви спочатку згенерували ключі (Опція 3), якщо це необхідно. Деталі: {ex.Message}");
                Console.WriteLine($"ПОМИЛКА: Файл не знайдено. Переконайтеся, що ви спочатку згенерували ключі (Опція 3), якщо це необхідно.");
            }
            catch (CryptographicException ex)
            {
                Logger.Log($"ПОМИЛКА: Виникла криптографічна помилка. Деталі: {ex.Message}");
                Console.WriteLine("Можливі причини: невірний ключ, пошкоджені дані або невдала перевірка автентифікації.");
            }
            catch (Exception ex)
            {
                Logger.Log($"ФАТАЛЬНА ПОМИЛКА: Виникла непередбачена помилка. Деталі: {ex.Message}");
            }
        }
    }

    private static void HandleSymmetricEncrypt()
    {
        Console.Write("Введіть текст для шифрування: ");
        string text = Console.ReadLine();
        var data = Encoding.UTF8.GetBytes(text);
        var (key, _) = SymmetricEncryption.GenerateKeyAndSalt();
        var encryptedData = SymmetricEncryption.EncryptAesGcm(data, key);
        File.WriteAllBytes(GetDataPath("symmetric_encrypted.dat"), encryptedData);
        File.WriteAllBytes(GetKeyPath("symmetric.key"), key);
        Logger.Log("Симетричне шифрування успішне.");
        Console.WriteLine("Зашифровані дані збережено у 'Data/symmetric_encrypted.dat'");
        Console.WriteLine("Ключ шифрування збережено у 'Keys/symmetric.key'");
    }

    private static void HandleSymmetricDecrypt()
    {
        Console.Write("Введіть назву файлу із зашифрованими даними (за замовчуванням: symmetric_encrypted.dat): ");
        string dataFile = Console.ReadLine();
        if (string.IsNullOrEmpty(dataFile)) dataFile = "symmetric_encrypted.dat";
        Console.Write("Введіть назву файлу з ключем (за замовчуванням: symmetric.key): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "symmetric.key";
        var encryptedData = File.ReadAllBytes(GetDataPath(dataFile));
        var key = File.ReadAllBytes(GetKeyPath(keyFile));
        var decryptedData = SymmetricEncryption.DecryptAesGcm(encryptedData, key);
        Logger.Log("Симетричне розшифрування успішне.");
        Console.WriteLine($"Розшифрований текст: {Encoding.UTF8.GetString(decryptedData)}");
    }

    private static void HandleAsymmetricKeyGen()
    {
        var (publicKey, privateKey) = AsymmetricEncryption.GenerateKeys();
        File.WriteAllText(GetKeyPath("public.pem"), publicKey);
        File.WriteAllText(GetKeyPath("private.pem"), privateKey);
        Logger.Log("Пару ключів RSA згенеровано.");
        Console.WriteLine("Ключі збережено у 'Keys/public.pem' та 'Keys/private.pem'.");
    }

    private static void HandleAsymmetricEncrypt()
    {
        Console.Write("Введіть текст для шифрування: ");
        string text = Console.ReadLine();
        var data = Encoding.UTF8.GetBytes(text);
        Console.Write("Введіть назву файлу публічного ключа (за замовчуванням: public.pem): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "public.pem";
        var publicKey = File.ReadAllText(GetKeyPath(keyFile));
        var encryptedData = AsymmetricEncryption.Encrypt(data, publicKey);
        File.WriteAllBytes(GetDataPath("asymmetric_encrypted.dat"), encryptedData);
        Logger.Log("Асиметричне шифрування успішне.");
        Console.WriteLine("Зашифровані дані збережено у 'Data/asymmetric_encrypted.dat'.");
    }

    private static void HandleAsymmetricDecrypt()
    {
        Console.Write("Введіть назву файлу із зашифрованими даними (за замовчуванням: asymmetric_encrypted.dat): ");
        string dataFile = Console.ReadLine();
        if (string.IsNullOrEmpty(dataFile)) dataFile = "asymmetric_encrypted.dat";
        Console.Write("Введіть назву файлу приватного ключа (за замовчуванням: private.pem): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "private.pem";
        var encryptedData = File.ReadAllBytes(GetDataPath(dataFile));
        var privateKey = File.ReadAllText(GetKeyPath(keyFile));
        var decryptedData = AsymmetricEncryption.Decrypt(encryptedData, privateKey);
        Logger.Log("Асиметричне розшифрування успішне.");
        Console.WriteLine($"Розшифрований текст: {Encoding.UTF8.GetString(decryptedData)}");
    }

    private static void HandleSignData()
    {
        Console.Write("Введіть текст для підпису: ");
        string text = Console.ReadLine();
        var data = Encoding.UTF8.GetBytes(text);
        Console.Write("Введіть назву файлу приватного ключа (за замовчуванням: private.pem): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "private.pem";
        var privateKey = File.ReadAllText(GetKeyPath(keyFile));
        var signature = AsymmetricEncryption.SignData(data, privateKey);
        File.WriteAllBytes(GetDataPath("data.signature"), signature);
        File.WriteAllBytes(GetDataPath("data_to_verify.txt"), data);
        Logger.Log("Підписання даних успішне.");
        Console.WriteLine("Підпис збережено у 'Data/data.signature'.");
        Console.WriteLine("Оригінальні дані збережено у 'Data/data_to_verify.txt'.");
    }
    
    private static void HandleVerifySignature()
    {
        Console.Write("Введіть назву файлу з оригінальними даними (за замовчуванням: data_to_verify.txt): ");
        string dataFile = Console.ReadLine();
        if (string.IsNullOrEmpty(dataFile)) dataFile = "data_to_verify.txt";
        Console.Write("Введіть назву файлу підпису (за замовчуванням: data.signature): ");
        string signatureFile = Console.ReadLine();
        if (string.IsNullOrEmpty(signatureFile)) signatureFile = "data.signature";
        Console.Write("Введіть назву файлу публічного ключа (за замовчуванням: public.pem): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "public.pem";
        var data = File.ReadAllBytes(GetDataPath(dataFile));
        var signature = File.ReadAllBytes(GetDataPath(signatureFile));
        var publicKey = File.ReadAllText(GetKeyPath(keyFile));
        bool isValid = AsymmetricEncryption.VerifySignature(data, signature, publicKey);
        Logger.Log($"Результат перевірки підпису: {isValid}.");
        Console.WriteLine($"Підпис дійсний: {isValid}");
    }

    private static void HandleHybridEncrypt()
    {
        Console.Write("Введіть шлях до файлу для шифрування: ");
        string filePath = Console.ReadLine();
        if (!File.Exists(filePath))
        {
            Console.WriteLine("Файл не знайдено.");
            return;
        }
        var data = File.ReadAllBytes(filePath);
        Console.Write("Введіть назву файлу публічного ключа отримувача (за замовчуванням: public.pem): ");
        string keyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(keyFile)) keyFile = "public.pem";
        var publicKey = File.ReadAllText(GetKeyPath(keyFile));
        var (encryptedData, encryptedKey) = HybridEncryption.Encrypt(data, publicKey);
        string baseFileName = Path.GetFileName(filePath);
        File.WriteAllBytes(GetDataPath($"hybrid_encrypted_{baseFileName}.dat"), encryptedData);
        File.WriteAllBytes(GetKeyPath($"hybrid_encrypted_{baseFileName}.key"), encryptedKey);
        Logger.Log("Гібридне шифрування успішне.");
        Console.WriteLine($"Зашифровані дані збережено у 'Data/hybrid_encrypted_{baseFileName}.dat'.");
        Console.WriteLine($"Зашифрований сеансовий ключ збережено у 'Keys/hybrid_encrypted_{baseFileName}.key'.");
    }

    private static void HandleHybridDecrypt()
    {
        Console.Write("Введіть назву файлу із зашифрованими даними (наприклад, hybrid_encrypted_myfile.txt.dat): ");
        string dataFile = Console.ReadLine();
        Console.Write("Введіть назву файлу із зашифрованим ключем (наприклад, hybrid_encrypted_myfile.txt.key): ");
        string encKeyFile = Console.ReadLine();
        Console.Write("Введіть назву файлу вашого приватного ключа (за замовчуванням: private.pem): ");
        string privateKeyFile = Console.ReadLine();
        if (string.IsNullOrEmpty(privateKeyFile)) privateKeyFile = "private.pem";
        var encryptedData = File.ReadAllBytes(GetDataPath(dataFile));
        var encryptedKey = File.ReadAllBytes(GetKeyPath(encKeyFile));
        var privateKey = File.ReadAllText(GetKeyPath(privateKeyFile));
        var decryptedData = HybridEncryption.Decrypt(encryptedData, encryptedKey, privateKey);
        string outPath = GetDataPath("decrypted_" + dataFile.Replace("hybrid_encrypted_", "").Replace(".dat", ""));
        File.WriteAllBytes(outPath, decryptedData);
        Logger.Log("Гібридне розшифрування успішне.");
        Console.WriteLine($"Розшифровані дані збережено у '{outPath}'.");
    }
}
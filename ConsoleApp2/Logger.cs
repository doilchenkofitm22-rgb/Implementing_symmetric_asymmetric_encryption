 

public static class Logger
{
    private static readonly string logFilePath = "crypto_app.log";

    public static void Log(string message)
    {
        try
        {
            string logMessage = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} | {message}";
            Console.WriteLine(logMessage);  
            File.AppendAllText(logFilePath, logMessage + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Не змогли записати повідомлення: {ex.Message}");
        }
    }
}
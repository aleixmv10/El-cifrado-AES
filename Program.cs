using System.Security.Cryptography;
using System.Text;

namespace CajaFuerte_Apellido1_Apellido2;

internal static class Program
{
    // FORMATO BINARIO DEL FICHERO .caja (en este orden):
    // [0..15]   Sal (16 bytes), usada por PBKDF2-SHA256.
    // [16..27]  Nonce/IV de AES-GCM (12 bytes).
    // [28..43]  Etiqueta de autenticación/tag de AES-GCM (16 bytes).
    // [44..fin] Texto cifrado (mismo número de bytes que el original).
    // La longitud de los tres primeros bloques es fija; el resto es el texto cifrado.
    //
    // Seguridad: AES-256-GCM, clave derivada con PBKDF2-SHA256 y 600.000 iteraciones.
    // La sal y el nonce se generan de nuevo con RandomNumberGenerator para cada cifrado.

    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32; // 32 bytes = 256 bits
    private const int Pbkdf2Iterations = 600_000;
    private const int HeaderSize = SaltSize + NonceSize + TagSize;

    private static int Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("====================================");
            Console.WriteLine("       CAJAFUERTE - AES-256-GCM");
            Console.WriteLine("====================================");
            Console.WriteLine("1. Cifrar un archivo .txt");
            Console.WriteLine("2. Descifrar un archivo .caja");
            Console.WriteLine("0. Salir");
            Console.Write("Elige una opción: ");

            string? option = Console.ReadLine()?.Trim();

            try
            {
                switch (option)
                {
                    case "1":
                        EncryptFile();
                        break;
                    case "2":
                        DecryptFile();
                        break;
                    case "0":
                        return 0;
                    default:
                        Console.WriteLine("Opción no válida.");
                        break;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Error: no tienes permisos para acceder a ese archivo o carpeta.");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Error de entrada/salida: {ex.Message}");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Error criptográfico: no se pudo completar la operación.");
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Dato no válido: {ex.Message}");
            }
        }
    }

    private static void EncryptFile()
    {
        Console.Write("Ruta del archivo .txt que quieres cifrar: ");
        string inputPath = ReadExistingPath();

        if (!Path.GetExtension(inputPath).Equals(".txt", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Solo se pueden cifrar archivos con extensión .txt.");
            return;
        }

        byte[] plaintext = File.ReadAllBytes(inputPath);

        Console.Write("Introduce una contraseña: ");
        string password = ReadPassword();
        if (string.IsNullOrEmpty(password))
        {
            Console.WriteLine("La contraseña no puede estar vacía.");
            return;
        }

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            // Estructura .caja: sal || nonce || tag || texto cifrado.
            byte[] output = new byte[HeaderSize + ciphertext.Length];
            Buffer.BlockCopy(salt, 0, output, 0, SaltSize);
            Buffer.BlockCopy(nonce, 0, output, SaltSize, NonceSize);
            Buffer.BlockCopy(tag, 0, output, SaltSize + NonceSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, output, HeaderSize, ciphertext.Length);

            string outputPath = Path.ChangeExtension(inputPath, ".caja");
            if (File.Exists(outputPath))
            {
                Console.Write($"El archivo '{outputPath}' ya existe. ¿Sobrescribir? (s/n): ");
                if (!IsYes(Console.ReadLine()))
                {
                    Console.WriteLine("Operación cancelada.");
                    return;
                }
            }

            File.WriteAllBytes(outputPath, output);
            Console.WriteLine($"Cifrado correcto. Archivo creado: {outputPath}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void DecryptFile()
    {
        Console.Write("Ruta del archivo .caja que quieres descifrar: ");
        string inputPath = ReadExistingPath();

        if (!Path.GetExtension(inputPath).Equals(".caja", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Solo se pueden descifrar archivos con extensión .caja.");
            return;
        }

        byte[] input = File.ReadAllBytes(inputPath);

        if (input.Length < HeaderSize)
        {
            Console.WriteLine("Archivo inválido o manipulado: no contiene la cabecera completa.");
            return;
        }

        byte[] salt = new byte[SaltSize];
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        int ciphertextLength = input.Length - HeaderSize;
        byte[] ciphertext = new byte[ciphertextLength];
        byte[] plaintext = new byte[ciphertextLength];

        Buffer.BlockCopy(input, 0, salt, 0, SaltSize);
        Buffer.BlockCopy(input, SaltSize, nonce, 0, NonceSize);
        Buffer.BlockCopy(input, SaltSize + NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(input, HeaderSize, ciphertext, 0, ciphertextLength);

        Console.Write("Introduce la contraseña: ");
        string password = ReadPassword();
        if (string.IsNullOrEmpty(password))
        {
            Console.WriteLine("La contraseña no puede estar vacía.");
            return;
        }

        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);

        try
        {
            using var aes = new AesGcm(key, TagSize);

            // Decrypt verifica el tag automáticamente. Si la contraseña es incorrecta
            // o se han alterado los datos, lanza CryptographicException.
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            string outputPath = Path.Combine(
                Path.GetDirectoryName(Path.GetFullPath(inputPath))!,
                Path.GetFileNameWithoutExtension(inputPath) + ".descifrado.txt");

            if (File.Exists(outputPath))
            {
                Console.Write($"El archivo '{outputPath}' ya existe. ¿Sobrescribir? (s/n): ");
                if (!IsYes(Console.ReadLine()))
                {
                    Console.WriteLine("Operación cancelada.");
                    return;
                }
            }

            File.WriteAllBytes(outputPath, plaintext);
            Console.WriteLine($"Descifrado correcto. Archivo creado: {outputPath}");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("DESCIFRADO RECHAZADO: contraseña incorrecta o archivo manipulado/dañado.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static string ReadExistingPath()
    {
        string? path = Console.ReadLine()?.Trim().Trim('"');

        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("La ruta no puede estar vacía.");

        if (!File.Exists(path))
            throw new FileNotFoundException("No se encuentra el archivo indicado.", path);

        return Path.GetFullPath(path);
    }

    private static string ReadPassword()
    {
        var password = new StringBuilder();

        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return password.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                    password.Length--;
                continue;
            }

            if (!char.IsControl(key.KeyChar))
                password.Append(key.KeyChar);
        }
    }

    private static bool IsYes(string? answer) =>
        answer?.Trim().Equals("s", StringComparison.OrdinalIgnoreCase) == true ||
        answer?.Trim().Equals("si", StringComparison.OrdinalIgnoreCase) == true ||
        answer?.Trim().Equals("sí", StringComparison.OrdinalIgnoreCase) == true;
}

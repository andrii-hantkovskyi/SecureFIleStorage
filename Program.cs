using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SecureFileManager
{
    public static class Constants
    {
        private static readonly string BaseDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\"));
        
        private static readonly string DataDir = Path.Combine(BaseDir, "Data");

        public static readonly string KeyFilePath = Path.Combine(BaseDir, "encryption.key");
        public static readonly string IvFilePath = Path.Combine(BaseDir, "encryption.iv");
        public static readonly string UsersFilePath = Path.Combine(DataDir, "users.json");
        public static readonly string FilesFolder = Path.Combine(DataDir, "files");
    }

    public abstract class FileEncryption
    {
        public static byte[] GenerateEncryptionKey()
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                var key = aesAlg.Key;
                WriteKeyToFile(key);
                return key;
            }
        }

        public static byte[] GenerateIv()
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.GenerateIV();
                var iv = aesAlg.IV;
                WriteIvToFile(iv);
                return iv;
            }
        }

        private static void WriteKeyToFile(byte[] key)
        {
            File.WriteAllBytes(Constants.KeyFilePath, key);
        }

        private static void WriteIvToFile(byte[] iv)
        {
            File.WriteAllBytes(Constants.IvFilePath, iv);
        }

        private static byte[] ReadKeyFromFile()
        {
            return File.ReadAllBytes(Constants.KeyFilePath);
        }

        private static byte[] ReadIvFromFile()
        {
            return File.ReadAllBytes(Constants.IvFilePath);
        }

        public static byte[] Encrypt(string content)
        {
            var key = ReadKeyFromFile();
            var iv = ReadIvFromFile();

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                var encryptor = aesAlg.CreateEncryptor();

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(content);
                        }

                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        public static string Decrypt(byte[] content)
        {
            var key = ReadKeyFromFile();
            var iv = ReadIvFromFile();

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor();

                using (var msDecrypt = new MemoryStream(content))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }

    public abstract class SecureFileManager
    {
        public static void CreateFile(User user, string filePath)
        {
            if (user == null)
            {
                Console.WriteLine("User not authenticated.");
                return;
            }

            var userFolderPath = Path.Combine(Constants.FilesFolder, user.Username);
            Directory.CreateDirectory(userFolderPath);

            var rawContent = File.ReadAllText(filePath);

            var encryptedContent = FileEncryption.Encrypt(rawContent);

            var encryptedFilePath = Path.Combine(userFolderPath,
                $"{filePath.Split(Path.DirectorySeparatorChar).Last()}.encrypted");
            File.WriteAllBytes(encryptedFilePath, encryptedContent);

            Console.WriteLine("File created successfully.");
        }

        public static void ViewFiles(User user)
        {
            if (user == null)
            {
                Console.WriteLine("User not authenticated.");
                return;
            }

            var userFolderPath = Path.Combine(Constants.FilesFolder, user.Username);
            if (!Directory.Exists(userFolderPath))
            {
                Console.WriteLine($"No files found for user '{user.Username}'.");
                return;
            }

            Console.WriteLine($"Files for user '{user.Username}':");
            var files = Directory.GetFiles(userFolderPath);
            foreach (var file in files) Console.WriteLine(Path.GetFileName(file));
        }

        public static void ViewFile(User user, string fileName)
        {
            if (user == null)
            {
                Console.WriteLine("User not authenticated.");
                return;
            }

            var userFilePath = Path.Combine(Path.Combine(Constants.FilesFolder, user.Username), fileName);
            if (!File.Exists(userFilePath))
            {
                Console.WriteLine("File not found.");
                return;
            }

            var encryptedContent = File.ReadAllBytes(userFilePath);

            var decryptedContent = FileEncryption.Decrypt(encryptedContent);

            Console.WriteLine(decryptedContent);
        }

        public static void DeleteFile(User user, string fileName)
        {
            if (user == null)
            {
                Console.WriteLine("User not authenticated.");
                return;
            }

            var userFilePath = Path.Combine(Path.Combine(Constants.FilesFolder, user.Username), fileName);
            if (!File.Exists(userFilePath))
            {
                Console.WriteLine("File not found.");
                return;
            }

            File.Delete(userFilePath);
            Console.WriteLine("File deleted successfully.");
        }
    }


    internal abstract class Program
    {
        private static void Main()
        {
            var looping = true;
            
            var userAuthenticator = new UserAuthenticator();
            User currentUser = null;

            while (looping)
            {
                Console.WriteLine(
                    "1. Register\n2. Authenticate\n3. Create File\n4. View All Files\n5. View File\n6. Delete File\n7. Exit");
                Console.Write("Select an option: ");
                var option = Console.ReadLine();

                switch (option)
                {
                    case "3":
                        if (currentUser == null)
                        {
                            Console.WriteLine("Please authenticate first.");
                            break;
                        }

                        Console.Write("Enter file path: ");
                        var filePath = Console.ReadLine();
                        SecureFileManager.CreateFile(currentUser, filePath);

                        break;
                    case "4":
                        if (currentUser != null)
                            SecureFileManager.ViewFiles(currentUser);
                        else
                            Console.WriteLine("Please authenticate first.");

                        break;
                    case "5":
                        if (currentUser == null)
                        {
                            Console.WriteLine("Please authenticate first.");
                            break;
                        }

                        Console.Write("Enter file name to view: ");
                        var viewFileName = Console.ReadLine();
                        SecureFileManager.ViewFile(currentUser, viewFileName);

                        break;
                    case "6":
                        if (currentUser == null)
                        {
                            Console.WriteLine("Please authenticate first.");
                            break;
                        }

                        Console.Write("Enter file name to delete: ");
                        var deleteFileName = Console.ReadLine();
                        SecureFileManager.DeleteFile(currentUser, deleteFileName);

                        break;
                    case "7":
                        looping = false;
                        break;
                    default:
                        Console.WriteLine("Invalid option.");
                        break;
                }
            }
        }
    }
}
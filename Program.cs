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

    public class User
    {
        public string Username { get; }

        public string Password { get; }

        public User(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public static string EncryptPassword(string password)
        {
            using (var md5 = MD5.Create())
            {
                var inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
                var hashBytes = md5.ComputeHash(inputBytes);

                return Convert.ToBase64String(hashBytes);
            }
        }
    }

    public class UserAuthenticator
    {
        private readonly List<User> _users;

        public UserAuthenticator()
        {
            if (!File.Exists(Constants.UsersFilePath))
            {
                _users = new List<User>();
                return;
            }

            var json = File.ReadAllText(Constants.UsersFilePath);
            _users = JsonConvert.DeserializeObject<List<User>>(json);
        }
        public static bool CheckPasswordComplexity(string password)
        {
            if (password.Length < 8 ||
                !password.Any(char.IsUpper) ||
                !password.Any(char.IsLower) ||
                !password.Any(char.IsDigit) ||
                password.All(char.IsLetterOrDigit))
            {
                return false;
            }

            return true;
        }

        public void RegisterUser(string username, string password)
        {
            if (_users.Find(u => u.Username == username) != null)
            {
                Console.WriteLine("Username already exists.");
                return;
            }
            if (UserAuthenticator.CheckPasswordComplexity(password) == true)
            {
                _users.Add(new User(username, User.EncryptPassword(password)));
                SaveUsersToFile();
                Console.WriteLine("User registered successfully.");
            }
            else Console.WriteLine("Password just simple");
        }

        public User AuthenticateUser(string username, string password)
        {
            var user = _users.Find(u => u.Username == username);
            if (user != null && user.Password == new User(username, User.EncryptPassword(password)).Password)
            {
                Console.WriteLine("Authentication successful.");
                return user;
            }

            Console.WriteLine("Authentication failed.");
            return null;
        }

        private void SaveUsersToFile()
        {
            var json = JsonConvert.SerializeObject(_users);
            File.WriteAllText(Constants.UsersFilePath, json);
        }
    }

    public abstract class FileEncryption
    {
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
                    case "1":
                        Console.Write("Enter username: ");
                        var regUsername = Console.ReadLine();
                        Console.Write("Enter password: ");
                        var regPassword = Console.ReadLine();
                        userAuthenticator.RegisterUser(regUsername, regPassword);
                        break;
                    case "2":
                        Console.Write("Enter username: ");
                        var authUsername = Console.ReadLine();
                        Console.Write("Enter password: ");
                        var authPassword = Console.ReadLine();
                        currentUser = userAuthenticator.AuthenticateUser(authUsername, authPassword);
                        break;
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
using Laboratory_2_Zash_Inf.Classes;

Console.WriteLine("Введите свою фамилию: ");
string surname = Console.ReadLine()?.Trim() ?? string.Empty;
string key = "3214";

string encrypted = Encryptor.PermutationCipher(surname, key);
Console.WriteLine("\nПростая одинарная перестановка. Шифрация: " + encrypted);
string decrypted = Encryptor.PermutationDecipher(encrypted, key);
Console.WriteLine("Простая одинарная перестановка. Расшифровка: " + decrypted);

int blockSize = 3;
int[] permutation = [2, 3, 1];

encrypted = Encryptor.BlockPermutationCipher(surname, blockSize, permutation);
Console.WriteLine("\nБлочная одинарная перестановка. Шифрация: " + encrypted);
decrypted = Encryptor.BlockPermutationDecipher(encrypted, blockSize, permutation);
Console.WriteLine("Блочная одинарная перестановка. Расшифровка: " + decrypted);

Console.WriteLine("\nВведите своё имя: ");
string name = Console.ReadLine()?.Trim() ?? string.Empty;

key = "231";

string encryptedName = Encryptor.RoutePermutationCipher(name, key);
string encryptedSurname = Encryptor.RoutePermutationCipher(surname, key);
Console.WriteLine("\nТабличная маршрутная перестановка. Шифрация: " + encryptedSurname + " " + encryptedName);

string decryptedName = Encryptor.RoutePermutationDecipher(encryptedName, key);
string decryptedSurname = Encryptor.RoutePermutationDecipher(encryptedSurname, key);
Console.WriteLine("Табличная маршрутная перестановка. Расшифровка: " + decryptedSurname + " " + decryptedName);

encryptedName = Encryptor.VerticalCipher(name, key);
encryptedSurname = Encryptor.VerticalCipher(surname, key);
Console.WriteLine("\nШифр вертикальной перестановка. Шифрация: " + encryptedSurname + " " + encryptedName);

decryptedName = Encryptor.VerticalDecipher(encryptedName, key);
decryptedSurname = Encryptor.VerticalDecipher(encryptedSurname, key);
Console.WriteLine("Шифр вертикальной перестановка. Расшифровка: " + decryptedSurname + " " + decryptedName);

List<List<bool>> template =
[
    [true, false, true, false],
    [false, false, false, false],
    [false, true, false, true],
    [false, false, false, false]
];

encryptedName = Encryptor.RotorSquareCipher(name, template);
encryptedSurname = Encryptor.RotorSquareCipher(surname, template);
Console.WriteLine("\nШифр поворотной решетки. Шифрация: " + encryptedSurname + " " + encryptedName);

decryptedName = Encryptor.RotorSquareDecipher(encryptedName, template);
decryptedSurname = Encryptor.RotorSquareDecipher(encryptedSurname, template);
Console.WriteLine("Шифр поворотной решетки. Расшифровка: " + decryptedSurname + " " + decryptedName);

int[,] square = {
    {16, 3, 2, 13},
    {5, 10, 11, 8},
    {9, 6, 7, 12},
    {4, 15, 14, 1}
};

encryptedName = Encryptor.MagicSquareCipher(name, square);
encryptedSurname = Encryptor.MagicSquareCipher(surname, square);
Console.WriteLine("\nШифр магическим квадратом. Шифрация: " + encryptedSurname + " " + encryptedName);

decryptedName = Encryptor.MagicSquareDecipher(encryptedName, square);
decryptedSurname = Encryptor.MagicSquareDecipher(encryptedSurname, square);
Console.WriteLine("Шифр магическим квадратом. Расшифровка: " + decryptedSurname + " " + decryptedName);

string keyFirst = "qwertyuiopasdfghjklzxcvbnm";
string keySecond = "mnbvcxzlkjhgfdsapoiuytrewq";

encryptedName = Encryptor.DoublePermutationCipher(name, keyFirst, keySecond);
encryptedSurname = Encryptor.DoublePermutationCipher(surname, keyFirst, keySecond);
Console.WriteLine("\nШифр двойной перестановки. Шифрация: " + encryptedSurname + " " + encryptedName);

decryptedName = Encryptor.DoublePermutationDecipher(encryptedName, keyFirst, keySecond);
decryptedSurname = Encryptor.DoublePermutationDecipher(encryptedSurname, keyFirst, keySecond);
Console.WriteLine("Шифр двойной перестановки. Расшифровка: " + decryptedSurname + " " + decryptedName);

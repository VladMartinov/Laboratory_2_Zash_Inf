using System;
using System.Data.Common;
using System.Drawing;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace Laboratory_2_Zash_Inf.Classes
{
    internal class Encryptor
    {
        #region - Вспомогательные функции -
        private static void RotateSquare(List<List<bool>> list, int index)
        {
            switch (index)
            {
                case 1:
                    for (int j = 0; j < list.Count; j++)
                    {
                        for (int k = 0; k < list.Count / 2; k++)
                        {
                            (list[j][list.Count - 1 - k], list[j][k]) = (list[j][k], list[j][list.Count - 1 - k]);
                        }
                    }
                    break;
                case 2:
                    for (int k = 0; k < list.Count; k++)
                    {
                        for (int j = 0; j < list.Count / 2; j++)
                        {
                            (list[list.Count - 1 - j][k], list[j][k]) = (list[j][k], list[list.Count - 1 - j][k]);
                        }
                    }
                    break;
                case 3:
                    for (int j = 0; j < list.Count; j++)
                    {
                        for (int k = 0; k < list.Count / 2; k++)
                        {
                            (list[j][list.Count - 1 - k], list[j][k]) = (list[j][k], list[j][list.Count - 1 - k]);
                        }
                    }
                    break;
            }
        }
        
        #endregion

        #region - Шифраторы -
        public static string PermutationCipher(string input, string key)
        {
            int keyLength = key.Length;
            int[] permutationOrder = new int[keyLength];

            // Определяем порядок перестановки на основе ключа
            for (int i = 0; i < keyLength; i++)
            {
                permutationOrder[i] = Convert.ToInt32(key[i].ToString()) - 1;
            }

            // Вычисляем длину дополненной строки
            int len = (int)Math.Ceiling((double)input.Length / keyLength) * keyLength;
            char[] paddedInput = input.PadRight(len, ' ').ToCharArray();
            char[] encrypted = new char[len];

            // Применяем перестановку
            for (int i = 0; i < len / keyLength; i++)
            {
                for (int j = 0; j < keyLength; j++)
                {
                    encrypted[i * keyLength + j] = paddedInput[i * keyLength + permutationOrder[j]];
                }
            }

            return new string(encrypted).TrimEnd(); // Удаляем лишние пробелы в конце
        }

        public static string BlockPermutationCipher(string input, int blockSize, int[] permutation)
        {
            if (permutation.Length != blockSize)
            {
                throw new ArgumentException("Длина массива перестановок должна совпадать с размером блока.");
            }

            // Дополнение исходного сообщения
            int paddingLength = (blockSize - (input.Length % blockSize)) % blockSize;
            string paddedInput = input.PadRight(input.Length + paddingLength, ' ');


            char[] encrypted = new char[paddedInput.Length];
            for (int i = 0; i < paddedInput.Length; i += blockSize)
            {
                string block = paddedInput.Substring(i, blockSize);
                char[] permutedBlock = new char[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    permutedBlock[j] = block[permutation[j] - 1]; // Индексы в permutation начинаются с 1
                }
                permutedBlock.CopyTo(encrypted, i);
            }

            return new string(encrypted);
        }

        public static string RoutePermutationCipher(string input, string key)
        {
            // Определяем размер таблицы
            int keyLength = key.Length;
            int rows = (int)Math.Ceiling((double)input.Length / key.Length);
            char[,] table = new char[rows, keyLength];

            // Заполняем таблицу символами входной строки
            for (int i = 0; i < input.Length; i++)
            {
                table[i / keyLength, i % keyLength] = input[i];
            }

            // Чтение символов в соответствии с порядком, указанным в ключе
            char[] encryptedArray = new char[input.Length];
            int index = 0;

            // Преобразуем ключ в массив индексов
            int[] order = new int[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                order[i] = int.Parse(key[i].ToString()) - 1; // Преобразуем символ ключа в индекс
            }

            // Чтение из таблицы по порядку ключа
            for (int i = 0; i < keyLength; i++)
            {
                int column = order[i];
                for (int j = 0; j < rows; j++)
                {
                    if (table[j, column] != '\0') // Проверяем на заполненность
                    {
                        encryptedArray[index++] = table[j, column];
                    }
                }
            }
            return new string(encryptedArray).TrimEnd('\0'); // Убираем лишние символы
        }

        public static string VerticalCipher(string input, string key)
        {
            int keyLength = key.Length;
            int numCols = keyLength;
            int numRows = (int)Math.Ceiling((double)input.Length / numCols);

            char[,] matrix = new char[numRows, numCols];
            int k = 0;
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    if (k < input.Length)
                    {
                        matrix[i, j] = input[k++];
                    }
                    else
                    {
                        matrix[i, j] = '\0'; // Padding with null characters
                    }
                }
            }

            int[] keyOrder = new int[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                keyOrder[i] = int.Parse(key[i].ToString()) - 1; //Adjusting for 0-based array index
            }


            var ciphertext = new StringBuilder();
            for (int j = 0; j < numCols; j++)
            {
                int colIndex = Array.IndexOf(keyOrder, j);
                for (int i = 0; i < numRows; i++)
                {
                    if (matrix[i, colIndex] != '\0')
                    {
                        ciphertext.Append(matrix[i, colIndex]);
                    }
                }
            }

            return ciphertext.ToString();
        }

        public static string RotorSquareCipher(string input, List<List<bool>> template)
        {
            if (template.Count % 2 != 0) throw new ArgumentException("Размер трафарета должен быть четным.");
            
            var newTemplate = new List<List<bool>>(template.Count);
            foreach (var row in template)
                newTemplate.Add(new List<bool>(row));

            string result = string.Empty;
            char[,] cipherMatrix = new char[newTemplate.Count, newTemplate.Count];

            for (int i = 0, z = 0; i < 4; i++)
            {
                for (int j = 0; j < newTemplate.Count; j++)
                {
                    for (int k = 0; k < newTemplate.Count; k++)
                    {
                        if (newTemplate[j][k])
                        {
                            if (z < input.Length)
                            {
                                cipherMatrix[j, k] = input[z];
                                z++;
                            }
                            else
                            {
                                cipherMatrix[j, k] = '_';
                            }
                        }
                    }
                }

                RotateSquare(newTemplate, i + 1);
            }

            for (int j = 0; j < newTemplate.Count; j++)
            {
                for (int i = 0; i < newTemplate.Count; i++)
                {
                    result += cipherMatrix[i, j];
                }
            }

            return result;
        }

        public static string MagicSquareCipher(string input, int[,] square)
        {
            var encryptedText = new List<char>();

            for (int i = 0; i < square.GetLength(0); i++)
            {
                for (int j = 0; j < square.GetLength(1); j++)
                {
                    int num = square[i, j] - 1;

                    if (num < input.Length)
                        encryptedText.Add(input[num]);
                    else
                        encryptedText.Add('.');
                }
            }

            return new string(encryptedText.ToArray());
        }

        public static string DoublePermutationCipher(string input, string substFirst, string substSecond)
        {
            var result = new StringBuilder();

            // Первое шифрование
            foreach (char c in input)
            {
                if (char.IsLetter(c))
                {
                    char lowerChar = char.ToLower(c);
                    int index = lowerChar - 'a';
                    result.Append(char.IsUpper(c) ? char.ToUpper(substFirst[index]) : substFirst[index]);
                }
                else
                {
                    result.Append(c);
                }
            }

            string firstSubstitution = result.ToString();
            result.Clear();

            // Второе шифрование
            foreach (char c in firstSubstitution)
            {
                if (char.IsLetter(c))
                {
                    char lowerChar = char.ToLower(c);
                    int index = lowerChar - 'a';
                    result.Append(char.IsUpper(c) ? char.ToUpper(substSecond[index]) : substSecond[index]);
                }
                else
                {
                    result.Append(c);
                }
            }

            return result.ToString();
        }
        #endregion

        #region - Дешифраторы -
        public static string PermutationDecipher(string input, string key)
        {
            int keyLength = key.Length;
            int[] permutationOrder = new int[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                permutationOrder[i] = Convert.ToInt32(key[i].ToString()) - 1;
            }

            int len = input.Length;
            char[] encrypted = input.ToCharArray();
            char[] decrypted = new char[len];

            for (int i = 0; i < len / keyLength; i++)
            {
                for (int j = 0; j < keyLength; j++)
                {
                    decrypted[i * keyLength + permutationOrder[j]] = encrypted[i * keyLength + j];
                }
            }
            return new string(decrypted).TrimEnd();
        }

        public static string BlockPermutationDecipher(string input, int blockSize, int[] permutation)
        {
            if (permutation.Length != blockSize)
            {
                throw new ArgumentException("Длина массива перестановок должна совпадать с размером блока.");
            }

            char[] decrypted = new char[input.Length];
            for (int i = 0; i < input.Length; i += blockSize)
            {
                string block = input.Substring(i, blockSize);
                char[] permutedBlock = new char[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    permutedBlock[permutation[j] - 1] = block[j]; // обратная перестановка
                }
                permutedBlock.CopyTo(decrypted, i);
            }

            return new string(decrypted).TrimEnd(); // Удаляем завершающие пробелы
        }

        public static string RoutePermutationDecipher(string input, string key)
        {
            // Определяем размер таблицы
            int keyLength = key.Length;
            int rows = (int)Math.Ceiling((double)input.Length / key.Length);
            char[,] table = new char[rows, keyLength];

            // Чтение символов в соответствии с порядком, указанным в ключе
            int index = input.Length - 1;

            // Преобразуем ключ в массив индексов
            int[] order = new int[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                order[i] = int.Parse(key[i].ToString()) - 1; // Преобразуем символ ключа в индекс
            }

            // Чтение из таблицы по порядку ключа
            for (int i = keyLength - 1; i >= 0; i--)
            {
                int column = order[i];
                for (int j = rows - 1; j >= 0; j--)
                {
                    if (table[j, column] == '\0' && j * keyLength + column <= input.Length - 1) // Проверяем на заполненность
                    {
                        table[j, column] = input[index--];
                    }
                }
            }

            char[] charArray = new char[table.GetLength(0) * table.GetLength(1)];
            index = 0;

            for (int i = 0; i < table.GetLength(0); i++)
            {
                for (int j = 0; j < table.GetLength(1); j++)
                {
                    charArray[index++] = table[i, j];
                }
            }

            return new string(charArray);
        }

        public static string VerticalDecipher(string input, string key)
        {
            int keyLength = key.Length;
            int numCols = keyLength;
            int numRows = (int)Math.Ceiling((double)input.Length / numCols);

            char[,] matrix = new char[numRows, numCols];
            int[] keyOrder = new int[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                keyOrder[i] = int.Parse(key[i].ToString()) - 1; //Adjusting for 0-based array index

            }
            int k = 0;
            for (int j = 0; j < numCols; j++)
            {
                int colIndex = Array.IndexOf(keyOrder, j);
                for (int i = 0; i < numRows; i++)
                {
                    if (k < input.Length && i * keyLength + colIndex <= input.Length - 1)
                    {
                        matrix[i, colIndex] = input[k++];
                    }

                }
            }

            var plaintext = new StringBuilder();
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    if (matrix[i, j] != '\0')
                    {
                        plaintext.Append(matrix[i, j]);
                    }
                }
            }

            return plaintext.ToString();
        }
        
        public static string RotorSquareDecipher(string input, List<List<bool>> template)
        {
            if (template.Count % 2 != 0) throw new ArgumentException("Размер трафарета должен быть четным.");

            var newTemplate = new List<List<bool>>(template.Count);
            foreach (var row in template)
                newTemplate.Add(new List<bool>(row));

            string result = string.Empty;
            char[,] cipherMatrix = new char[newTemplate.Count, newTemplate.Count];

            for (int i = 0; i < 4; i++)
                RotateSquare(newTemplate, i + 1);

            for (int j = newTemplate.Count - 1, z = input.Length - 1; j >= 0 && z >= 0; j--)
            {
                for (int i = newTemplate.Count - 1; i >= 0; i--, z--)
                {
                    cipherMatrix[i, j] = input[z];
                }
            }

            for (int i = 3; i >= 0; i--)
            {
                for (int j = newTemplate.Count - 1; j >= 0; j--)
                {
                    for (int k = newTemplate.Count - 1; k >= 0; k--)
                    {
                        if (newTemplate[j][k] && cipherMatrix[j, k] != '_')
                        {
                            result = cipherMatrix[j, k] + result;
                        }
                    }
                }

                RotateSquare(newTemplate, i);
            }

            return result;
        }

        public static string MagicSquareDecipher(string input, int[,] square)
        {
            var encryptedText = new char[input.Length];

            for (int i = 0; i < square.GetLength(0); i++)
            {
                for (int j = 0; j < square.GetLength(1); j++)
                {
                    int num = square[i, j] - 1;

                    if (input[i * square.GetLength(0) + j] != '.')
                        encryptedText[num] = input[i * square.GetLength(0) + j];
                }
            }

            return new string(encryptedText);
        }

        public static string DoublePermutationDecipher(string input, string substFirst, string substSecond)
        {
            var result = new StringBuilder();

            // Обратное второе шифрование
            foreach (char c in input)
            {
                if (char.IsLetter(c))
                {
                    char lowerChar = char.ToLower(c);
                    int index = substSecond.IndexOf(lowerChar);
                    if (index != -1)
                    {
                        result.Append(char.IsUpper(c) ? char.ToUpper((char)('a' + index)) : (char)('a' + index));
                    }
                    else
                    {
                        result.Append(c);
                    }
                }
                else
                {
                    result.Append(c);
                }
            }

            string secondDecryption = result.ToString();
            result.Clear();

            // Обратное первое шифрование
            foreach (char c in secondDecryption)
            {
                if (char.IsLetter(c))
                {
                    char lowerChar = char.ToLower(c);
                    int index = substFirst.IndexOf(lowerChar);
                    if (index != -1)
                    {
                        result.Append(char.IsUpper(c) ? char.ToUpper((char)('a' + index)) : (char)('a' + index));
                    }
                    else
                    {
                        result.Append(c);
                    }

                }
                else
                {
                    result.Append(c);
                }
            }

            return result.ToString();
        }
        #endregion
    }
}

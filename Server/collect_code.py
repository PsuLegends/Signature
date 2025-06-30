import os
import argparse

def collect_code(src_directory, output_file, extensions):
    """
    Собирает код из всех файлов с заданными расширениями в один текстовый файл.

    :param src_directory: Путь к директории с исходным кодом.
    :param output_file: Путь к выходному файлу.
    :param extensions: Список расширений файлов для сбора (например, ['.cpp', '.h']).
    """
    
    # Проверяем, существует ли директория с исходным кодом
    if not os.path.isdir(src_directory):
        print(f"Ошибка: Директория '{src_directory}' не найдена.")
        return

    # Открываем выходной файл для записи
    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            print(f"Начало сбора кода из '{src_directory}' в файл '{output_file}'...")
            
            # Рекурсивно обходим все файлы и директории
            for root, _, files in os.walk(src_directory):
                # Сортируем файлы для предсказуемого порядка
                files.sort()
                for filename in files:
                    # Проверяем, соответствует ли расширение файла нужному
                    if any(filename.endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, filename)
                        
                        # Получаем относительный путь для красивого вывода
                        relative_path = os.path.relpath(file_path, src_directory)
                        
                        print(f"  -> Добавляется файл: {relative_path}")
                        
                        # Пишем заголовок-разделитель в выходной файл
                        outfile.write("=" * 80 + "\n")
                        outfile.write(f"// Файл: {relative_path}\n")
                        outfile.write("=" * 80 + "\n\n")
                        
                        # Читаем и записываем содержимое файла
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                                outfile.write(infile.read())
                                outfile.write("\n\n")
                        except Exception as e:
                            print(f"    - Не удалось прочитать файл {relative_path}: {e}")
                            outfile.write(f"// Не удалось прочитать содержимое файла: {e}\n\n")
            
            print(f"\nСбор кода успешно завершен. Результат в файле '{output_file}'.")

    except IOError as e:
        print(f"Ошибка записи в файл '{output_file}': {e}")


if __name__ == "__main__":
    # Настраиваем парсер аргументов командной строки для удобства
    parser = argparse.ArgumentParser(
        description="Скрипт для сбора исходного кода из директории в один файл.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-s', '--source',
        type=str,
        default='src',
        help="Путь к директории с исходным кодом (по умолчанию: 'src')"
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='all_code.txt',
        help="Имя выходного файла (по умолчанию: 'all_code.txt')"
    )
    
    parser.add_argument(
        '-e', '--extensions',
        nargs='+',  # принимаем один или несколько аргументов
        default=['.cpp', '.h', '.hpp'],
        help="Расширения файлов для сбора (по умолчанию: .cpp .h .hpp)"
    )

    args = parser.parse_args()

    # Запускаем основную функцию с полученными аргументами
    collect_code(args.source, args.output, args.extensions)
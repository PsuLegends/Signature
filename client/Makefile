# --- Имя компилятора ---
CXX = g++

# --- Имя целевого исполняемого файла ---
TARGET = client

# --- Директории ---
SRCDIR = src
BUILDDIR = build

# --- Флаги компиляции ---
# -std=c++20            : Стандарт C++
# -fPIC                 : Position-Independent Code
# -Wall -Wextra         : Включаем максимум предупреждений для чистоты кода
# -g                    : Добавляем отладочную информацию (рекомендуется во время разработки)
# -O2                   : Умеренная оптимизация (O3 может быть слишком агрессивной)
CXXFLAGS = -std=c++20 -fPIC -Wall -Wextra -g -O2

# --- Флаги линковки и Библиотеки ---
# Клиенту НЕ НУЖНЫ: Qt, uWebSockets/uSockets, libuv, zlib, pthreads.
# Клиенту НУЖНЫ:
#   -lssl -lcrypto        : Для OpenSSL (используется в модуле Rsa)
#   -lcryptopp            : Для Crypto++ (используется в Crypto_utils)
#   -lboost_program_options : Для парсинга аргументов (используется в UI)
#   -lboost_filesystem    : Для проверки пути к лог-файлу (используется в Logger)
# LDFLAGS пуст, т.к. все стандартные пути.
LDFLAGS =
LDLIBS  = -lssl -lcrypto -lcryptopp -lboost_program_options -lboost_filesystem


# === Автоматическое обнаружение исходных файлов (без изменений) ===
# Находим все .cpp файлы рекурсивно в директории src
SOURCES := $(shell find $(SRCDIR) -name '*.cpp' -type f)

# Создаем список объектных файлов, заменяя 'src/' на 'build/' и '.cpp' на '.o'
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES))


# === Основные цели (без изменений в логике) ===

.PHONY: all clean check_libs

# Цель по умолчанию: сначала проверить библиотеки, затем собрать исполняемый файл
all: check_libs $(TARGET)

# Правило для линковки финального исполняемого файла
$(TARGET): $(OBJECTS)
	@echo "Линковка -> $@"
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Правило для компиляции каждого .cpp файла в .o файл
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция -> $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Цель для очистки проекта (без изменений)
clean:
	@echo "Очистка проекта..."
	@rm -rf $(BUILDDIR) $(TARGET)


# === Вспомогательная цель для проверки библиотек (полностью переписана под клиента) ===

check_libs:
	@echo "Проверка наличия необходимых библиотек для клиента..."
	# --- Проверка OpenSSL ---
	@if ! pkg-config --exists openssl; then \
		echo "Ошибка: Библиотека OpenSSL (libssl, libcrypto) не найдена."; \
		echo "  Используется модулем Rsa для работы с большими числами."; \
		echo "  Установите: sudo apt install libssl-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# --- Проверка Crypto++ ---
	@if ! ld -lcryptopp 2>&1 | grep -q "cannot find"; then \
		echo "Проверка Crypto++ пройдена (через ld)"; \
	elif ! pkg-config --exists cryptopp; then \
		echo "Ошибка: Библиотека Crypto++ (libcryptopp) не найдена."; \
		echo "  Используется модулем Crypto_utils для хеширования."; \
		echo "  Установите: sudo apt install libcrypto++-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# --- Проверка Boost ---
	@if ! ld -lboost_program_options 2>&1 | grep -q "cannot find"; then \
		echo "Проверка Boost пройдена (через ld)"; \
	else \
		echo "Внимание: Не удалось проверить наличие Boost через ld."; \
		echo "  Убедитесь, что установлена библиотека Boost Program Options."; \
		echo "  Установите: sudo apt install libboost-program-options-dev libboost-filesystem-dev (Debian/Ubuntu)"; \
	fi
	@echo "Все необходимые библиотеки для клиента найдены."

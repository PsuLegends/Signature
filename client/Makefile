# --- Имя компилятора ---
CXX = g++

# --- Имя целевого исполняемого файла ---
TARGET = client

# --- Директории ---
SRCDIR = src
BUILDDIR = build

# --- Флаги компиляции ---
# -g                    : Оставляем отладочные символы, это полезно даже в релизе
# -O2                   : Стандартный флаг оптимизации для релизных сборок
CXXFLAGS = -std=c++20 -fPIC -Wall -Wextra -g -O2

# --- Флаги линковки ---
# Больше не нужны флаги для Sanitizer'а, LDFLAGS пуст
LDFLAGS =

# --- Библиотеки ---
# Удалена библиотека -lasan, т.к. AddressSanitizer больше не используется
LDLIBS  = -lssl -lcrypto -lcryptopp -lboost_program_options -lboost_filesystem


# === Автоматическое обнаружение исходных файлов (без изменений) ===
SOURCES := $(shell find $(SRCDIR) -name '*.cpp' -type f)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES))


# === Основные цели (без изменений в логике) ===
.PHONY: all clean check_libs

all: check_libs $(TARGET)

# --- Правило линковки ---
# Теперь оно снова простое. Для надежности передаем CXXFLAGS и сюда.
$(TARGET): $(OBJECTS)
	@echo "Линковка -> $@"
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

# Правило компиляции (без изменений)
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция -> $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- Правило очистки ---
clean:
	@echo "Очистка проекта..."
	@rm -rf $(BUILDDIR) $(TARGET) a.out



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

# --- Имя компилятора ---
CXX = g++

# --- Имя целевого исполняемого файла ---
TARGET = server

# --- Директории ---
SRCDIR = src
BUILDDIR = build

# === НОВЫЕ ФЛАГИ ДЛЯ ОТЛАДКИ ===
# -g                    : Добавляем отладочные символы, что КРАЙНЕ ВАЖНО для ASan.
# -fsanitize=address    : Включаем AddressSanitizer.
# -fno-omit-frame-pointer: Рекомендуется для более качественных стектрейсов с ASan.
SANITIZE_FLAGS = -g -fsanitize=address -fno-omit-frame-pointer

# --- Флаги компиляции ---
# -std=c++20            : Стандарт C++
# -fPIC                 : Position-Independent Code
# -Wall -Wextra         : Максимум предупреждений
# -O1                   : СНИЖАЕМ оптимизацию до -O1. ASan лучше всего работает
#                         с низкой оптимизацией. Вернете -O3 после отладки.
# $(shell ...)          : Получаем флаги от pkg-config
CXXFLAGS = -std=c++20 -fPIC -Wall -Wextra -O1 $(SANITIZE_FLAGS) \
           $(shell pkg-config --cflags Qt5Core Qt5Sql)

# --- Флаги линковки ---
# Добавляем SANITIZE_FLAGS сюда, чтобы линковщик подтянул библиотеку libasan.
LDFLAGS = -Llib/uWebSockets/uSockets $(SANITIZE_FLAGS)

# --- Библиотеки (LDLIBS) ---
# Добавляем -lpthread явно, т.к. ваш сервер использует std::thread.
LDLIBS  = -l:uSockets.a -lssl -lcrypto -luv -lz -lpthread -lcryptopp -lboost_program_options -lboost_filesystem \
          $(shell pkg-config --libs Qt5Core Qt5Sql)

# === Автоматическое обнаружение исходных файлов (без изменений) ===
SOURCES := $(shell find $(SRCDIR) -name '*.cpp' -type f)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES))


# === Основные цели (без изменений в логике) ===

.PHONY: all clean check_libs

all: check_libs $(TARGET)

# Правило для линковки (без изменений, т.к. флаги уже в LDFLAGS)
$(TARGET): $(OBJECTS)
	@echo "Линковка -> $@"
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Правило для компиляции (без изменений, т.к. флаги уже в CXXFLAGS)
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция -> $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Цель для очистки (без изменений)
clean:
	@echo "Очистка проекта..."
	@rm -rf $(BUILDDIR) $(TARGET)


# Эта часть остается без изменений, она отличная.
check_libs:
	@echo "Проверка наличия необходимых библиотек..."
	# Проверка libuv
	@if ! pkg-config --exists libuv; then \
		echo "Ошибка: Библиотека libuv не найдена. Она необходима для сборки проекта."; \
		echo "  Установите: sudo apt install libuv1-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# Проверка OpenSSL
	@if ! pkg-config --exists openssl; then \
		echo "Ошибка: Библиотека OpenSSL (libssl, libcrypto) не найдена."; \
		echo "  Установите: sudo apt install libssl-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# Проверка zlib
	@if ! pkg-config --exists zlib; then \
		echo "Ошибка: Библиотека zlib не найдена."; \
		echo "  Установите: sudo apt install zlib1g-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# Проверка Qt5Core
	@if ! pkg-config --exists Qt5Core; then \
		echo "Ошибка: Модуль Qt5Core не найден."; \
		echo "  Установите: sudo apt install qtbase5-dev (Debian/Ubuntu)"; \
		exit 1; \
	fi
	# Проверка Qt5Sql
	@if ! pkg-config --exists Qt5Sql; then \
		echo "Ошибка: Модуль Qt5Sql не найден."; \
		echo "  Установите: sudo apt install libqt5sql5-sqlite (Debian/Ubuntu)"; \
		exit 1; \
	fi
	@echo "Все необходимые библиотеки найдены."
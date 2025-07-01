# --- Имя компилятора ---
CXX = g++

# --- Имена целевых исполняемых файлов ---
TARGET_SERVER = server
# *** ИЗМЕНЕНИЕ: Полный и однозначный путь к бинарнику утилиты ***
TARGET_KEYGEN = src/Signing/keygen

# --- Директории ---
SRCDIR = src
BUILDDIR = build

# --- Флаги Sanitizer'а ---
SANITIZE_FLAGS = -g -fsanitize=address -fno-omit-frame-pointer

# --- Флаги компиляции СЕРВЕРА ---
CXXFLAGS_SERVER = -std=c++20 -fPIC -Wall -Wextra -O1 $(SANITIZE_FLAGS) \
                  $(shell pkg-config --cflags Qt5Core Qt5Sql)

# --- Флаги компиляции УТИЛИТЫ KEYGEN ---
CXXFLAGS_KEYGEN = -std=c++20 -Wall -Wextra -g -O2

# --- Библиотеки для СЕРВЕРА ---
LDFLAGS_SERVER = -Llib/uWebSockets/uSockets $(SANITIZE_FLAGS)
LDLIBS_SERVER  = -l:uSockets.a -lssl -lcrypto -luv -lz -lpthread -lcryptopp -lboost_program_options -lboost_filesystem \
                 $(shell pkg-config --libs Qt5Core Qt5Sql)

# --- Библиотеки для УТИЛИТЫ KEYGEN ---
LDLIBS_KEYGEN  = -lssl -lcrypto

# === Автоматическое обнаружение исходных файлов СЕРВЕРА ===
# Исключаем keygen.cpp, как и раньше
SOURCES_SERVER := $(shell find $(SRCDIR) -name '*.cpp' -type f -not -path "$(SRCDIR)/Keygen/keygen.cpp")
OBJECTS_SERVER := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES_SERVER))


# === Основные цели ===
.PHONY: all clean check_libs

# Цель `all` зависит от полного пути к `keygen`
all: $(TARGET_KEYGEN) check_libs $(TARGET_SERVER)

# --- Правила сборки для СЕРВЕРА ---
$(TARGET_SERVER): $(OBJECTS_SERVER)
	@echo "Линковка сервера -> $@"
	$(CXX) $(CXXFLAGS_SERVER) $^ -o $@ $(LDLIBS_SERVER)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция файла сервера -> $<"
	$(CXX) $(CXXFLAGS_SERVER) -c $< -o $@


# === ИСПРАВЛЕННЫЕ ПРАВИЛА СБОРКИ ДЛЯ KEYGEN ===
KEYGEN_SRC = $(SRCDIR)/Keygen/keygen.cpp
RSA_SRC = $(SRCDIR)/Rsa/rsa_crypto.cpp 
RSA_OBJ = $(BUILDDIR)/Rsa/rsa_crypto.o_keygen

# *** ГЛАВНОЕ ИЗМЕНЕНИЕ ***
# Цель теперь - наш TARGET_KEYGEN (src/Signing/keygen)
$(TARGET_KEYGEN): $(KEYGEN_SRC) $(RSA_OBJ)
	@echo "Проверка/создание директории $(dir $@)..."
	@mkdir -p $(dir $@)
	@echo "Линковка утилиты keygen -> $@"
	# Передаем исходники и объектник, а в -o подставляем имя цели ($@),
	# которое теперь равно "src/Signing/keygen"
	$(CXX) $(CXXFLAGS_KEYGEN) $(KEYGEN_SRC) $(RSA_OBJ) -o $@ $(LDLIBS_KEYGEN)

# Правило для компиляции RSA-модуля для keygen (без изменений)
$(RSA_OBJ): $(RSA_SRC)
	@mkdir -p $(dir $@)
	@echo "Компиляция RSA для keygen -> $<"
	$(CXX) $(CXXFLAGS_KEYGEN) -c $< -o $@

# --- Общие цели ---
clean:
	@echo "Очистка проекта..."
	# Удаляем build, оба бинарника и временный объектник
	@rm -rf $(BUILDDIR) $(TARGET_SERVER) $(TARGET_KEYGEN) $(RSA_OBJ)
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
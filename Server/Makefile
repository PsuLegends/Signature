# --- Имя компилятора ---
CXX = g++

# --- Имя целевого исполняемого файла ---
TARGET = server

# --- Директории ---
SRCDIR = src
BUILDDIR = build

# --- Флаги компиляции ---
# -std=c++20            : Стандарт C++
# -fPIC                 : Position-Independent Code (хорошая практика для библиотек)
# -Wall -Wextra         : Включаем максимум предупреждений для чистоты кода
# -O3                   : Максимальная оптимизация
# $(shell ...)          : Получаем флаги от pkg-config
CXXFLAGS = -std=c++20 -fPIC -Wall -Wextra -O3 \
           $(shell pkg-config --cflags Qt5Core Qt5Sql)

# --- Флаги линковки ---
# -L...                 : Пути к библиотекам
# -l...                 : Имена библиотек
LDFLAGS = -Llib/uWebSockets/uSockets
LDLIBS  = -l:uSockets.a -lssl -lcrypto -luv -lz -lpthread -lcryptopp -lboost_program_options -lboost_filesystem \
          $(shell pkg-config --libs Qt5Core Qt5Sql)

# === Автоматическое обнаружение исходных файлов ===
# Находим все .cpp файлы рекурсивно в директории src
SOURCES := $(shell find $(SRCDIR) -name '*.cpp' -type f)

# Создаем список объектных файлов, заменяя 'src/' на 'build/' и '.cpp' на '.o'
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES))


# === Основные цели ===

# .PHONY указывает, что 'all' и 'clean' - это не файлы
.PHONY: all clean check_libs

# Цель по умолчанию: сначала проверить библиотеки, затем собрать исполняемый файл
all: check_libs $(TARGET)

# Правило для линковки финального исполняемого файла
# $@ - имя цели (т.е. $(TARGET))
# $^ - все зависимости (т.е. $(OBJECTS))
$(TARGET): $(OBJECTS)
	@echo "Линковка -> $@"
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Правило для компиляции каждого .cpp файла в .o файл
# $< - первая зависимость (т.е. один из .cpp файлов)
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@# Создаем поддиректорию в build/, если она еще не существует
	@mkdir -p $(dir $@)
	@echo "Компиляция -> $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Цель для очистки проекта
clean:
	@echo "Очистка проекта..."
	@# ИСПРАВЛЕНО: BUILDDIR вместо BUILDДIR
	@rm -rf $(BUILDDIR) $(TARGET)


# === Вспомогательная цель для проверки библиотек ===

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
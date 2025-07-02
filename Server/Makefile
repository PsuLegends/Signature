CXX = g++
TARGET_SERVER = server
TARGET_KEYGEN = src/Signing/keygen
SRCDIR = src
BUILDDIR = build
SANITIZE_FLAGS = -g -fsanitize=address -fno-omit-frame-pointer
CXXFLAGS_SERVER = -std=c++20 -fPIC -Wall -Wextra -O1 $(SANITIZE_FLAGS) \
                  $(shell pkg-config --cflags Qt5Core Qt5Sql)
CXXFLAGS_KEYGEN = -std=c++20 -Wall -Wextra -g -O2
LDFLAGS_SERVER = -Llib/uWebSockets/uSockets $(SANITIZE_FLAGS)
LDLIBS_SERVER  = -l:uSockets.a -lssl -lcrypto -luv -lz -lpthread -lcryptopp -lboost_program_options -lboost_filesystem \
                 $(shell pkg-config --libs Qt5Core Qt5Sql)
LDLIBS_KEYGEN  = -lssl -lcrypto
SOURCES_SERVER := $(shell find $(SRCDIR) -name '*.cpp' -type f -not -path "$(SRCDIR)/Keygen/keygen.cpp")
OBJECTS_SERVER := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES_SERVER))
.PHONY: all clean check_libs
all: $(TARGET_KEYGEN) check_libs $(TARGET_SERVER)
$(TARGET_SERVER): $(OBJECTS_SERVER)
	@echo "Линковка сервера -> $@"
	$(CXX) $(CXXFLAGS_SERVER) $^ -o $@ $(LDLIBS_SERVER)
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция файла сервера -> $<"
	$(CXX) $(CXXFLAGS_SERVER) -c $< -o $@
KEYGEN_SRC = $(SRCDIR)/Keygen/keygen.cpp
RSA_SRC = $(SRCDIR)/Rsa/rsa_crypto.cpp 
RSA_OBJ = $(BUILDDIR)/Rsa/rsa_crypto.o_keygen
$(TARGET_KEYGEN): $(KEYGEN_SRC) $(RSA_OBJ)
	@echo "Проверка/создание директории $(dir $@)..."
	@mkdir -p $(dir $@)
	@echo "Линковка утилиты keygen -> $@"
	# Передаем исходники и объектник, а в -o подставляем имя цели ($@),
	# которое теперь равно "src/Signing/keygen"
	$(CXX) $(CXXFLAGS_KEYGEN) $(KEYGEN_SRC) $(RSA_OBJ) -o $@ $(LDLIBS_KEYGEN)
$(RSA_OBJ): $(RSA_SRC)
	@mkdir -p $(dir $@)
	@echo "Компиляция RSA для keygen -> $<"
	$(CXX) $(CXXFLAGS_KEYGEN) -c $< -o $@
clean:
	@echo "Очистка проекта..."
	# Удаляем build, оба бинарника и временный объектник
	@rm -rf $(BUILDDIR) $(TARGET_SERVER) $(TARGET_KEYGEN) $(RSA_OBJ)
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
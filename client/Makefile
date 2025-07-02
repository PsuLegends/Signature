CXX = g++
TARGET = client
SRCDIR = src
BUILDDIR = build
CXXFLAGS = -std=c++20 -fPIC -Wall -Wextra -g -O2
LDFLAGS =
LDLIBS  = -lssl -lcrypto -lcryptopp -lboost_program_options -lboost_filesystem
SOURCES := $(shell find $(SRCDIR) -name '*.cpp' -type f)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SOURCES))
.PHONY: all clean check_libs
all: check_libs $(TARGET)
$(TARGET): $(OBJECTS)
	@echo "Линковка -> $@"
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(dir $@)
	@echo "Компиляция -> $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@
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

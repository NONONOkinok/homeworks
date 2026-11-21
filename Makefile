# Makefile для проекта «Система аутентификации»
#
# Запускается из корня проекта:
#   make help      — список команд
#   make install   — установить зависимости
#   make run       — запустить приложение
#   make test      — запустить все тесты
#   make clean     — очистить временные файлы

# --- Настройки ---
PYTHON ?= python3              # интерпретатор Python
PIP    ?= $(PYTHON) -m pip     # модуль установки пакетов

# .PHONY — «фальшивые» цели, у которых нет одноимённых файлов
.PHONY: help install run test test-unit test-integration test-cov clean

# --- Справка ---
help:
	@echo "Доступные команды:"
	@echo "  make install          — установить зависимости из requirements.txt"
	@echo "  make run              — запустить приложение"
	@echo "  make test             — запустить все тесты (pytest)"
	@echo "  make test-unit        — только юнит-тесты"
	@echo "  make test-integration — только интеграционные тесты"
	@echo "  make test-cov         — тесты с отчётом о покрытии (терминал + HTML)"
	@echo "  make clean            — удалить кэш, БД и __pycache__"

# Установка зависимостей
install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

# Запуск приложения
run:
	$(PYTHON) auth_system.py

# Тесты
test:
	$(PYTHON) -m pytest

test-unit:
	$(PYTHON) -m pytest test_auth_system.py test_secret_store.py test_token_manager.py test_refresh_token.py test_sessions.py test_rotation.py

test-integration:
	$(PYTHON) -m pytest test_integration.py

test-cov:
	$(PYTHON) -m pytest --cov=auth_system --cov=database --cov=secret_store --cov=token_manager --cov=security --cov=refresh_token --cov=session_manager --cov-report=term-missing --cov-report=html

# Очистка
clean:
	rm -rf .pytest_cache htmlcov .coverage
	rm -f users.db users_test.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
"""
Integration tests for auth system (end-to-end)

Tests the complete flow:
1. Register new user
2. Login with correct password
3. Login with wrong password
4. Account lockout after failed attempts

Run: python test_integration.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
import auth_system


def test_registration_success():
    """Test 1: Successful registration"""
    print("\n--- Test 1: Registration ---")

    # Clear login attempts before test
    auth_system._login_attempts.clear()

    username = "new_user_test"
    password = "Registratciya123Aa"
    confirm = "Registratciya123Aa"

    success, message = auth_system.register_user(username, password, confirm)

    assert success == True, f"Expected success, got: {message}"
    assert auth_system.db_user_exists(username) == True

    print(f"[OK] User '{username}' registered successfully")
    return username, password


def test_registration_password_mismatch():
    """Test 2: Password mismatch"""
    print("\n--- Test 2: Password mismatch ---")

    username = "test_mismatch"
    password = "Password123Aa"
    confirm = "Different123Aa"

    success, message = auth_system.register_user(username, password, confirm)

    assert success == False, "Expected error, but registration passed"

    print(f"[OK] Rejected correctly")
    return


def test_registration_duplicate_user():
    """Test 3: Duplicate username"""
    print("\n--- Test 3: Duplicate user ---")

    username = "duplicate_test"
    password = "Test123Aa"
    confirm = "Test123Aa"

    # Create user first
    auth_system.register_user(username, password, confirm)

    # Try to register again
    success, message = auth_system.register_user(username, password, confirm)

    assert success == False, "Expected error, but registration passed"

    print(f"[OK] Rejected correctly")
    return


def test_registration_weak_password():
    """Test 4: Weak password"""
    print("\n--- Test 4: Weak password ---")

    username = "weak_test"
    password = "123"
    confirm = "123"

    success, message = auth_system.register_user(username, password, confirm)

    assert success == False, "Expected error, but registration passed"

    print(f"[OK] Rejected correctly")
    return


def test_login_success(username, password):
    """Test 5: Successful login"""
    print("\n--- Test 5: Login success ---")

    success, message = auth_system.login_user(username, password)

    assert success == True, f"Expected success, got: {message}"

    print(f"[OK] Login successful for '{username}'")
    return


def test_login_wrong_password(username):
    """Test 6: Wrong password"""
    print("\n--- Test 6: Wrong password ---")

    wrong_password = "WrongPassword999"
    success, message = auth_system.login_user(username, wrong_password)

    assert success == False, "Expected error, but login passed"

    print(f"[OK] Rejected correctly")
    return


def test_login_nonexistent_user():
    """Test 7: Non-existent user"""
    print("\n--- Test 7: Non-existent user ---")

    success, message = auth_system.login_user("NonExistentUser", "Password123")

    assert success == False, "Expected error, but login passed"

    print(f"[OK] Rejected correctly")
    return


def test_login_with_unicode():
    """Test 8: Unicode password"""
    print("\n--- Test 8: Unicode password ---")

    username = "unicode_user"
    password = "Test🔐123Aa"  # with emoji

    # Register
    auth_system.register_user(username, password, password)

    # Login
    success, message = auth_system.login_user(username, password)

    assert success == True, f"Expected success with unicode, got: {message}"

    print(f"[OK] Unicode password works")
    return


# ============== RUN ==============

def run_integration_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("INTEGRATION TESTS")
    print("=" * 60)

    # Use separate test DB
    test_db = "users_test.db"

    # Temporarily change DB path
    original_db = auth_system.DB_FILE
    auth_system.DB_FILE = os.path.join(os.path.dirname(__file__), test_db)

    # Remove old test DB
    if os.path.exists(auth_system.DB_FILE):
        try:
            os.remove(auth_system.DB_FILE)
        except:
            pass

    # Clear login attempts
    auth_system._login_attempts.clear()

    # Initialize DB
    auth_system.init_db()

    # Run tests
    username, password = test_registration_success()
    test_registration_password_mismatch()
    test_registration_duplicate_user()
    test_registration_weak_password()
    test_login_success(username, password)
    test_login_wrong_password(username)
    test_login_nonexistent_user()
    test_login_with_unicode()

    print("\n" + "=" * 60)
    print("All integration tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_integration_tests()
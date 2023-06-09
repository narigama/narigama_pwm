import pytest
from pytest_bdd import parsers, given, when, then

import narigama_pwm


# TODO: algo factory?
ALGORITHMS = {
    "argon2": narigama_pwm.Argon2PasswordFunction(),
}


@given("I have a password manager", target_fixture="password_manager")
def password_manager():
    yield narigama_pwm.PasswordManager()


@given("I have a default password manager", target_fixture="password_manager")
def password_manager_default():
    yield narigama_pwm.PasswordManager.default()


@given(parsers.parse("I install the {algo} module"))
def password_manager_load_algorithm(password_manager: narigama_pwm.PasswordManager, algo: str):
    password_manager.install(ALGORITHMS[algo.strip().lower()])
    yield


@when(parsers.parse("I reinstall the {algo} module it should fail"))
def password_manager_reinstall_algo_crashes(password_manager: narigama_pwm.PasswordManager, algo: str):
    with pytest.raises(narigama_pwm.PasswordAlgorithmAlreadyRegistered) as ex:
        password_manager.install(ALGORITHMS[algo.strip().lower()])

    assert ex.value.args == ("argon2",)


@when(parsers.parse("I call the encrypt method with the password '{plaintext}'"), target_fixture="ciphertext")
def password_manager_encrypt_password(password_manager: narigama_pwm.PasswordManager, plaintext: str):
    yield password_manager.encrypt(plaintext)


@when(
    parsers.parse("I call the decrypt method with the password '{plaintext}' and the ciphertext '{ciphertext}'"),
    target_fixture="decrypt_result",
)
def password_manager_decrypt_password(password_manager: narigama_pwm.PasswordManager, plaintext: str, ciphertext: str):
    yield password_manager.decrypt(plaintext, ciphertext)


@then(parsers.parse("I should receive an encrypted string starting with '{prefix}'"))
def check_prefix(prefix: str, ciphertext: str):
    assert ciphertext.startswith(prefix)


@then(parsers.parse("I should receive {ok} and nothing to update"))
@then(parsers.parse("I should receive {ok} and {new_ciphertext}"))
def check_decryption(decrypt_result: tuple[bool, str | None], ok: str, new_ciphertext: str | None = None):
    ok = ok.strip().lower() == "true"
    assert decrypt_result == (ok, new_ciphertext)


@then(parsers.parse("It should have {algorithms} installed"))
def check_installed_algorithms(password_manager: narigama_pwm.PasswordManager, algorithms: str):
    algorithms = [] if algorithms == "nothing" else algorithms.split(",")
    assert set(password_manager.functions.keys()) == set(algorithms)


@then(parsers.parse("It's default algorithm should be {algorithm}"))
def check_default_algorithm(password_manager: narigama_pwm.PasswordManager, algorithm: str):
    if algorithm == "nothing":
        assert password_manager.default is None

    else:
        assert password_manager.default == algorithm

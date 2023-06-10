from pytest_bdd import given, scenarios, parsers, then, when

import narigama_pwm


@given(parsers.parse("I create an {algorithm} function"), target_fixture="password_function")
@given(parsers.parse("I create a {algorithm} function"), target_fixture="password_function")
def password_function_create(password_function_factory, algorithm: str):
    yield password_function_factory(algorithm)


@when(parsers.parse("I call encrypt with '{plaintext}'"), target_fixture="encrypt_result")
def password_function_call_encrypt(password_function: narigama_pwm.PasswordFunction, plaintext: str):
    yield password_function.encrypt(plaintext)


@when(parsers.parse("I call decrypt with '{plaintext}' and '{ciphertext}'"), target_fixture="decrypt_result")
def password_function_call_decrypt(password_function: narigama_pwm.PasswordFunction, plaintext: str, ciphertext: str):
    yield password_function.decrypt(plaintext, ciphertext)


@when("I access the algorithm_name property", target_fixture="algo_name")
def password_function_get_algorithm_name(password_function: narigama_pwm.PasswordFunction):
    yield password_function.algorithm_name


@when("I access the algorithm_prefix property", target_fixture="algo_prefix")
def password_function_get_algorithm_prefix(password_function: narigama_pwm.PasswordFunction):
    yield password_function.algorithm_prefix


@then("I should have an encrypted ciphertext returned")
def password_function_check_encrypted_result(password_function: narigama_pwm.PasswordFunction, encrypt_result: str):
    assert encrypt_result.startswith(password_function.algorithm_prefix)


@then(parsers.parse("I should have an {algorithm} function"))
@then(parsers.parse("I should have a {algorithm} function"))
def password_function_check(password_function, algorithm):
    assert isinstance(password_function, narigama_pwm.PasswordFunction)
    assert password_function.algorithm_name == algorithm.strip().lower()


@then(parsers.parse("the result should be {ok}"))
def password_decrypt_result_check(decrypt_result, ok: bool):
    ok = ok.strip().lower() == "true"
    assert decrypt_result == ok


@then(parsers.parse("the name should be '{expected_name}'"))
def password_function_algorithm_name_check(algo_name: str, expected_name: str):
    assert algo_name == expected_name


@then(parsers.parse("the prefix should be '{expected_prefix}'"))
def password_function_algorithm_prefix_check(algo_prefix: str, expected_prefix: str):
    assert algo_prefix == expected_prefix


@then("it should be a subtype of PasswordFunction")
def password_function_is_correct_subtype(password_function):
    assert isinstance(password_function, narigama_pwm.PasswordFunction)


scenarios("features/argon2.feature")

import pytest
import narigama_pwm


ALGOS = {
    "argon2": narigama_pwm.Argon2PasswordFunction,
}


@pytest.fixture(scope="session")
def password_function_factory():
    def factory(fn_name: str, *args, **kwargs) -> narigama_pwm.PasswordFunction:
        return ALGOS[fn_name.strip().lower()](*args, **kwargs)

    yield factory

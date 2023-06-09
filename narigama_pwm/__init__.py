import abc
import logging


logger = logging.getLogger(__name__)


class PasswordException(Exception):
    pass


class PasswordAlgorithmAlreadyRegistered(PasswordException):
    pass


class PasswordFunction(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def algorithm_name(self) -> str:
        """
        Return a easily read name for this algorithm.
        """

    @property
    @abc.abstractmethod
    def algorithm_prefix(self) -> str:
        """
        Encrypted strings should start with this prefix.
        """

    @abc.abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt `plaintext` into a ciphertext using either the default
        algorithm, or a provided one.
        """

    @abc.abstractmethod
    def decrypt(self, plaintext: str, ciphertext: str) -> bool:
        """
        Check the plaintext "matches" the ciphertext, returning true/false.
        """


class Argon2PasswordFunction(PasswordFunction):
    def __init__(self):
        # Importing argon2 like this makes it optional as a dependency.
        # This'll raise if it's not installed.
        import argon2

        self._argon = argon2

    @property
    def algorithm_name(self) -> str:
        """
        Return a easily read name for this algorithm.
        """
        return "argon2"

    @property
    def algorithm_prefix(self) -> str:
        """
        Encrypted strings should start with this prefix.
        """
        return "$argon2i"

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt `plaintext` into a ciphertext using either the default
        algorithm, or a provided one.
        """
        return self._argon.hash_password(plaintext.encode()).decode()

    def decrypt(self, plaintext: str, ciphertext: str) -> bool:
        """
        Check the plaintext "matches" the ciphertext, returning true/false.
        """
        try:
            self._argon.verify_password(ciphertext.encode(), plaintext.encode())
            return True

        except self._argon.exceptions.Argon2Error as ex:
            logger.debug(ex)
            return False


class PasswordManager:
    def __init__(self):
        self.default = None  # first algo in becomes default
        self.functions = {}
        self.prefixes = {}

    @classmethod
    def default(cls):
        instance = cls()
        instance.install(Argon2PasswordFunction())
        return instance

    def install(self, password_function: PasswordFunction):
        if password_function.algorithm_name in self.functions:
            raise PasswordAlgorithmAlreadyRegistered(password_function.algorithm_name)

        self.default = self.default or password_function.algorithm_name
        self.functions[password_function.algorithm_name] = password_function
        self.prefixes[password_function.algorithm_prefix] = password_function

    def get_algorithm(self, algorithm: str | None = None) -> PasswordFunction:
        """
        Get an algorithm by name, or whatever the default is if None.
        """
        return self.functions[algorithm or self.default]

    def encrypt(self, plaintext: str, algorithm: str | None = None) -> str:
        """
        Encrypt `plaintext` into a ciphertext using either the default
        algorithm, or a provided one.
        """
        return self.get_algorithm(algorithm).encrypt(plaintext)

    def decrypt(self, plaintext: str, ciphertext: str, algorithm: str | None = None) -> tuple[bool, str | None]:
        """
        Check the plaintext "matches" the ciphertext returning true/false. If
        the ciphertext provided is not encrypted using the "default" algorithm,
        rehash it and return it too.
        """
        algo = self.get_algorithm(algorithm)
        needs_update = not ciphertext.startswith(algo.algorithm_prefix)
        ok = algo.decrypt(plaintext, ciphertext)

        if not ok:
            return False

        if needs_update:
            # re-encrypt with the default algo
            return True, self.encrypt(plaintext)

        return True, None

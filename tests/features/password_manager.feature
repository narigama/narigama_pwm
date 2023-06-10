Feature: Password Manager

    Provide a general abstraction to manage passwords and refresh old ones.

    Scenario: Create a Password Manager
        Given I create a password manager
        Then It should have nothing installed

    Scenario: Create a default Password Manager
        Given I create a password manager with defaults
        Then It should have argon2 installed
        And It's default algorithm should be argon2

    Scenario: Reinstall an existing algorithm
        Given I create a password manager
        And I install the argon2 module
        When I reinstall the argon2 module it should fail

    Scenario: Encrypting a Password
        Given I create a password manager with defaults
        When I call the encrypt method with the password 'tescovalue'
        Then I should receive an encrypted string starting with '$argon2i'

    Scenario: Decrypting a Password
        Given I create a password manager with defaults
        When I call the decrypt method with the password 'tescovalue' and the ciphertext '$argon2i$v=19$m=65536,t=3,p=4$c4XtrAoBUDfB+P5w+um2wA$bO956ivd67V6OlbDJPSH5i52quDAmum+M05ICMxQHis'
        Then I should receive True and nothing to update

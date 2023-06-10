Feature: Argon2 Password Function

    Provide an Argon2 compatible password hashing function

    Scenario: Create a new Function
        Given I create an Argon2 function
        Then I should have an Argon2 function
        And it should be a subtype of PasswordFunction

    Scenario: Encrypt with a function
        Given I create an Argon2 function
        When I call encrypt with 'tescovalue'
        Then I should have an encrypted ciphertext returned

    Scenario: Decrypt with a function
        Given I create an Argon2 function
        When I call decrypt with 'tescovalue' and '$argon2i$v=19$m=65536,t=3,p=4$c4XtrAoBUDfB+P5w+um2wA$bO956ivd67V6OlbDJPSH5i52quDAmum+M05ICMxQHis'
        Then the result should be true

    Scenario: Decrypt with a function and a wrong password
        Given I create an Argon2 function
        When I call decrypt with 'hunter2' and '$argon2i$v=19$m=65536,t=3,p=4$c4XtrAoBUDfB+P5w+um2wA$bO956ivd67V6OlbDJPSH5i52quDAmum+M05ICMxQHis'
        Then the result should be false

    Scenario: Decrypt with a function and a wrong hash
        Given I create an Argon2 function
        When I call decrypt with 'tescovalue' and '$argon2i$v=19$m=65536,t=3,p=4$IfadCJQp223UtShhKiy6dQ$noGVrsreY9dn+OT8D8s0fwtRSKmUXezoenSNeO+HvM0'
        Then the result should be false

    Scenario: Get the function name
        Given I create an Argon2 function
        When I access the algorithm_name property
        Then the name should be 'argon2'

    Scenario: Get the function prefix
        Given I create an Argon2 function
        When I access the algorithm_prefix property
        Then the prefix should be '$argon2i'

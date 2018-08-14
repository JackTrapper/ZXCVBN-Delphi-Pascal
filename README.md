# ZXCVBN-Delphi-Pascal
This is a Pascal/Delphi implementation of ZXCVBN password protocol. For details on the protocol please see https://github.com/dropbox/zxcvbn

zxcvbn is a password strength estimator inspired by password crackers.

Through pattern matching and conservative estimation, it recognizes and weighs 30k common passwords, common names and surnames according to US census data, popular English words from Wikipedia and US television and movies, and other common patterns like

- dates
- repeats (aaa)
- sequences (abcd)
- keyboard patterns (qwertyuiop)
- l33t speak

Consider using zxcvbn as an algorithmic alternative to password composition policy — it is more secure, flexible, and usable when sites require a minimal complexity score in place of annoying rules like "passwords must contain three of (lower, upper, numbers, symbols)

Password complexity policies weaken the security of the system.


Sample Usage
============

    res: TZxcvbnResult;

    res := TZxcvbn.MatchPassword('hunter2');

The result class contains the scoring of the password

    res.Guesses                      // Estimated guesses needed to crack the password
    res.GuessesLog10                 // Order of magnitude of res.Guesses

    // Estimated time time crack, in seconds, based on different scenarios
    res.CrackTimeOnlineThrottling    //  10 guess/hr  - online attack on a service that ratelimits password auth attempts
    res.CrackTimeOnlineNoThrottling  // 100 guess/sec - online attack on a service that doesn't ratelimit, or where an attacker has outsmarted ratelimiting.
    res.CrackTimeOfflineSlowHash     // 10k guess/sec - offline attack. assumes multiple attackers, proper user-unique salting, and a slow hash function w/ moderate work factor, such as bcrypt, scrypt, PBKDF2.
    res.CrackTimeOfflineFastHash     // 10B guess/sec - offline attack with user-unique salting but a fast hash function like SHA-1, SHA-256 or MD5. A wide range of reasonable numbers anywhere from one billion - one trillion guesses per second, depending on number of cores and machines. ballparking at 10B/sec.

    // CrackTimexxxDisplay - same as CrackTimexxx, but with friendly text duration (e.g. "instant", "5 seconds", "4 days", "2 years", "centuries"
    res.CrackTimeOnlineThrottling
    res.CrackTimeOnlineNoThrottling
    res.CrackTimeOfflineSlowHash
    res.CrackTimeOfflineFastHash

    res.Score           // (0..4) Useful for implementing a strength bar
                        // - 0: guesses < 10k
                        // - 1: guesses < 10M
                        // - 2: guesses < 1B
                        // - 3: guesses < 100B
                        // - 4: guesses >= 100B
    res.ScoreDisplay    // text description that of the score

    res.WarningText     // text that can be used to tell the user what they did wrong
    res.SuggestionsText // list of suggestions the user can take to improve the password

How strong should a password be?
================================

A good requirement is for an Offline slow hash (e.g. bcrypt, scrypt, argon2) to take 25 years to crack:

    res.CrackTimeOfflineSlowHash > 788923800  // 788923800 seconds = 25 years
    res.Guesses > 7.889238E12                 // 7.889238E12 guesses = 25 years * 10000/sec
    res.GuessesLog10 > 12.897                 // 12.897 = Log10(7.889238E12)


Example password crack times
============================

| Password                       | Fast Hash | Slow Hash | Notes                                                     |
|--------------------------------|-----------|-----------|-----------------------------------------------------------|
|	`correct horse battery staple` | 34 years  | centuries | https://xkcd.com/936/                                     |
|	`Compl3xity < Length!`		     | 4 days    | centuries | Intel World Password Day 2014 - https://imgur.com/XuMUU0b |
|	`cLbTyv2t`                     | 5 hours   | centuries | random 8 character, uppercase lowercase digit             |
|	`Tr0ub4dor&3`                  |  3 hours  | centuries | misspelling of troubadour                                 |
|	`Tr0ub4dour&3`                 | instant   |  5 days   | correct spelling of troubador                             |
|	`hunter2`                      | instant   |  instant  | all i see is *******                                      |


Version History
===============

- **Version 1.2**   *(8/14/2018)*

  - added "b6" and "q9" 1337-speak (HashCat)
	- calculation time (ms) is now a float. QueryPerformanceCounter supports down to 0.0001 ms (100 ns) (i.e. "%.4f")
	- Demo now includes some of the more well-known passwords (You may only see *******)
	- Merged everything into one unit (Zxcvbn.pas)
	- Moved some purely internal classes and interfaces into the implementation section (don't expose your internal details)

- **Version 1.1**   *(8/11/2018)*

  - Removed duplicated words from dictionaries
  - Removed unused variable
	- Fixed typo trying to calculate LogN(1, ) rather than LogN(2, )  (floating point exception)
	- Changed Result class to return the same 4 sets of crack times than zxcvbn cacnonical does (online throttled, online unthrottled, offline slow hash, offline fast hash)
	- Changed password scor (0..4) to be based on guesses, not crack time (as zxcvbn canonical correctly does)
	- Removed use of madExcept from demo application
	- Changed localization to be based on locale name (e.g. "de-DE") rather than an enumeration
	- Changed localization system to use more common technique of localizing strings
	- Added remaining translactions for French and German (thanks Google Translate)

- **Version 1.0**   *(4/17/2018)*
			
  - Initial version by TCardinal on GitHub (https://github.com/TCardinal/ZXCVBN-Delphi-Pascal)

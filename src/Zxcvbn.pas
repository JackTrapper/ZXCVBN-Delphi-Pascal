unit Zxcvbn;

interface

{
	zxcvbn is a password strength estimator inspired by password crackers.

	Through pattern matching and conservative estimation, it recognizes and weighs:

		- 30k common passwords
		- common names and surnames according to US census data
		- popular English words from Wikipedia and US television and movies

	and other common patterns like:

		- dates
		- repeats (aaa)
		- sequences (abcd)
		- keyboard patterns (qwertyuiop)
		- l33t speak

	Consider using zxcvbn as an algorithmic alternative to password composition policy — it is more secure,
	flexible, and usable when sites require a minimal complexity score in place of annoying rules
	like "passwords must contain three of (lower, upper, numbers, symbols)

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

		res.Score           (0..4) Useful for implementing a strength bar
										- 0: guesses  < 10k
										- 1: guesses  < 10M
										- 2: guesses  < 1B
										- 3: guesses  < 100B
										- 4: guesses >= 100B
		res.ScoreText       // text description that of the score
										- 0: Too guessable; risky password.
										- 1: Very guessable; protection from throttled online attacks.
										- 2: Somewhat guessable; protection from unthrottled online attacks.
										- 3: Safely unguessable; moderate protection from offline slow-hash scenario.
										- 4: Very unguessable; strong protection from offline slow-hash scenario.

		res.WarningText     // text that can be used to tell the user what they did wrong
		res.SuggestionsText // list of suggestions the user can take to improve the password

	How strong should a password be?
	================================

	A good requirement is for an Offline slow hash (e.g. bcrypt, scrypt, argon2) to take 25 years to crack:

		passwordIsGood := (res.CrackTimeOfflineSlowHash >= 788923800); // 788923800 seconds = 25 years


	Example password crack times
	============================

	Password                        Fast Hash  Slow Hash
	------------------------------  ---------  ---------
	"correct horse battery staple"  34 years   centuries  https://xkcd.com/936/
	"Compl3xity < Length!"		      4 days    centuries  Intel World Password Day 2014 - https://imgur.com/XuMUU0b
	"cLbTyv2t"                       5 hours   centuries  random 8 character, uppercase lowercase digit
	"Tr0ub4dor&3"                    3 hours   centuries  misspelling of troubadour
	"Tr0ub4dour&3"                   instant      5 days  correct spelling of troubador
	"hunter2"                        instant     instant  all i see is *******


	Version History
	===============

	Version 1.2   8/14/2018
			- added "b6" and "q9" 1337-speak (HashCat)
			- calculation time (ms) is now a float. QueryPerformanceCounter supports down to 0.0001 ms (100 ns) (i.e. "%.4f")
			- Demo now includes some of the more well-known passwords (You may only see *******)
			- Localization now does correct language fallback
			- Localized ScoreText
			- Merged everything into one unit (Zxcvbn.pas)
			- Moved some purely internal classes and interfaces into the implementation section (don't expose your internal details)
			- Pass unsecure password around as const to minimize the chance of a duplicate being made in memory
	Version 1.1   8/11/2018
			- Removed duplicated words from dictionaries
			- Removed unused variable
			- Fixed typo trying to calculate LogN(1, ) rather than LogN(2, )  (floating point exception)
			- Changed Result class to return the same 4 sets of crack times than zxcvbn cacnonical does
					(online throttled, online unthrottled, offline slow hash, offline fast hash)
			- Changed password scor (0..4) to be based on guesses, not crack time (as zxcvbn canonical correctly does)
			- Removed use of madExcept from demo application
			- Changed localization to be based on locale name (e.g. "de-DE") rather than an enumeration
			- Changed localization system to use more common technique of localizing strings
			- Added remaining translactions for French and German (thanks Google Translate)
	Version 1.0   4/17/2018
			Initial version by TCardinal on GitHub (https://github.com/TCardinal/ZXCVBN-Delphi-Pascal)
}

uses
	System.Classes, System.SysUtils, System.Generics.Collections;

type
	TZxcvbnMatch = class; //forward declaration

	/// <summary> The results of zxcvbn's password analysis </summary>
	TZxcvbnResult = class
	private
		function GetGuesses: Real;
		function GetGuessesLog10: Real;
		function GetScore: Integer;
	public
		/// <summary>A calculated estimate of how many bits of entropy the password covers, rounded to three decimal places.</summary>
		Entropy: Double;

		/// <summary>The number of milliseconds that zxcvbn took to calculate results for this password</summary>
		CalcTime: Real;

		/// <summary>An estimation of the crack time for this password in seconds</summary>
		CrackTimeOnlineThrottling:   Real;	// ( 10 guess/hr)  online attack on a service that ratelimits password auth attempts
		CrackTimeOnlineNoThrottling: Real;	// (100 guess/sec) online attack on a service that doesn't ratelimit, or where an attacker has outsmarted ratelimiting.
		CrackTimeOfflineSlowHash:    Real;	// (10k guess/sec) offline attack. assumes multiple attackers, proper user-unique salting, and a slow hash function w/ moderate work factor, such as bcrypt, scrypt, PBKDF2.
		CrackTimeOfflineFastHash:    Real;	// (10B guess/sec) offline attack with user-unique salting but a fast hash function like SHA-1, SHA-256 or MD5. A wide range of reasonable numbers anywhere from one billion - one trillion guesses per second, depending on number of cores and machines. ballparking at 10B/sec.

		/// <summary>A localized friendly string for the crack time (like "centuries", "instant", "7 minutes", "14 hours" etc.)</summary>
		CrackTimeOnlineThrottlingDisplay:   string;
		CrackTimeOnlineNoThrottlingDisplay: string;
		CrackTimeOfflineSlowHashDisplay:    string;
		CrackTimeOfflineFastHashDisplay:    string;

		/// <summary>The sequence of matches that were used to create the entropy calculation</summary>
		MatchSequence: TList<TZxcvbnMatch>;

		/// <summary>The password that was used to generate these results</summary>
		Password: string;

		/// <summary>Warning on this password</summary>
		WarningText: string;

		/// <summary>Suggestion on how to improve the password</summary>
		SuggestionsText: string;

		ScoreText: string; //Localized description of the score

		/// <summary>Constructor initialize Suggestion list.</summary>
		constructor Create;
		destructor Destroy; override;

		property Guesses: Real read GetGuesses; // estimated number of guesses to crack password
		property GuessesLog10: Real read GetGuessesLog10; // order of magnitude of result.guesses
		property Score: Integer read GetScore; // A score from 0 to 4 (inclusive). 0: too guessable, 1: very guessable, 2:somewhat guessable, 3: safely unguessable, 4:very unguessable
	end;

	/// <summary>All pattern matchers must implement the IZxcvbnMatcher interface.</summary>
	IZxcvbnMatcher = interface
		/// <summary>
		/// This function is called once for each matcher for each password being evaluated.
		/// It should perform the matching process and add TZxcvbnMatch objects for each match found to AMatches list.
		/// </summary>
		/// <param name="APassword">Password</param>
		/// <param name="AMatches">Matches list</param>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;

	/// <summary>
	/// Interface that matcher factories must implement.
	/// Matcher factories return a list of the matchers that will be used to evaluate the password
	/// </summary>
	IZxcvbnMatcherFactory = interface
		/// <summary>
		/// <para>Create the matchers to be used by an instance of Zxcvbn. </para>
		///
		/// <para>This function will be called once per each password being evaluated, to give the opportunity to provide
		/// different user inputs for each password. Matchers that are not dependent on user inputs should ideally be created
		/// once and cached so that processing (e.g. dictionary loading) will only have to be performed once, these cached
		/// matchers plus any user input matches would then be returned when CreateMatchers is called.</para>
		/// </summary>
		/// <param name="AUserInputs">List of per-password user information for this invocation</param>
		/// <returns>A list of <see cref="IZxcvbnMatcher"/> objects that will be used to pattern match this password</returns>
		function CreateMatchers(const AUserInputs: TStrings): TList<IZxcvbnMatcher>;
	end;

	/// <summary>
	/// <para>Zxcvbn is used to estimate the strength of passwords. </para>
	///
	/// <para>This implementation is a port of the Zxcvbn JavaScript library by Dan Wheeler:
	/// https://github.com/lowe/zxcvbn</para>
	///
	/// <para>To quickly evaluate a password, use the <see cref="MatchPassword"/> static function.</para>
	///
	/// <para>To evaluate a number of passwords, create an instance of this object and repeatedly call the <see cref="EvaluatePassword"/> function.
	/// Reusing the the Zxcvbn instance will ensure that pattern matchers will only be created once rather than being recreated for each password
	/// e=being evaluated.</para>
	/// </summary>
	TZxcvbn = class
	const
		BruteforcePattern = 'bruteforce';
	private
		FMatcherFactory: IZxcvbnMatcherFactory;
		FLocaleName: string;

		/// <summary>
		/// Returns a new result structure initialised with data for the lowest entropy result of all of the matches passed in, adding brute-force
		/// matches where there are no lesser entropy found pattern matches.
		/// </summary>
		/// <param name="APassword">Password being evaluated</param>
		/// <param name="AMatches">List of matches found against the password</param>
		/// <returns>A result object for the lowest entropy match sequence</returns>
		function FindMinimumEntropyMatch(const APassword: string; AMatches: TList<TZxcvbnMatch>): TZxcvbnResult;

		function GetLongestMatch(const AMatchSequence: TList<TZxcvbnMatch>): TZxcvbnMatch;
		procedure GetMatchFeedback(const AMatch: TZxcvbnMatch; AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string);
	protected
		/// <summary>
		/// Create an instance of Zxcvbn that will use the given matcher factory to create matchers to use
		/// to find password weakness.
		/// </summary>
		/// <param name="AMatcherFactory">The factory used to create the pattern matchers used</param>
		/// <param name="ATranslation">The language in which the strings are returned</param>
		constructor Create(AMatcherFactory: IZxcvbnMatcherFactory); overload;
	public
		/// <summary>
		/// Create a new instance of Zxcvbn with the default matchers.
		/// </summary>
		/// <param name="ADictionariesPath">Path where to look for dictionary files (if not embedded in resources)</param>
		/// <param name="ATranslation">The language in which the strings are returned</param>
		constructor Create; overload;

		/// <summary>
		/// <para>Perform the password matching on the given password and user inputs, returing the result structure with information
		/// on the lowest entropy match found.</para>
		///
		/// <para>User data will be treated as another kind of dictionary matching, but can be different for each password being evaluated.</para>
		/// </summary>
		/// <param name="APassword">Password</param>
		/// <param name="AUserInputs">Optionally, a string list of user data</param>
		/// <returns>Result for lowest entropy match</returns>
		function EvaluatePassword(const APassword: string; AUserInputs: TStrings=nil): TZxcvbnResult;

		/// <summary>
		/// <para>A class function to match a password against the default matchers without having to create
		/// an instance of Zxcvbn yourself, with supplied user data. </para>
		///
		/// <para>Supplied user data will be treated as another kind of dictionary matching.</para>
		/// </summary>
		/// <param name="APassword">the password to test</param>
		/// <param name="ADictionariesPath">optionally, dictionary files path</param>
		/// <param name="AUserInputs">optionally, the user inputs list</param>
		/// <returns>The results of the password evaluation</returns>
		class function MatchPassword(const APassword: string; AUserInputs: TStrings=nil): TZxcvbnResult;

		property LocaleName: string read FLocaleName write FLocaleName;
	end;

	/// <summary>
	/// <para>A single match that one of the pattern matchers has made against the password being tested.</para>
	/// <para>Some pattern matchers implement subclasses of match that can provide more information on their specific results.</para>
	/// <para>Matches must all have the <see cref="Pattern"/>, <see cref="Token"/>, <see cref="Entropy"/>, <see cref="i"/> and
	/// <see cref="j"/> fields (i.e. all but the <see cref="Cardinality"/> field, which is optional) set before being returned from the matcher
	/// in which they are created.</para>
	/// </summary>
	TZxcvbnMatch = class
	private
		function GetGuessesLog10: Real;
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); virtual;
	public
		/// <summary>The name of the pattern matcher used to generate this match (E.g. 'repeat' | 'dictionary' | 'reverse_dictionary' | 'l33t' | 'spatial' | 'sequence' | 'regex' | 'date' )</summary>
		Pattern: string;

		/// <summary>The portion of the password that was matched</summary>
		Token: string;

		/// <summary>The start index in the password string of the matched token.</summary>
		i: Integer; // Start Index

		/// <summary>The end index in the password string of the matched token.</summary>
		j: Integer; // End Index

		/// <summary>The entropy that this portion of the password covers using the current pattern matching technique</summary>
		Entropy: Extended;

		destructor Destroy; override;

		function Clone: TZxcvbnMatch;

		property GuessesLog10: Real read GetGuessesLog10;
	end;

	/// <summary>
	/// A match found by the date matcher
	/// </summary>
	TZxcvbnDateMatch = class(TZxcvbnMatch)
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The detected year</summary>
		year: Integer;

		/// <summary>The detected month</summary>
		month: Integer;

		/// <summary>The detected day</summary>
		day: Integer;

		/// <summary>Where a date with separators is matched, this will contain the separator that was used (e.g. '/', '-')</summary>
		Separator: string;

		destructor Destroy; override;

		procedure CopyTo(AMatch: TZxcvbnDateMatch);
	end;

	/// <summary>
	/// Matches found by the dictionary matcher contain some additional information about the matched word.
	/// </summary>
	TZxcvbnDictionaryMatch = class(TZxcvbnMatch)
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The dictionary word matched</summary>
		MatchedWord: string;

		/// <summary>The rank of the matched word in the dictionary (i.e. 1 is most frequent, and larger numbers are less common words)</summary>
		Rank: Integer;

		/// <summary>The name of the dictionary the matched word was found in</summary>
		DictionaryName: string;

		/// <summary>The base entropy of the match, calculated from frequency rank</summary>
		BaseEntropy: Double;

		/// <summary>Additional entropy for this match from the use of mixed case</summary>
		UppercaseEntropy: Double;

		destructor Destroy; override;

		procedure CopyTo(AMatch: TZxcvbnDictionaryMatch);
	end;

	/// <summary>
	/// A match made with the <see cref="TZxcvbnSpatialMatcher"/>. Contains additional information specific to spatial matches.
	/// </summary>
	TZxcvbnSpatialMatch = class(TZxcvbnMatch)
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The name of the keyboard layout used to make the spatial match</summary>
		Graph: string;

		/// <summary>The number of turns made (i.e. when direction of adjacent keys changes)</summary>
		Turns: Integer;

		/// <summary>The number of shifted characters matched in the pattern (adds to entropy)</summary>
		ShiftedCount: Integer;

		procedure CopyTo(AMatch: TZxcvbnSpatialMatch);
	end;

	/// <summary>A match found with the RepeatMatcher</summary>
	TZxcvbnRepeatMatch = class(TZxcvbnMatch)
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The substring that was repeated</summary>
		BaseToken: string;

		/// <summary>Repeat count</summary>
		RepeatCount: Integer;

		procedure CopyTo(AMatch: TZxcvbnRepeatMatch);
	end;

	/// <summary>A match made using the <see cref="TZxcvbnSequenceMatcher"/> containing some additional sequence information.</summary>
	TZxcvbnSequenceMatch = class(TZxcvbnMatch)
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The name of the sequence that the match was found in (e.g. 'lower', 'upper', 'digits')</summary>
		SequenceName: string;

		/// <summary>The size of the sequence the match was found in (e.g. 26 for lowercase letters)</summary>
		SequenceSize: Integer;

		/// <summary>Whether the match was found in ascending order (cdefg) or not (zyxw)</summary>
		Ascending: Boolean;

		procedure CopyTo(AMatch: TZxcvbnSequenceMatch);
	end;

	/// <summary>
	/// L33tMatcher results are like dictionary match results with some extra information that pertains to the extra entropy that
	/// is garnered by using substitutions.
	/// </summary>
	TZxcvbnL33tMatch = class(TZxcvbnDictionaryMatch)
	private
		FSubs: TDictionary<Char, Char>;
	protected
		procedure GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string); override;
	public
		/// <summary>The extra entropy from using l33t substitutions</summary>
		L33tEntropy: Double;

		/// <summary>Create a new l33t match from a dictionary match</summary>
		/// <param name="dm">The dictionary match to initialise the l33t match from</param>
		constructor Create(ADictionaryMatch: TZxcvbnDictionaryMatch); overload;

		/// <summary>Create an empty l33t match</summary>
		constructor Create; overload;

		destructor Destroy; override;

		/// <summary>The character mappings that are in use for this match</summary>
		property Subs: TDictionary<Char, Char> read FSubs write FSubs;

		procedure CopyTo(AMatch: TZxcvbnL33tMatch);
	end;

	function CompressString(const s: string): string;
	function DecompressString(const s: string): string;

	procedure BuildFrequencyLists(DataPath: string; OutputFilename: string='Zxcvbn_FrequencyLists.inc');


implementation

uses
	System.Math,
	System.Diagnostics,
	System.RegularExpressions,
	System.Types,
	System.StrUtils,
	System.IOUtils,
	Winapi.Windows,
	ZLibEx;


function GetLocaleStrEx(LocaleName: string; LocaleType: Integer; Default: string): string;
var
	cch: Integer;
	buffer: array[0..255] of Char;
begin
	cch := GetLocaleInfoEx(PWideChar(LocaleName), LocaleType, Buffer, Length(Buffer));

	if cch > 0 then
		SetString(Result, Buffer, cch-1)
	else
		Result := Default;
end;

/// <summary>Localize a string into the given locale.
/// If no translation is availble, the original text is returned.
/// </summary>
/// <param name="AMatcher">The text to be localized</param>
/// <param name="LocaleName">The language (e.g. 'fr-CA') to convert text into.</param>
function L(AMatcher: string; LocaleName: string): string;
var
	i: Integer;
	parentLanguage: string;

const
	LOCALE_SNAME   = $0000005c;  { locale name (ie: en-us) }
	LOCALE_SPARENT = $0000006d;  { Fallback name for resources }

	de: array [0..36, 0..1] of string = (
			// Crack times
			('instant',   'unmittelbar'),
			('minutes',   'Minuten'),
			('hours',     'Stunden'),
			('days',      'Tage'),
			('months',    'Monate'),
			('years',     'Jahre'),
			('centuries', 'Jahrhunderte'),

			// Warnings
			('Straight rows of keys are easy to guess', 'Gerade Reihen von Tasten sind leicht zu erraten'),
			('Short keyboard patterns are easy to guess', 'Kurze Tastaturmuster sind leicht zu erraten'),
			('Repeats like "aaa" are easy to guess', 'Wiederholungen wie "aaa" sind leicht zu erraten'),
			('Repeats like "abcabcabc" are only slightly harder to guess than "abc"', 'Wiederholungen wie "abcabcabc" sind nur etwas schwerer zu erraten als "abc"'),
			('Sequences like abc or 6543 are easy to guess', 'Sequenzen wie abc oder 6543 sind leicht zu erraten'),
			('Recent years are easy to guess', 'Die letzten Jahre sind leicht zu erraten'),
			('Dates are often easy to guess', 'Termine sind oft leicht zu erraten'),
			('This is a top-10 common password', 'Dies ist ein Top-10-Passwort'),
			('This is a top-100 common password', 'Dies ist ein Top-100-Passwort'),
			('This is a very common password', 'Dies ist ein sehr häufiges Passwort'),
			('This is similar to a commonly used password', 'Dies ähnelt einem häufig verwendeten Passwort'),
			('A word by itself is easy to guess', 'Ein Wort an sich ist leicht zu erraten'),
			('Names and surnames by themselves are easy to guess', 'Namen und Familiennamen sind leicht zu erraten'),
			('Common names and surnames are easy to guess', 'Allgemeine Namen und Nachnamen sind leicht zu erraten'),

			// Suggestions
			('Add another word or two. Uncommon words are better.', 'Fügen Sie ein oder zwei weitere Wörter hinzu. Ungewöhnliche Wörter sind besser.'),
			('Use a longer keyboard pattern with more turns', 'Verwenden Sie ein längeres Tastaturmuster mit mehr Drehungen'),
			('Avoid repeated words and characters', 'Vermeiden Sie wiederholte Wörter und Zeichen'),
			('Avoid sequences', 'Vermeiden Sie Sequenzen'),
			('Avoid recent years ' + #10 + ' Avoid years that are associated with you', 'Vermeide die letzten Jahre' + #10 + 'Vermeiden Sie Jahre, die mit Ihnen verbunden sind'),
			('Avoid dates and years that are associated with you', 'Vermeiden Sie Daten und Jahre, die mit Ihnen verbunden sind'),
			('Capitalization doesn''t help very much', 'Die Großschreibung hilft nicht sehr'),
			('All-uppercase is almost as easy to guess as all-lowercase', 'Großbuchstaben sind fast so einfach zu erraten wie Kleinbuchstaben'),
			('Reversed words aren''t much harder to guess', 'Umgekehrte Wörter sind nicht viel schwerer zu erraten'),
			('Predictable substitutions like "@" instead of "a" don''t help very much', 'Vorhersehbare Substitutionen wie "@" anstelle von "a" helfen nicht sehr'),
			('Use a few words, avoid common phrases ' + #10 + ' No need for symbols, digits, or uppercase letters', 'Verwenden Sie ein paar Wörter, vermeiden Sie häufige Phrasen' + #10 + 'Keine Notwendigkeit für Symbole, Ziffern oder Großbuchstaben'),

			//Score
			('Too guessable; risky password.', 'Zu erraten; riskantes Passwort.'),
			('Very guessable; protection from throttled online attacks.', 'Sehr erraten; Schutz vor gedrosselten Online-Angriffen.'),
			('Somewhat guessable; protection from unthrottled online attacks.', 'Etwas zu erraten; Schutz vor ungedrosselten Online-Angriffen.'),
			('Safely unguessable; moderate protection from offline slow-hash scenario.', 'Sicher unbegreifbar; Moderater Schutz vor Offline-Slow-Hash-Szenario.'),
			('Very unguessable; strong protection from offline slow-hash scenario.', 'Sehr unbegreiflich; starker Schutz vor Offline-Slow-Hash-Szenario.')
	);


	fr: array [0..36, 0..1] of string = (
			// Crack times
			('instant',   'instantané'),
			('minutes',   'Minutes'),
			('hours',     'Heures'),
			('days',      'Journées'),
			('months',    'mois'),
			('years',     'Ans'),
			('centuries', 'Siècles'),

			// Warnings
			('Straight rows of keys are easy to guess', 'Des rangées droites de touches sont faciles à deviner'),
			('Short keyboard patterns are easy to guess', 'Les raccourcis clavier sont faciles à deviner'),
			('Repeats like "aaa" are easy to guess', 'Des répétitions comme "aaa" sont faciles à deviner'),
			('Repeats like "abcabcabc" are only slightly harder to guess than "abc"', 'Les répétitions comme "abcabcabc" ne sont que légèrement plus difficiles à deviner que "abc"'),
			('Sequences like abc or 6543 are easy to guess', 'Des séquences comme abc ou 6543 sont faciles à deviner'),
			('Recent years are easy to guess', 'Les dernières années sont faciles à deviner'),
			('Dates are often easy to guess', 'Les dates sont souvent faciles à deviner'),
			('This is a top-10 common password', 'Ceci est un mot de passe commun top-10'),
			('This is a top-100 common password', 'Ceci est un mot de passe commun parmi les 100 premiers'),
			('This is a very common password', 'Ceci est un mot de passe très courant'),
			('This is similar to a commonly used password', 'Ceci est similaire à un mot de passe couramment utilisé'),
			('A word by itself is easy to guess', 'Un mot en soi est facile à deviner'),
			('Names and surnames by themselves are easy to guess', 'Les noms et prénoms sont faciles à deviner'),
			('Common names and surnames are easy to guess', 'Les noms et prénoms communs sont faciles à deviner'),

			('Add another word or two. Uncommon words are better.', 'Ajouter un autre mot ou deux. Les mots peu communs sont meilleurs.'),
			('Use a longer keyboard pattern with more turns', 'Utilisez un modèle de clavier plus long avec plus de tours'),
			('Avoid repeated words and characters', 'Évitez les mots et les caractères répétés'),
			('Avoid sequences', 'asdfaÉviter les séquencessdf'),
			('Avoid recent years ' + #10 + ' Avoid years that are associated with you', 'Éviter les dernières années' + #13#10 + 'Évitez les années qui vous sont associées'),
			('Avoid dates and years that are associated with you', 'Évitez les dates et les années qui vous sont associées'),
			('Capitalization doesn''t help very much', 'La capitalisation n''aide pas beaucoup'),
			('All-uppercase is almost as easy to guess as all-lowercase', 'Les majuscules sont presque aussi faciles à deviner que les minuscules'),
			('Reversed words aren''t much harder to guess', 'Les mots inversés ne sont pas beaucoup plus difficiles à deviner'),
			('Predictable substitutions like "@" instead of "a" don''t help very much', 'Les substitutions prévisibles comme "@" au lieu de "a" n''aident pas beaucoup'),
			('Use a few words, avoid common phrases ' + #10 + ' No need for symbols, digits, or uppercase letters', 'Utilisez quelques mots, évitez les phrases courantes' + #13#10 + 'Pas besoin de symboles, de chiffres ou de lettres majuscules'),

			//Score
			('Too guessable; risky password.', 'Trop devinable; mot de passe risqué.'),
			('Very guessable; protection from throttled online attacks.', 'Très devinable; protection contre les attaques en ligne étranglées.'),
			('Somewhat guessable; protection from unthrottled online attacks.', 'Un peu devinable protection contre les attaques en ligne sans restriction.'),
			('Safely unguessable; moderate protection from offline slow-hash scenario.', 'Sûrement impénétrable protection modérée contre le scénario de hachage lent hors ligne.'),
			('Very unguessable; strong protection from offline slow-hash scenario.', 'Très impénétrable forte protection contre le scénario de hachage lent hors ligne.')
	);

begin
	Result := AMatcher;

	if AMatcher = '' then
		Exit;

	if LocaleName = '' then
		LocaleName := GetLocaleStr(LOCALE_USER_DEFAULT, LOCALE_SNAME, 'en-US');

	{
		Languages have many variants:

		 - German:  de-AT, de-CH, de-DE, de-LI, de-LU
		 - French:  fr-BE, fr-CA, fr-CD, fr-CH, fr-CI, fr-CM, fr-FR, fr-HT, fr-LU, fr-MA, fr-MC, fr-ML, fr-RE, fr-SN, fr-029 (029 = Caribbean)
		 - English: en-AU, en-BZ, en-CA, en-GB, en-HK, en-ID, en-IE, en-IN, en-JM, en-MY, en-NZ, en-PH, en-SG, en-TT, en-US, en-ZA, en-ZW, en-029 (029 = Caribbean)

		Nobody will ever add any other languages to this Zxcvbn implementation.
		And they certainly won't add different sub-variants of German, French, or English. (e.g. "fr-CA" as opposed to "fR-FR")

		So we're safe simply falling back parent language of the locale:

			de-DE --> de (Deutsch)
			fr-FR --> fr (Français)
			fr-CA --> fr (Français)
			en-US --> en (English)
			en-GB --> en (English)
			en-CA --> en (English)
	}
	parentLanguage := GetLocaleStrEx(LocaleName, LOCALE_SPARENT, 'en');

	if SameText(parentLanguage, 'de') then
	begin
		for i := Low(de) to High(de) do
		begin
			if SameText(de[i, 0], AMatcher) then
			begin
				Result := de[i, 1];
				Exit;
			end;
		end;
		if IsDebuggerPresent then
			OutputDebugString(PChar('No '+parentLanguage+' translaction for "' + AMatcher + '"'));
	end
	else if SameText(parentLanguage, 'fr') then
	begin
		for i := Low(fr) to High(fr) do
		begin
			if SameText(fr[i, 0], AMatcher) then
			begin
				Result := fr[i, 1];
				Exit;
			end;
		end;
		if IsDebuggerPresent then
			OutputDebugString(PChar('No '+parentLanguage+' translaction for "' + AMatcher + '"'));
	end;
end;

function DisplayTime(ASeconds: Real; LocaleName: string): string;
const
	minute  = 60;
	hour    = minute * 60;
	day     = hour * 24;
	year    = day * 365.2425;
	month   = year / 12;
	century = year * 100;
begin
	if (ASeconds < minute) then
		Result := L('instant', LocaleName)
	else if (ASeconds < hour) then
		Result := Format('%d %s', [1 + Ceil(ASeconds / minute), L('minutes', LocaleName)])
	else if (ASeconds < day) then
		Result := Format('%d %s', [1 + Ceil(ASeconds / hour), L('hours', LocaleName)])
	else if (ASeconds < month) then
		Result := Format('%d %s', [1 + Ceil(ASeconds / day), L('days', LocaleName)])
	else if (ASeconds < year) then
		Result := Format('%d %s', [1 + Ceil(ASeconds / month), L('months', LocaleName)])
	else if (ASeconds < century) then
		Result := Format('%d %s', [1 + Ceil(ASeconds / year), L('years', LocaleName)])
	else
		Result := L('centuries', LocaleName);
end;

function StringReverse(const AStr: string): string;
begin
	Result := System.StrUtils.ReverseString(AStr);
end;

function IntParseSubstring(const AStr: string; AStartIndex, ALength: Integer; out AResult: Integer): Boolean;
begin
	Result := TryStrToInt(AStr.Substring(AStartIndex, ALength), AResult);
end;

function ToInt(const AStr: string): Integer;
var
	r: Integer;
begin
	r := 0;
	TryStrToInt(AStr, r);
	Result := r;
end;

function GetEmbeddedResourceLines(AResourceName: string): TStringList;
var
	rs: TResourceStream;
	lines: TStringList;
begin
	Result := nil;

	if (FindResource(hInstance, PChar(AResourceName), RT_RCDATA) = 0) then
		Exit;

	rs := TResourceStream.Create(hInstance, AResourceName, RT_RCDATA);
	try
		lines := TStringList.Create;
		lines.LoadFromStream(rs);
		Result := lines;
	finally
		rs.Free;
	end;
end;

function GetCompressedWordList(ADictionaryName: string): TStrings;
var
	comp: string;
	sl: TStrings;
{$INCLUDE Zxcvbn_FrequencyLists.inc}
{
const
	Senglish_wikipedia	= '[base85 compressed lf separated words]';
	Sfemale_names			= '[base85 compressed lf separated words]';
	Smale_names				= '[base85 compressed lf separated words]';
	Spasswords				= '[base85 compressed lf separated words]';
	Ssurnames				= '[base85 compressed lf separated words]';
	Sus_tv_and_film		= '[base85 compressed lf separated words]';
}

begin
	Result := nil;
	comp := '';

{$IFDEF zxcvbn-fl}
	if SameText(ADictionaryName, 'us_tv_and_film') then
		comp := Sus_tv_and_film
	else if SameText(ADictionaryName, 'english_wikipedia') then
		comp := Senglish_wikipedia
	else if SameText(ADictionaryName, 'passwords') then
		comp := Spasswords
	else if SameText(ADictionaryName, 'surnames') then
		comp := Ssurnames
	else if SameText(ADictionaryName, 'male_names') then
		comp := Smale_names
	else if SameText(ADictionaryName, 'female_names') then
		comp := Sfemale_names
	else
		Exit;
{$ENDIF}


	comp := DecompressString(comp);
	if comp = '' then
		Exit;

	sl := TStringList.Create;
	sl.Text := comp;

	Result := sl;
end;

procedure BurnString(var s: UnicodeString);
begin
	if Length(s) > 0 then
	begin
		{$IFDEF UNICODE}
		{
			In Delphi 5 (and really anything before XE2), UnicodeString is an alias for WideString.
			WideString does not have, or does it need, an RTL UniqueString function.
		}
		UniqueString({var}s); //We can't FillChar the string if it's shared, or its in the constant data page
		{$ENDIF}
		FillChar(s[1], Length(s), 0);
		s := '';
	end;
end;

type
	/// <summary>Warning associated with the password analysis</summary>
	TZxcvbnWarning = (
			/// <summary>Empty string</summary>
			zwDefault,

			/// <summary>Straight rows of keys are easy to guess</summary>
			zwStraightRow,

			/// <summary>Short keyboard patterns are easy to guess</summary>
			zwShortKeyboardPatterns,

			/// <summary>Repeats like "aaa" are easy to guess</summary>
			zwRepeatsLikeAaaEasy,

			/// <summary> Repeats like "abcabcabc" are only slightly harder to guess than "abc" </summary>
			zwRepeatsLikeAbcSlighterHarder,

			/// <summary>Sequences like abc or 6543 are easy to guess</summary>
			zwSequenceAbcEasy,

			/// <summary>Recent years are easy to guess</summary>
			zwRecentYearsEasy,

			/// <summary>Dates are often easy to guess</summary>
			zwDatesEasy,

			/// <summary>This is a top-10 common password</summary>
			zwTop10Passwords,

			/// <summary>This is a top-100 common password</summary>
			zwTop100Passwords,

			/// <summary>This is a very common password</summary>
			zwCommonPasswords,

			/// <summary>This is similar to a commonly used password</summary>
			zwSimilarCommonPasswords,

			/// <summary>A word by itself is easy to guess</summary>
			zwWordEasy,

			/// <summary>Names and surnames by themselves are easy to guess</summary>
			zwNameSurnamesEasy,

			/// <summary>Common names and surnames are easy to guess</summary>
			zwCommonNameSurnamesEasy,

			/// <summary>Empty string</summary>
			zwEmpty
	);

function GetWarning(AWarning: TZxcvbnWarning; LocaleName: string): string;
var
	s: string;
const
	SWarnings: array [TZxcvbnWarning] of string = (
			'', // zwDefault
			'Straight rows of keys are easy to guess',	// zwStraightRow
			'Short keyboard patterns are easy to guess',	// zwShortKeyboardPatterns
			'Repeats like "aaa" are easy to guess',	// zwRepeatsLikeAaaEasy
			'Repeats like "abcabcabc" are only slightly harder to guess than "abc"',	// zwRepeatsLikeAbcSlighterHarder
			'Sequences like abc or 6543 are easy to guess',	// zwSequenceAbcEasy
			'Recent years are easy to guess',	// zwRecentYearsEasy
			'Dates are often easy to guess',	// zwDatesEasy
			'This is a top-10 common password',	// zwTop10Passwords
			'This is a top-100 common password',	// zwTop100Passwords
			'This is a very common password',	// zwCommonPasswords
			'This is similar to a commonly used password',	// zwSimilarCommonPasswords
			'A word by itself is easy to guess',	// zwWordEasy
			'Names and surnames by themselves are easy to guess',	// zwNameSurnamesEasy
			'Common names and surnames are easy to guess',	// zwCommonNameSurnamesEasy
			'' // zwEmpty
	);
begin
	s := SWarnings[AWarning];

	Result := L(s, LocaleName);
end;

type
	/// <summary>Suggestion on how to improve the password base on zxcvbn's password analysis</summary>
	TZxcvbnSuggestion = (
			/// <summary>Use a few words, avoid common phrases. No need for symbols, digits, or uppercase letters</summary>
			zsDefault,

			/// <summary>Add another word or two. Uncommon words are better.</summary>
			zsAddAnotherWordOrTwo,

			/// <summary>Use a longer keyboard pattern with more turns</summary>
			zsUseLongerKeyboardPattern,

			/// <summary>Avoid repeated words and characters</summary>
			zsAvoidRepeatedWordsAndChars,

			/// <summary>Avoid sequences</summary>
			zsAvoidSequences,

			/// <summary>Avoid recent years. Avoid years that are associated with you.</summary>
			zsAvoidYearsAssociatedYou,

			/// <summary>Avoid dates and years that are associated with you</summary>
			zsAvoidDatesYearsAssociatedYou,

			/// <summary>Capitalization doesn't help very much</summary>
			zsCapsDontHelp,

			/// <summary>All-uppercase is almost as easy to guess as all-lowercase</summary>
			zsAllCapsEasy,

			/// <summary>Reversed words aren't much harder to guess</summary>
			zsReversedWordEasy,

			/// <summary>Predictable substitutions like '@' instead of 'a' don't help very much</summary>
			zsPredictableSubstitutionsEasy,

			/// <summary>Empty string</summary>
			zsEmpty
	);
	TZxcvbnSuggestions = set of TZxcvbnSuggestion;

function GetSuggestion(ASuggestion: TZxcvbnSuggestion; LocaleName: string): string;
var
	s: string;
const
	SSuggestionName: array [TZxcvbnSuggestion] of string = (
			'Use a few words, avoid common phrases ' + #10 + ' No need for symbols, digits, or uppercase letters', // zsDefault
			'Add another word or two. Uncommon words are better.', // zsAddAnotherWordOrTwo
			'Use a longer keyboard pattern with more turns', // zsUseLongerKeyboardPattern
			'Avoid repeated words and characters', // zsAvoidRepeatedWordsAndChars
			'Avoid sequences', // zsAvoidSequences
			'Avoid recent years ' + #10 + ' Avoid years that are associated with you', // zsAvoidYearsAssociatedYou
			'Avoid dates and years that are associated with you', // zsAvoidDatesYearsAssociatedYou
			'Capitalization doesn''t help very much', // zsCapsDontHelp
			'All-uppercase is almost as easy to guess as all-lowercase', // zsAllCapsEasy
			'Reversed words aren''t much harder to guess', // zsReversedWordEasy
			'Predictable substitutions like "@" instead of "a" don''t help very much', // zsPredictableSubstitutionsEasy
			'' // zsEmpty
	);

begin
	s := SSuggestionName[ASuggestion];
	Result := L(s, LocaleName);
end;

function GetSuggestions(ASuggestions: TZxcvbnSuggestions; LocaleName: string): string;
var
	suggestion: TZxcvbnSuggestion;
	suggestions: string;
	s: string;
begin
	suggestions := '';
	for suggestion in ASuggestions do
	begin
		s := GetSuggestion(suggestion, LocaleName);
		if s = '' then
			Continue;

		if suggestions <> '' then
			suggestions := suggestions + #13#10;
		suggestions := suggestions + '- ' + s;
	end;

	Result := suggestions;
end;

function GetScoreText(AScore: Integer; LocaleName: string): string;
begin
	Result := '';

	case AScore of
	0: Result := 'Too guessable; risky password.';
	1: Result := 'Very guessable; protection from throttled online attacks.';
	2: Result := 'Somewhat guessable; protection from unthrottled online attacks.';
	3: Result := 'Safely unguessable; moderate protection from offline slow-hash scenario.';
	4: Result := 'Very unguessable; strong protection from offline slow-hash scenario.';
	end;

	Result := L(Result, LocaleName);
end;

const
	StartUpper = '^[A-Z][^A-Z]+$';
	EndUpper   = '^[^A-Z]+[A-Z]$';
	AllUpper   = '^[^a-z]+$';
	AllLower   = '^[^A-Z]+$';

/// <summary>
/// Calculate the cardinality of the minimal character sets necessary to brute force the password (roughly)
/// (e.g. lowercase = 26, numbers = 10, lowercase + numbers = 36)
/// </summary>
/// <param name="password">THe password to evaluate</param>
/// <returns>An estimation of the cardinality of charactes for this password</returns>
function PasswordCardinality(const APassword: string): Integer;
var
	cl: Integer;
	i: Integer;
	c: Char;
	charType: Integer;
begin
{
	charType is bitwise flags of what kinds of characters the password contains:

		1: lower
		2: uppercase
		4: numbers
		8: symbols
		16: unicode
}
	charType := 0;

	for i := 1 to APassword.Length do
	begin
		c := APassword[i];
		if CharInSet(c, ['a' .. 'z']) then
			charType := charType or 1 // Lowercase
		else if CharInSet(c, ['A' .. 'Z']) then
			charType := charType or 2 // Uppercase
		else if CharInSet(c, ['0' .. '9']) then
			charType := charType or 4 // Numbers
		else if (c <= '/') or ((':' <= c) and (c <= '@')) or (('[' <= c) and (c <= '`')) or (('{' <= c) and (Ord(c) <= $7F)) then
			charType := charType or 8 // Symbols
		else if Ord(c) > $7F then
			charType := charType or 16; // 'Unicode'
	end;

	// cl is the approximiate number of characters the password draws from
	cl := 0;
	if (charType and 1) = 1 then
		cl := cl + 26;
	if (charType and 2) = 2 then
		cl := cl + 26;
	if (charType and 4) = 4 then
		cl := cl + 10;
	if (charType and 8) = 8 then
		cl := cl + 33;
	if (charType and 16) = 16 then
		cl := cl + 100;

	Result := cl;
end;

/// <summary>
/// Return a score for password strength from the crack time. Scores are 0..4, 0 being minimum and 4 maximum strength.
/// </summary>
/// <param name="crackTimeSeconds">Number of seconds estimated for password cracking</param>
/// <returns> Password strength. 0 to 4, 0 is minimum </returns>
function EntropyToScore(Entropy: Real): Integer;
var
	guesses: Real;
begin
	{
	  Integer from 0-4 (useful for implementing a strength bar)

	  0 # too guessable: risky password. (guesses < 10^3)
	  1 # very guessable: protection from throttled online attacks. (guesses < 10^6)
	  2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
	  3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
	  4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
	}

	guesses := 0.5 * Power(2, Entropy);

	if (guesses < 10E3) then
		Result := 0
	else if (guesses < 10E6) then
		Result := 1
	else if (guesses < 10E8) then
		Result := 2
	else if (guesses < 10E10) then
		Result := 3
	else
		Result := 4;
end;

/// <summary>
/// Caclulate binomial coefficient (i.e. nCk)
/// Uses same algorithm as zxcvbn (cf. scoring.coffee), from http://blog.plover.com/math/choose.html
/// </summary>
/// <param name="k">k</param>
/// <param name="n">n</param>
/// <returns>Binomial coefficient; nCk</returns>
function Binomial(n, k: Integer): Integer;
var
	d: Integer;
begin
	if k > n then
	begin
		Result := 0;
		Exit;
	end;
	if k = 0 then
	begin
		Result := 1;
		Exit;
	end;

	if k > n - k then
		k := n - k;
	Result := 1;
	d := 0;
	while d < k do
	begin
		Result := Result * (n - d);
		Inc(d);
		Result := Result div d;
	end;
end;

/// <summary>
/// Estimate the extra entropy in a token that comes from mixing upper and lowercase letters.
/// This has been moved to a static function so that it can be used in multiple entropy calculations.
/// </summary>
/// <param name="word">The word to calculate uppercase entropy for</param>
/// <returns>An estimation of the entropy gained from casing in <paramref name="word"/></returns>
function CalculateUppercaseEntropy(AWord: string): Double;
var
	lowers, uppers: Integer;
	i: Integer;
	sum: Double;
begin
	Result := 0;
	if TRegEx.IsMatch(AWord, AllLower) then
		Exit;

	// If the word is all uppercase add's only one bit of entropy, add only one bit for initial/end single cap only
	if TRegEx.IsMatch(AWord, StartUpper) or TRegEx.IsMatch(AWord, EndUpper) or TRegEx.IsMatch(AWord, AllUpper) then
	begin
		Result := 1;
		Exit;
	end;

	lowers := 0;
	uppers := 0;
	for i := 1 to AWord.Length do
	begin
		if CharInSet(AWord[i], ['a' .. 'z']) then
			Inc(lowers)
		else if CharInSet(AWord[i], ['A' .. 'Z']) then
			Inc(uppers);
	end;

	// Calculate numer of ways to capitalise (or inverse if there are fewer lowercase chars) and return lg for entropy
	sum := 0;
	for i := 0 to Min(uppers, lowers) do
		sum := sum + Binomial(uppers + lowers, i);

	Result := LogN(2, sum);
end;

type
	/// <summary>
	/// <para>This matcher reads in a list of words (in frequency order) and matches substrings of the password against that dictionary.</para>
	///
	/// <para>The dictionary to be used can be specified directly by passing an enumerable of strings through the constructor (e.g. for
	/// matching agains user inputs). Most dictionaries will be in word list files.</para>
	///
	/// <para>Using external files is a departure from the JS version of Zxcvbn which bakes in the word lists, so the default dictionaries
	/// have been included in the Zxcvbn assembly as embedded resources (to remove the external dependency). Thus when a word list is specified
	/// by name, it is first checked to see if it matches and embedded resource and if not is assumed to be an external file. </para>
	///
	/// <para>Thus custom dictionaries can be included by providing the name of an external text file, but the built-in dictionaries (english.lst,
	/// female_names.lst, male_names.lst, passwords.lst, surnames.lst) can be used without concern about locating a dictionary file in an accessible
	/// place.</para>
	///
	/// <para>Dictionary word lists must be in decreasing frequency order and contain one word per line with no additional information.</para>
	/// </summary>
	TZxcvbnDictionaryMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	const
		DictionaryPattern = 'dictionary';
	private
		FDictionaryName: string;
		FRankedDictionary: TDictionary<string, Integer>;

		procedure CalculateEntropyForMatch(AMatch: TZxcvbnDictionaryMatch);
		function BuildRankedDictionary(AWordListFile: string): TDictionary<string, Integer>; overload;
		function BuildRankedDictionary(AWordList: TStrings): TDictionary<string, Integer>; overload;
	public
		/// <summary>
		/// Creates a new dictionary matcher. <paramref name="AWordListPath"/> must be the path (relative or absolute) to a file containing one word per line,
		/// entirely in lowercase, ordered by frequency (decreasing); or <paramref name="AWordListPath"/> must be the name of a built-in dictionary.
		/// </summary>
		/// <param name="AName">The name provided to the dictionary used</param>
		/// <param name="AWordListPath">The filename of the dictionary (full or relative path) or name of built-in dictionary</param>
		constructor Create(AName: string; AWordListPath: string); overload;

		/// <summary>
		/// Creates a new dictionary matcher from the passed in word list. If there is any frequency order then they should be in
		/// decreasing frequency order.
		/// </summary>
		constructor Create(AName: string; AWordList: TStrings); overload;

		destructor Destroy; override;

		/// <summary>
		/// Match substrings of password agains the loaded dictionary. Adds dictionary matches to AMatches
		/// </summary>
		/// <param name="APassword">The password to match</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="TZxcvbnDictionaryMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;

	/// <summary>
	/// This matcher applies some known l33t character substitutions and then attempts to match against passed in dictionary matchers.
	/// This detects passwords like 4pple which has a '4' substituted for an 'a'
	/// </summary>
	TZxcvbnL33tMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	private
		FDictionaryMatchers: TList<IZxcvbnMatcher>;

		FSubstitutions: TDictionary<Char, string>;

		procedure CalculateL33tEntropy(AMatch: TZxcvbnL33tMatch);

		function TranslateString(ACharMap: TDictionary<Char, Char>; AStr: string): string;

		function EnumerateSubtitutions(ATable: TDictionary<Char, string>): TList<TDictionary<Char, Char>>;

		function BuildSubstitutionsMap: TDictionary<Char, string>;
	public
		/// <summary>
		/// Create a l33t matcher that applies substitutions and then matches agains the passed in list of dictionary matchers.
		/// </summary>
		/// <param name="ADictionaryMatchers">The list of dictionary matchers to check transformed passwords against</param>
		constructor Create(const ADictionaryMatchers: TList<IZxcvbnMatcher>); overload;

		/// <summary>
		/// Create a l33t matcher that applies substitutions and then matches agains a single dictionary matcher.
		/// </summary>
		/// <param name="ADictionaryMatcher">The dictionary matcher to check transformed passwords against</param>
		constructor Create(const ADictionaryMatcher: IZxcvbnMatcher); overload;

		destructor Destroy; override;

		/// <summary>
		/// Apply applicable l33t transformations and check <paramref name="APassword"/> against the dictionaries.
		/// </summary>
		/// <param name="APassword">The password to check</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="TZxcvbnL33tMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;

	TZxcvbnSplitsArr = array [0 .. 1] of Integer;

	TZxcvbnDmy = record
		valid: Boolean;
		day: Integer;
		month: Integer;
		year: Integer;
	end;

	TZxcvbnDm = record
		valid: Boolean;
		day: Integer;
		month: Integer;
	end;

	/// <summary>
	/// <para>This matcher attempts to guess dates, with and without date separators. E.g. 1197 (could be 1/1/97) through to 18/12/2015.</para>
	///
	/// <para>The format for matching dates is quite particular, and only detected years in the range 00-99 and 1000-2050 are considered by
	/// this matcher.</para>
	/// </summary>
	TZxcvbnDateMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	const
		DatePattern = 'date';
	private
		FDateSplits: TDictionary<Integer, TArray<TZxcvbnSplitsArr>>;
		function CalculateEntropy(AMatch: TZxcvbnDateMatch): Double;

		function MapIntsToDmy(AIntegers: TList<Integer>): TZxcvbnDmy;
		function MapIntsToDm(AIntegers: TList<Integer>): TZxcvbnDm;
		function TwoToFourDigitYear(AYear: Integer): Integer;

		function Metric(ACandidate: TZxcvbnDmy): Integer;
	public
		/// <summary>
		/// Find date matches in <paramref name="APassword"/> and adds them to <paramref name="AMatches"/>
		/// </summary>
		/// <param name="APassword">The passsword to check</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="TZxcvbnDateMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);

		constructor Create;
		destructor Destroy; override;
	end;

	/// <summary>
	/// <para>This matcher factory will use all of the default password matchers.</para>
	///
	/// <para>Default dictionary matchers use the built-in word lists: passwords, english, male_names, female_names, surnames</para>
	/// <para>Also matching against: user data, all dictionaries with l33t substitutions</para>
	/// <para>Other default matchers: repeats, sequences, digits, years, dates, spatial</para>
	///
	/// <para>See <see cref="Zxcvbn.Matcher.IZxcvbnMatcher"/> and the classes that implement it for more information on each kind of pattern matcher.</para>
	/// </summary>
	TZxcvbnDefaultMatcherFactory = class(TInterfacedObject, IZxcvbnMatcherFactory)
	private
		FMatchers: TList<IZxcvbnMatcher>;
		FCustomMatchers: TList<IZxcvbnMatcher>;
	public
		/// <summary>Create a matcher factory that uses the default list of pattern matchers</summary>
		constructor Create;
		destructor Destroy; override;

		/// <summary>
		/// Get instances of pattern matchers, adding in per-password matchers on userInputs (and userInputs with l33t substitutions)
		/// </summary>
		/// <param name="AUserInputs">string list of user information</param>
		/// <returns>List of matchers to use</returns>
		function CreateMatchers(const AUserInputs: TStrings): TList<IZxcvbnMatcher>;
	end;

type
	TZxcvbnPoint = record
		x: Integer;
		y: Integer;
		procedure ZxcvbnPoint(Ax, Ay: Integer);
		function ToString: string;
	end;

	TZxcvbnPoints = array of TZxcvbnPoint;

	// See build_keyboard_adjacency_graph.py in zxcvbn for how these are generated
	TZxcvbnSpatialGraph = class
	private
		FName: string;
		FAdjacencyGraph: TObjectDictionary<Char, TStringList>;
		FStartingPositions: Integer;
		FAverageDegree: Double;

		function GetSlantedAdjacent(Ac: TZxcvbnPoint): TZxcvbnPoints;
		function GetAlignedAdjacent(Ac: TZxcvbnPoint): TZxcvbnPoints;
		procedure BuildGraph(ALayout: string; ASlanted: Boolean; ATokenSize: Integer);
	public
		constructor Create(AName: string; ALayout: string; ASlanted: Boolean; ATokenSize: Integer);
		destructor Destroy; override;

		/// <summary>
		/// Returns true when ATestAdjacent is in Ac's adjacency list
		/// </summary>
		function IsCharAdjacent(Ac: Char; ATestAdjacent: Char): Boolean;

		/// <summary>
		/// Returns the 'direction' of the adjacent character (i.e. index in the adjacency list).
		/// If the character is not adjacent, -1 is returned
		///
		/// Uses the 'shifted' out parameter to let the caller know if the matched character is shifted
		/// </summary>
		function GetAdjacentCharDirection(Ac: Char; AAdjacent: Char; out AShifted: Boolean): Integer;

		/// <summary>
		/// Calculate entropy for a math that was found on this adjacency graph
		/// </summary>
		function CalculateEntropy(AMatchLength: Integer; ATurns: Integer; AShiftedCount: Integer): Double;

		property Name: string read FName;
		property StartingPositions: Integer read FStartingPositions;
		property AverageDegree: Double read FAverageDegree;
	end;

	/// <summary>
	/// <para>A matcher that checks for keyboard layout patterns (e.g. 78523 on a keypad, or plkmn on a QWERTY keyboard).</para>
	/// <para>Has patterns for QWERTY, DVORAK, numeric keybad and mac numeric keypad</para>
	/// <para>The matcher accounts for shifted characters (e.g. qwErt or po9*7y) when detecting patterns as well as multiple changes in direction.</para>
	/// </summary>
	TZxcvbnSpatialMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	const
		SpatialPattern = 'spatial';
	private
		FSpatialGraphs: TObjectList<TZxcvbnSpatialGraph>;

		/// <summary>
		/// Match the password against a single pattern and adds matching patterns to AMatches
		/// </summary>
		/// <param name="AGraph">Adjacency graph for this key layout</param>
		/// <param name="APassword">Password to match</param>
		/// <param name="AMatches"></param>
		procedure SpatialMatch(AGraph: TZxcvbnSpatialGraph; const APassword: string; var AMatches: TList<TZxcvbnMatch>);

		// In the JS version these are precomputed, but for now we'll generate them here when they are first needed.
		function GenerateSpatialGraphs: TObjectList<TZxcvbnSpatialGraph>;
	public
		constructor Create;
		destructor Destroy; override;

		/// <summary>
		/// Match the password against the known keyboard layouts and adds matches to AMatches
		/// </summary>
		/// <param name="APassword">Password to match</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="TZxcvbnSpatialMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;


	/// <summary>
	/// Match repeated characters in the password (repeats must be more than two characters long to count)
	/// </summary>
	TZxcvbnRepeatMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	const
		RepeatPattern = 'repeat';
	private
		function CalculateEntropy(AMatch: TZxcvbnRepeatMatch): Double;
	public
		/// <summary>
		/// Find repeat matches in <paramref name="APassword"/> and adds them to <paramref name="AMatches"/>
		/// </summary>
		/// <param name="APassword">The password to check</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="TZxcvbnRepeatMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;

type
	/// <summary>
	/// <para>Use a regular expression to match agains the password. (e.g. 'year' and 'digits' pattern matchers are implemented with this matcher.</para>
	/// <para>A note about cardinality: the cardinality parameter is used to calculate the entropy of matches found with the regex matcher. Since
	/// this cannot be calculated automatically from the regex pattern it must be provided. It can be provided per-character or per-match. Per-match will
	/// result in every match having the same entropy (lg cardinality) whereas per-character will depend on the match length (lg cardinality ^ length)</para>
	/// </summary>
	TZxcvbnRegexMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	private
		FMatchRegex: TRegEx;
		FMatcherName: string;
		FCardinality: Integer;
		FPerCharCardinality: Boolean;
	public
		/// <summary>
		/// Create a new regex pattern matcher
		/// </summary>
		/// <param name="APattern">The regex pattern to match</param>
		/// <param name="ACardinality">The cardinality of this match. Since this cannot be calculated from a pattern it must be provided. Can
		/// be give per-matched-character or per-match</param>
		/// <param name="APerCharCardinality">True if cardinality is given as per-matched-character</param>
		/// <param name="AMatcherName">The name to give this matcher ('pattern' in resulting matches)</param>
		constructor Create(APattern: string; ACardinality: Integer; APerCharCardinality: Boolean = True; AMatcherName: string = 'regex'); overload;

		/// <summary>
		/// Create a new regex pattern matcher
		/// </summary>
		/// <param name="AMatchRegex">The regex object used to perform matching</param>
		/// <param name="ACardinality">The cardinality of this match. Since this cannot be calculated from a pattern it must be provided. Can
		/// be give per-matched-character or per-match</param>
		/// <param name="APerCharCardinality">True if cardinality is given as per-matched-character</param>
		/// <param name="AMatcherName">The name to give this matcher ('pattern' in resulting matches)</param>
		constructor Create(AMatchRegex: TRegEx; ACardinality: Integer; APerCharCardinality: Boolean = True; AMatcherName: string = 'regex'); overload;

		/// <summary>
		/// Find all matches of the regex in <paramref name="APassword"/> and adds them to <paramref name="AMatches"/> list
		/// </summary>
		/// <param name="APassword">The password to check</param>
		/// <param name="AMatches"></param>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;

type
	/// <summary>
	/// This matcher detects lexicographical sequences (and in reverse) e.g. abcd, 4567, PONML etc.
	/// </summary>
	TZxcvbnSequenceMatcher = class(TInterfacedObject, IZxcvbnMatcher)
	private
		// Sequences should not overlap, sequences here must be ascending, their reverses will be checked automatically
		const
			Sequences: array [0 .. 2] of string = ('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '01234567890');
			SequenceNames: array [0 .. 2] of string = ('lower', 'upper', 'digits');
			SequencePattern = 'sequence';
	private
		function CalculateEntropy(AMatch: string; AAscending: Boolean): Double;
	public
		/// <summary>
		/// Find matching sequences in <paramref name="APassword"/> and adds them to <paramref name="AMatches"/>
		/// </summary>
		/// <param name="APassword">The password to check</param>
		/// <param name="AMatches"></param>
		/// <seealso cref="SequenceMatch"/>
		procedure MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
	end;


	{ TZxcvbn }

constructor TZxcvbn.Create;
begin
	Create(TZxcvbnDefaultMatcherFactory.Create);
end;

constructor TZxcvbn.Create(AMatcherFactory: IZxcvbnMatcherFactory);
begin
	FMatcherFactory := AMatcherFactory;
end;

function TZxcvbn.FindMinimumEntropyMatch(const APassword: string; AMatches: TList<TZxcvbnMatch>): TZxcvbnResult;
var
	bruteforce_cardinality: Integer;
	minimumEntropyToIndex: array of Double;
	bestMatchForIndex: array of TZxcvbnMatch;
	k: Integer;
	match: TZxcvbnMatch;
	candidate_entropy: Double;
	MatchSequence, matchSequenceCopy: TList<TZxcvbnMatch>;
	m1, m2: TZxcvbnMatch;
	m2i: Integer;
	ns, ne: Integer;
	minEntropy: Double;
	crackTime: Double;
	res: TZxcvbnResult;
	longestMatch: TZxcvbnMatch;
	WarningText: string;
	Suggestions: string;

const
	CrackSpeed_OnlineThrottled    = 100*60*60; //100 guesses/hour
	CrackSpeed_OnlineNoThrottling = 100;       // 100 guesses/sec
	CrackSpeed_OfflineSlowHash    = 10000;     // 10k guesses/sec
	CrackSpeed_OfflineFastHash    = 10E9;      // 10B guesses/sec
begin
	bruteforce_cardinality := PasswordCardinality(APassword);

	// Minimum entropy up to position k in the password
	SetLength(minimumEntropyToIndex, APassword.Length);
	SetLength(bestMatchForIndex, APassword.Length);

	for k := 0 to APassword.Length - 1 do
	begin
		// Start with bruteforce scenario added to previous sequence to beat
		if (k = 0) then
			minimumEntropyToIndex[k] := LogN(2, bruteforce_cardinality)
		else
			minimumEntropyToIndex[k] := (minimumEntropyToIndex[k - 1]) + LogN(2, bruteforce_cardinality);

		// All matches that end at the current character, test to see if the entropy is less
		for match in AMatches do
		begin
			if (match.j <> k) then
				Continue;

			if (match.i <= 0) then
				candidate_entropy := match.Entropy
			else
				candidate_entropy := minimumEntropyToIndex[match.i - 1] + match.Entropy;

			if (candidate_entropy < minimumEntropyToIndex[k]) then
			begin
				minimumEntropyToIndex[k] := candidate_entropy;
				bestMatchForIndex[k] := match;
			end;
		end;
	end;

	// Walk backwards through lowest entropy matches, to build the best password sequence
	MatchSequence := TList<TZxcvbnMatch>.Create;
	k := APassword.Length - 1;
	while k >= 0 do
	begin
		if (bestMatchForIndex[k] <> nil) then
		begin
			// to-do clone
			MatchSequence.Add(bestMatchForIndex[k].Clone);
			k := bestMatchForIndex[k].i; // Jump back to start of match
		end;
		Dec(k);
	end;
	MatchSequence.Reverse;

	// The match sequence might have gaps, fill in with bruteforce matching
	// After this the matches in matchSequence must cover the whole string (i.e. match[k].j == match[k + 1].i - 1)
	if (MatchSequence.Count = 0) and (APassword.Length > 0) then
	begin
		// To make things easy, we'll separate out the case where there are no matches so everything is bruteforced
		match := TZxcvbnMatch.Create;
		match.i := 0;
		match.j := APassword.Length;
		match.Token := APassword;
		match.Pattern := BruteforcePattern;
		try
			match.Entropy := LogN(2, Power(bruteforce_cardinality, APassword.Length));
		except
			on e: EOverflow do
				match.Entropy := Infinity;
		end;
		MatchSequence.Add(match);
	end
	else
	begin
		// There are matches, so find the gaps and fill them in
		matchSequenceCopy := TList<TZxcvbnMatch>.Create;
		for k := 0 to MatchSequence.Count - 1 do
		begin
			m1 := MatchSequence[k];
			// Next match, or a match past the end of the password
			if (k < MatchSequence.Count - 1) then
				m2i := MatchSequence[k + 1].i
			else
			begin
				m2i := APassword.Length;
			end;

			// to-do clone
			matchSequenceCopy.Add(m1.Clone);
			if (m1.j < m2i - 1) then
			begin
				// Fill in gap
				ns := m1.j + 1;
				ne := m2i - 1;

				match := TZxcvbnMatch.Create;
				match.i := ns;
				match.j := ne;
				match.Token := APassword.Substring(ns, ne - ns + 1);
				match.Pattern := BruteforcePattern;
				match.Entropy := LogN(2, Power(bruteforce_cardinality, ne - ns + 1));
				matchSequenceCopy.Add(match);
			end;
		end;

		for match in MatchSequence do
			match.Free;
		MatchSequence.Free;
		MatchSequence := matchSequenceCopy;
	end;

	if (APassword.Length = 0) then
		minEntropy := 0
	else
		minEntropy := minimumEntropyToIndex[APassword.Length - 1];

	res := TZxcvbnResult.Create;
	res.Password := APassword;
	res.Entropy := minEntropy;
	res.MatchSequence := MatchSequence;

	res.CrackTimeOnlineThrottling   := res.Guesses / CrackSpeed_OnlineThrottled;
	res.CrackTimeOnlineNoThrottling := res.Guesses / CrackSpeed_OnlineNoThrottling;
	res.CrackTimeOfflineSlowHash    := res.Guesses / CrackSpeed_OfflineSlowHash;
	res.CrackTimeOfflineFastHash    := res.Guesses / CrackSpeed_OfflineFastHash;

	res.CrackTimeOnlineThrottlingDisplay   := DisplayTime(res.CrackTimeOnlineThrottling,   LocaleName);
	res.CrackTimeOnlineNoThrottlingDisplay := DisplayTime(res.CrackTimeOnlineNoThrottling, LocaleName);
	res.CrackTimeOfflineSlowHashDisplay    := DisplayTime(res.CrackTimeOfflineSlowHash,    LocaleName);
	res.CrackTimeOfflineFastHashDisplay    := DisplayTime(res.CrackTimeOfflineFastHash,    LocaleName);

	res.ScoreText := GetScoreText(res.Score, Self.LocaleName); // match knows how to calculate score itself (it comes from the entropy)

	// starting feedback
	if Assigned(MatchSequence) then
	begin
		if (MatchSequence.Count > 0) then
		begin
			// no Feedback if score is good or great
			if (res.Score <= 2) then
			begin
				// tie feedback to the longest match for longer sequences
				longestMatch := GetLongestMatch(MatchSequence);
				GetMatchFeedback(longestMatch, (MatchSequence.Count = 1), LocaleName, { out } WarningText, { out } Suggestions);
				res.WarningText := WarningText;
				res.SuggestionsText := Suggestions;
			end;
		end;
	end;

	Result := res;
end;

function TZxcvbn.GetLongestMatch(const AMatchSequence: TList<TZxcvbnMatch>): TZxcvbnMatch;
var
	longestMatch: TZxcvbnMatch;
	match: TZxcvbnMatch;
begin
	longestMatch := nil;

	if Assigned(AMatchSequence) then
	begin
		if (AMatchSequence.Count > 0) then
		begin
			longestMatch := AMatchSequence[0];
			for match in AMatchSequence do
			begin
				if (match.Token.Length > longestMatch.Token.Length) then
					longestMatch := match;
			end;
		end;
	end;

	Result := longestMatch;
end;

procedure TZxcvbn.GetMatchFeedback(const AMatch: TZxcvbnMatch; AIsSoleMatch: Boolean; LocaleName: string; out WarningText: string; out SuggestionsText: string);
begin
	WarningText := '';
	SuggestionsText := '';

	if AMatch = nil then
		Exit;

	if (AMatch.Pattern = 'dictionary') then
		AMatch.GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText)
	else if (AMatch.Pattern = 'spatial') then
		AMatch.GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText)
	else if (AMatch.Pattern = 'repeat') then
		AMatch.GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText)
	else if (AMatch.Pattern = 'sequence') then
		AMatch.GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText)
	else if (AMatch.Pattern = 'date') then
		AMatch.GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText);
end;

function TZxcvbn.EvaluatePassword(const APassword: string; AUserInputs: TStrings=nil): TZxcvbnResult;
var
	matches: TList<TZxcvbnMatch>;
	Matcher: IZxcvbnMatcher;
	match: TZxcvbnMatch;
	res: TZxcvbnResult;
	timer: TStopWatch;
begin
	matches := TList<TZxcvbnMatch>.Create;

	timer := System.Diagnostics.TStopWatch.StartNew;

	for Matcher in FMatcherFactory.CreateMatchers(AUserInputs) do
		Matcher.MatchPassword(APassword, matches);

	res := FindMinimumEntropyMatch(APassword, matches);

	// cleanup
	for match in matches do
		match.Free;
	matches.Free;

	timer.Stop;
	res.CalcTime := timer.Elapsed.TotalMilliseconds;

	Result := res;
end;

class function TZxcvbn.MatchPassword(const APassword: string; AUserInputs: TStrings=nil): TZxcvbnResult;
var
	zx: TZxcvbn;
begin
	zx := TZxcvbn.Create;
	try
		Result := zx.EvaluatePassword(APassword, AUserInputs);
	finally
		zx.Free;
	end;
end;

{ TZxcvbnDefaultMatcherFactory }

constructor TZxcvbnDefaultMatcherFactory.Create;
var
	dictionaryMatchers: TList<IZxcvbnMatcher>;
begin
	FMatchers := TList<IZxcvbnMatcher>.Create;
	FCustomMatchers := TList<IZxcvbnMatcher>.Create;

	dictionaryMatchers := TList<IZxcvbnMatcher>.Create;
	try
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('us_tv_and_film', 		'us_tv_and_film.lst'));
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('english_wikipedia',	'english_wikipedia.lst'));
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('passwords',				'passwords.lst'));
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('surnames',				'surnames.lst'));
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('male_names',				'male_names.lst'));
		dictionaryMatchers.Add(TZxcvbnDictionaryMatcher.Create('female_names',			'female_names.lst'));

		FMatchers.AddRange(dictionaryMatchers);

		//The 1337-speak matches is based off words from the dictionaries.
		FMatchers.Add(TZxcvbnL33tMatcher.Create(dictionaryMatchers));
	finally
		dictionaryMatchers.Free;
	end;

	//Other matches that are standalone; don't depend on dictionaries.
	FMatchers.Add(TZxcvbnRepeatMatcher.Create);
	FMatchers.Add(TZxcvbnSequenceMatcher.Create);
	FMatchers.Add(TZxcvbnRegexMatcher.Create('\d{3,}', 10, True, 'digits')); //each digit is 10 possible values for each digit
	FMatchers.Add(TZxcvbnRegexMatcher.Create('19\d\d|200\d|201\d', 119, False, 'year')); //1900-2019 is a fixed 119 possible values (119 possible years)
	FMatchers.Add(TZxcvbnDateMatcher.Create);
	FMatchers.Add(TZxcvbnSpatialMatcher.Create);
end;

destructor TZxcvbnDefaultMatcherFactory.Destroy;
begin
	FreeAndNil(FMatchers);
	FCustomMatchers.Clear;
	FCustomMatchers.Free;
	inherited;
end;

function TZxcvbnDefaultMatcherFactory.CreateMatchers(const AUserInputs: TStrings): TList<IZxcvbnMatcher>;
var
	userInputDict: IZxcvbnMatcher;
begin
	FCustomMatchers.Clear;
	FCustomMatchers.AddRange(FMatchers);

	if AUserInputs <> nil then
	begin
		userInputDict := TZxcvbnDictionaryMatcher.Create('user_inputs', AUserInputs);
		FCustomMatchers.Add(userInputDict);
		FCustomMatchers.Add(TZxcvbnL33tMatcher.Create(userInputDict));
	end;

	Result := FCustomMatchers;
end;

{ TZxcvbnResult }

constructor TZxcvbnResult.Create;
begin
	inherited;
end;

destructor TZxcvbnResult.Destroy;
var
	match: TZxcvbnMatch;
begin
	if Assigned(MatchSequence) then
	begin
		for match in MatchSequence do
			match.Free;
		MatchSequence.Free;
	end;

	{
		The user's password is the most important thing in the world.
			- its more important than their name
			- it's more important than their address, and phone number, and e-mail address
			- it's more important than their bank account number, social security number, and credit card number

		The password is the gateway to all those things. It is the key that controls everything.

			- we want to avoid it ending up in crash dumps, in pagefiles, in hibernate files

		That is why you need to make sure you burn the password when you're done with it.

		Not only that; but it should also be behind ISecureString.
	}
	BurnString({var}Self.Password);

	inherited;
end;

function TZxcvbnResult.GetGuesses: Real;
begin
	Result := 0.5 * Power(2, Self.Entropy);
end;

function TZxcvbnResult.GetGuessesLog10: Real;
begin
	Result := Log10(Self.Guesses);
end;

function TZxcvbnResult.GetScore: Integer;
begin
	{
	  Integer from 0-4 (useful for implementing a strength bar)

	  - 0: too guessable - risky password. (guesses < 10^3)
	  - 1: very guessable - protection from throttled online attacks. (guesses < 10^6)
	  - 2: somewhat guessable - protection from unthrottled online attacks. (guesses < 10^8)
	  - 3: safely unguessable - moderate protection from offline slow-hash scenario. (guesses < 10^10)
	  - 4: very unguessable - strong protection from offline slow-hash scenario. (guesses >= 10^10)
	}
	Result := EntropyToScore(Self.Entropy);
end;

{ TZxcvbnMatch }

function TZxcvbnMatch.Clone: TZxcvbnMatch;

	procedure CopyBaseProperties(const AFrom: TZxcvbnMatch; var ATo: TZxcvbnMatch);
	begin
		ATo.Pattern := AFrom.Pattern;
		ATo.Token := AFrom.Token;
		ATo.Entropy := AFrom.Entropy;
		ATo.i := AFrom.i;
		ATo.j := AFrom.j;
	end;

begin
	if Self is TZxcvbnDateMatch then
	begin
		Result := TZxcvbnDateMatch.Create;
		CopyBaseProperties(Self, Result);
		(Self as TZxcvbnDateMatch).CopyTo(Result as TZxcvbnDateMatch);
	end
	else if (Self is TZxcvbnDictionaryMatch) or (Self is TZxcvbnL33tMatch) then
	begin
		if Self is TZxcvbnL33tMatch then
		begin
			Result := TZxcvbnL33tMatch.Create;
			CopyBaseProperties(Self, Result);
			(Self as TZxcvbnL33tMatch).CopyTo(Result as TZxcvbnL33tMatch);
			(Self as TZxcvbnDictionaryMatch).CopyTo(Result as TZxcvbnDictionaryMatch);
		end
		else
		begin
			Result := TZxcvbnDictionaryMatch.Create;
			CopyBaseProperties(Self, Result);
			(Self as TZxcvbnDictionaryMatch).CopyTo(Result as TZxcvbnDictionaryMatch);
		end;
	end
	else if Self is TZxcvbnRepeatMatch then
	begin
		Result := TZxcvbnRepeatMatch.Create;
		CopyBaseProperties(Self, Result);
		(Self as TZxcvbnRepeatMatch).CopyTo(Result as TZxcvbnRepeatMatch);
	end
	else if Self is TZxcvbnSequenceMatch then
	begin
		Result := TZxcvbnSequenceMatch.Create;
		CopyBaseProperties(Self, Result);
		(Self as TZxcvbnSequenceMatch).CopyTo(Result as TZxcvbnSequenceMatch);
	end
	else if Self is TZxcvbnSpatialMatch then
	begin
		Result := TZxcvbnSpatialMatch.Create;
		CopyBaseProperties(Self, Result);
		(Self as TZxcvbnSpatialMatch).CopyTo(Result as TZxcvbnSpatialMatch);
	end
	else
	begin
		Result := TZxcvbnMatch.Create;
		CopyBaseProperties(Self, Result);
	end;
end;

destructor TZxcvbnMatch.Destroy;
begin
	BurnString({var}Self.Token); // Burn even a portion of the user's password. It shouldn't even be a string! (it should be a SecureString)

	inherited;
end;

function TZxcvbnMatch.GetGuessesLog10: Real;
var
	guesses: Real;
begin
	guesses := Power(2, Self.Entropy);

	Result := Log10(guesses);
end;

procedure TZxcvbnMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string; out WarningText, SuggestionsText: string);
begin
{
	Each descendant Match class gives its own warnings and suggestions.

	For example, the Sequence matcher might say:

		Warning:    Straight rows of keys are easy to guess
		Suggestion: Avoid sequences

	This virtual ancestor match defaults to nothing.
}
	WarningText     := '';
	SuggestionsText := '';
end;

{ TZxcvbnL33tMatch }

constructor TZxcvbnL33tMatch.Create(ADictionaryMatch: TZxcvbnDictionaryMatch);
begin
	Self.BaseEntropy := ADictionaryMatch.BaseEntropy;
	Self.DictionaryName := ADictionaryMatch.DictionaryName;
	Self.Entropy := ADictionaryMatch.Entropy;
	Self.i := ADictionaryMatch.i;
	Self.j := ADictionaryMatch.j;
	Self.MatchedWord := ADictionaryMatch.MatchedWord;
	Self.Pattern := ADictionaryMatch.Pattern;
	Self.Rank := ADictionaryMatch.Rank;
	Self.Token := ADictionaryMatch.Token;
	Self.UppercaseEntropy := ADictionaryMatch.UppercaseEntropy;

	FSubs := TDictionary<Char, Char>.Create;
end;

constructor TZxcvbnL33tMatch.Create;
begin
	FSubs := TDictionary<Char, Char>.Create;
end;

destructor TZxcvbnL33tMatch.Destroy;
begin
	FSubs.Free;
	inherited;
end;

procedure TZxcvbnL33tMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
	out WarningText, SuggestionsText: string);
begin
	inherited GetMatchFeedback(AIsSoleMatch, LocaleName, {out}WarningText, {out}SuggestionsText);

	if SuggestionsText <> '' then
		SuggestionsText := SuggestionsText + #13#10;

	SuggestionsText := SuggestionsText +
			'- '+GetSuggestion(zsPredictableSubstitutionsEasy, LocaleName);
end;

procedure TZxcvbnL33tMatch.CopyTo(AMatch: TZxcvbnL33tMatch);
var
	sub: TPair<Char, Char>;
begin
	AMatch.MatchedWord := Self.MatchedWord;
	AMatch.Rank := Self.Rank;
	AMatch.BaseEntropy := Self.BaseEntropy;
	AMatch.UppercaseEntropy := Self.UppercaseEntropy;
	AMatch.L33tEntropy := Self.L33tEntropy;
	AMatch.L33tEntropy := Self.L33tEntropy;
	for sub in FSubs do
		AMatch.Subs.Add(sub.Key, sub.Value);
end;

{ TZxcvbnL33tMatcher }

constructor TZxcvbnL33tMatcher.Create(const ADictionaryMatchers: TList<IZxcvbnMatcher>);
begin
	FDictionaryMatchers := TList<IZxcvbnMatcher>.Create;
	FDictionaryMatchers.AddRange(ADictionaryMatchers);

	FSubstitutions := BuildSubstitutionsMap;
end;

constructor TZxcvbnL33tMatcher.Create(const ADictionaryMatcher: IZxcvbnMatcher);
begin
	FDictionaryMatchers := TList<IZxcvbnMatcher>.Create;
	FDictionaryMatchers.Add(ADictionaryMatcher);

	FSubstitutions := BuildSubstitutionsMap;
end;

destructor TZxcvbnL33tMatcher.Destroy;
begin
	if Assigned(FSubstitutions) then
		FSubstitutions.Free;

	FDictionaryMatchers.Free;
	inherited;
end;

procedure TZxcvbnL33tMatcher.CalculateL33tEntropy(AMatch: TZxcvbnL33tMatch);
var
	possibilities: Integer;
	kvp: TPair<Char, Char>;
	subbedChars: Integer;
	unsubbedChars: Integer;
	c: Char;
	i: Integer;
	Entropy: Double;
begin
	possibilities := 0;

	subbedChars := 0;
	unsubbedChars := 0;
	for kvp in AMatch.Subs do
	begin
		for c in AMatch.Token do
			if (c = kvp.Key) then
				Inc(subbedChars);

		for c in AMatch.Token do
			if (c = kvp.Value) then
				Inc(unsubbedChars);

		for i := 0 to Min(subbedChars, unsubbedChars) + 1 do
			possibilities := possibilities + Binomial(subbedChars + unsubbedChars, i);
	end;

	Entropy := LogN(2, possibilities);

	// In the case of only a single subsitution (e.g. 4pple) this would otherwise come out as zero, so give it one bit
	if (Entropy < 1) then
		AMatch.L33tEntropy := 1
	else
		AMatch.L33tEntropy := Entropy;

	AMatch.Entropy := AMatch.Entropy + AMatch.L33tEntropy;

	// We have to recalculate the uppercase entropy -- the password matcher will have used the subbed password not the original text
	AMatch.Entropy := AMatch.Entropy - AMatch.UppercaseEntropy;
	AMatch.UppercaseEntropy := CalculateUppercaseEntropy(AMatch.Token);
	AMatch.Entropy := AMatch.Entropy + AMatch.UppercaseEntropy;
end;

function TZxcvbnL33tMatcher.TranslateString(ACharMap: TDictionary<Char, Char>; AStr: string): string;
var
	c: Char;
	res: string;
begin
	res := '';
	for c in AStr do
	begin
		if ACharMap.ContainsKey(c) then
			res := res + ACharMap[c]
		else
			res := res + c;
	end;

	Result := res;
end;

function TZxcvbnL33tMatcher.EnumerateSubtitutions(ATable: TDictionary<Char, string>): TList<TDictionary<Char, Char>>;
var
	Subs: TList<TDictionary<Char, Char>>;
	mapPair: TPair<Char, string>;
	normalChar: Char;
	l33tChar: Char;
	addedSubs: TList<TDictionary<Char, Char>>;
	subDict: TDictionary<Char, Char>;
	newSub: TDictionary<Char, Char>;
begin
	Subs := TList < TDictionary < Char, Char >>.Create;

	Subs.Add(TDictionary<Char, Char>.Create); // Must be at least one mapping dictionary to work

	for mapPair in ATable do
	begin
		normalChar := mapPair.Key;
		for l33tChar in mapPair.Value do
		begin
			// Can't add while enumerating so store here
			addedSubs := TList < TDictionary < Char, Char >>.Create;

			for subDict in Subs do
			begin
				if (subDict.ContainsKey(l33tChar)) then
				begin
					// This mapping already contains a corresponding normal character for this character, so keep the existing one as is
					// but add a duplicate with the mappring replaced with this normal character
					newSub := TDictionary<Char, Char>.Create(subDict);
					newSub.AddOrSetValue(l33tChar, normalChar);
					addedSubs.Add(newSub);
				end
				else
				begin
					subDict.AddOrSetValue(l33tChar, normalChar);
				end;
			end;

			Subs.AddRange(addedSubs);
			addedSubs.Free;
		end;
	end;

	Result := Subs;
end;

function TZxcvbnL33tMatcher.BuildSubstitutionsMap: TDictionary<Char, string>;
var
	Subs: TDictionary<Char, string>;
begin
	Subs := TDictionary<Char, string>.Create;

	Subs.Add('a', '4@');
	Subs.Add('b', '86'); //20180814: HashCash includes b-->6
	Subs.Add('c', '({[<');
	Subs.Add('e', '3');
	Subs.Add('g', '69');
	Subs.Add('i', '1!|');
	Subs.Add('l', '1|7');
	Subs.Add('o', '0');
	Subs.Add('q', '9');  //20180814: Hashcat includes q-->9
	Subs.Add('s', '$5');
	Subs.Add('t', '+7');
	Subs.Add('x', '%');
	Subs.Add('z', '2');

	Result := Subs;
end;

procedure TZxcvbnL33tMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	addMatch: TZxcvbnL33tMatch;
	matches: TList<TZxcvbnMatch>;
	Subs: TList<TDictionary<Char, Char>>;
	subDict: TDictionary<Char, Char>;
	sub_password: string;
	Matcher: IZxcvbnMatcher;
	dictMatches: TList<TZxcvbnMatch>;
	match: TZxcvbnMatch;
	Token: string;
	usedSubs: TDictionary<Char, Char>;
	kv: TPair<Char, Char>;
	prevMatch: TZxcvbnL33tMatch;
begin
	matches := TList<TZxcvbnMatch>.Create;
	try
		Subs := EnumerateSubtitutions(FSubstitutions);
		try
			prevMatch := nil;
			for subDict in Subs do
			begin
				sub_password := TranslateString(subDict, APassword);

				for Matcher in FDictionaryMatchers do
				begin
					dictMatches := TList<TZxcvbnMatch>.Create;
					try
						Matcher.MatchPassword(sub_password, dictMatches);
						for match in dictMatches do
						begin
							Token := APassword.Substring(match.i, match.j - match.i + 1);
							usedSubs := TDictionary<Char, Char>.Create;
							try
								for kv in subDict do
									if Token.Contains(kv.Key) then
										usedSubs.Add(kv.Key, kv.Value);
								if (usedSubs.Count > 0) then
								begin
									if Assigned(prevMatch) then
									begin
										if (prevMatch.i = match.i) and (prevMatch.j = match.j) and (prevMatch.Token = Token) then
											Continue;
									end;
									addMatch := TZxcvbnL33tMatch.Create(match as TZxcvbnDictionaryMatch);
									addMatch.Token := Token;
									for kv in usedSubs do
										addMatch.Subs.Add(kv.Key, kv.Value);
									matches.Add(addMatch);
									prevMatch := addMatch;
								end;
							finally
								usedSubs.Free;
							end;
						end;

						for match in dictMatches do
							match.Free;
					finally
						dictMatches.Free;
					end;
				end;
			end;

			for subDict in Subs do
				subDict.Free;
		finally
			Subs.Free;
		end;

		for match in matches do
			CalculateL33tEntropy(match as TZxcvbnL33tMatch);

		AMatches.AddRange(matches);
	finally
		matches.Free;
	end;
end;

{ TZxcvbnDictionaryMatch }

procedure TZxcvbnDictionaryMatch.CopyTo(AMatch: TZxcvbnDictionaryMatch);
begin
	AMatch.MatchedWord := Self.MatchedWord;
	AMatch.Rank := Self.Rank;
	AMatch.DictionaryName := Self.DictionaryName;
	AMatch.BaseEntropy := Self.BaseEntropy;
	AMatch.UppercaseEntropy := Self.UppercaseEntropy;
end;

destructor TZxcvbnDictionaryMatch.Destroy;
begin
	BurnString({var}MatchedWord);

	inherited;
end;

procedure TZxcvbnDictionaryMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
		out WarningText, SuggestionsText: string);
var
	word: string;
	warning: TZxcvbnWarning;
	suggestions: TZxcvbnSuggestions;
	theMatch: TZxcvbnDictionaryMatch;
begin
	theMatch := Self as TZxcvbnDictionaryMatch;
	warning := Low(TZxcvbnWarning);
	suggestions := [];

	if (theMatch.DictionaryName.Equals('passwords')) then
	begin
		// todo: add support for reversed words
		if (AIsSoleMatch and not(Self is TZxcvbnL33tMatch)) then
		begin
			if (theMatch.Rank <= 10) then
				warning := TZxcvbnWarning.zwTop10Passwords
			else if (theMatch.Rank <= 100) then
				warning := TZxcvbnWarning.zwTop100Passwords
			else
				warning := TZxcvbnWarning.zwCommonPasswords;

			Include(suggestions, zsAddAnotherWordOrTwo);
		end
		else if (EntropyToScore(theMatch.Entropy) <= 1) then
			warning := TZxcvbnWarning.zwSimilarCommonPasswords;
	end
	else if (theMatch.DictionaryName.Equals('english')) then
	begin
		if AIsSoleMatch then
			warning := TZxcvbnWarning.zwWordEasy;
	end
	else if (theMatch.DictionaryName.Equals('surnames') or theMatch.DictionaryName.Equals('male_names') or theMatch.DictionaryName.Equals('female_names')) then
	begin
		if AIsSoleMatch then
			warning := TZxcvbnWarning.zwNameSurnamesEasy
		else
			warning := TZxcvbnWarning.zwCommonNameSurnamesEasy;
	end
	else
		warning := TZxcvbnWarning.zwEmpty;

	word := theMatch.Token;
	if (TRegEx.IsMatch(word, StartUpper)) then
		Include(suggestions, TZxcvbnSuggestion.zsCapsDontHelp)
	else if (TRegEx.IsMatch(word, AllUpper) and not word.Equals(word.ToLowerInvariant)) then
		Include(suggestions, TZxcvbnSuggestion.zsAllCapsEasy);

	// todo: add support for reversed words
	// if match.reversed and match.token.length >= 4
	// suggestions.push "Reversed words aren't much harder to guess"

	WarningText := GetWarning(warning, LocaleName);
	SuggestionsText := GetSuggestions(suggestions, LocaleName);
end;

{ TZxcvbnDictionaryMatcher }

constructor TZxcvbnDictionaryMatcher.Create(AName: string; AWordListPath: string);
begin
	FDictionaryName := AName;
	FRankedDictionary := BuildRankedDictionary(AWordListPath);
end;

constructor TZxcvbnDictionaryMatcher.Create(AName: string; AWordList: TStrings);
var
	wordListToLower: TStringList;
	i: Integer;
begin
	FDictionaryName := AName;

	// Must ensure that the dictionary is using lowercase words only
	wordListToLower := TStringList.Create;
	try
		if Assigned(AWordList) then
		begin
			for i := 0 to AWordList.Count - 1 do
				wordListToLower.Add(AWordList[i].ToLower);
		end;
		FRankedDictionary := BuildRankedDictionary(wordListToLower);
	finally
		wordListToLower.Free;
	end;
end;

destructor TZxcvbnDictionaryMatcher.Destroy;
begin
	FRankedDictionary.Free;
	inherited;
end;

function TZxcvbnDictionaryMatcher.BuildRankedDictionary(AWordListFile: string): TDictionary<string, Integer>;
var
	lines: TStrings;
	resName: string;
begin
	{
		Look first to wordlists embedded in assembly (i.e. default dictionaries) otherwise treat as file path

		Examples of dictionary names are:
			- us_tv_and_film		//top 30,000
			- english_wikipedia	//top 30,000
			- passwords				//top 30,000
			- surnames				//top 10,000
			- male_names
			- female_names
	}
	Result := nil;

	try
		//Assume resources are one-per-line RCDATA
		resName := Format('ZxcvbnDictionaries_%s', [ChangeFileExt(AWordListFile, '')]);
		lines := GetEmbeddedResourceLines(resName);
		if Assigned(lines) then
		begin
			Result := BuildRankedDictionary(lines);
			Exit;
		end;

		//Try looking for a file
		if FileExists(AWordListFile) then
		begin
			lines := TStringList.Create;
			try
				lines.LoadFromFile(AWordListFile);
				Result := BuildRankedDictionary(lines);
				Exit;
			except
				FreeAndNil(lines);
			end;
		end;

		//Use the compressed in-box
		lines := GetCompressedWordList(ChangeFileExt(AWordListFile, ''));
		if Assigned(lines) then
		begin
			Result := BuildRankedDictionary(lines);
			Exit;
		end;

		raise Exception.CreateFmt('Could not load word list "%s"', [AWordListFile]);
	finally
		if Assigned(lines) then
			lines.Free;
	end;
end;

function TZxcvbnDictionaryMatcher.BuildRankedDictionary(AWordList: TStrings): TDictionary<string, Integer>;
var
	dict: TDictionary<string, Integer>;
	i: Integer;
begin
	dict := TDictionary<string, Integer>.Create;

	for i := 0 to AWordList.Count - 1 do
	begin
		// The word list is assumed to be in decreasing frequency order
		dict.Add(AWordList[i], i+1);
	end;

	Result := dict;
end;

procedure TZxcvbnDictionaryMatcher.CalculateEntropyForMatch(AMatch: TZxcvbnDictionaryMatch);
begin
	AMatch.BaseEntropy := LogN(2, AMatch.Rank);
	AMatch.UppercaseEntropy := CalculateUppercaseEntropy(AMatch.Token);

	AMatch.Entropy := AMatch.BaseEntropy + AMatch.UppercaseEntropy;
end;

procedure TZxcvbnDictionaryMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	passwordLower: string;
	addMatch: TZxcvbnDictionaryMatch;
	match: TZxcvbnMatch;
	matches: TList<TZxcvbnMatch>;
	i, j: Integer;
	passSub: string;
begin
	passwordLower := APassword.ToLower;

	matches := TList<TZxcvbnMatch>.Create;
	try
		for i := 0 to APassword.Length - 1 do
		begin
			for j := i to APassword.Length - 1 do
			begin
				passSub := passwordLower.Substring(i, j - i + 1);
				if FRankedDictionary.ContainsKey(passSub) then
				begin
					addMatch := TZxcvbnDictionaryMatch.Create;
					addMatch.Pattern := DictionaryPattern;
					addMatch.i := i;
					addMatch.j := j;
					addMatch.Token := APassword.Substring(i, j - i + 1); // Could have different case so pull from password
					addMatch.MatchedWord := passSub;
					addMatch.Rank := FRankedDictionary.Items[passSub];
					addMatch.DictionaryName := FDictionaryName;
					matches.Add(addMatch);
				end;
			end;
		end;

		for match in matches do
			CalculateEntropyForMatch(match as TZxcvbnDictionaryMatch);

		AMatches.AddRange(matches);
	finally
		matches.Free;
	end;
end;

const
	DATE_MIN_YEAR  = 1000;
	DATE_MAX_YEAR  = 2050;
	REFERENCE_YEAR = 2017;
	MIN_YEAR_SPACE = 10;

	{ TZxcvbnDateMatch }

procedure TZxcvbnDateMatch.CopyTo(AMatch: TZxcvbnDateMatch);
begin
	AMatch.year := Self.year;
	AMatch.month := Self.month;
	AMatch.day := Self.day;
	AMatch.Separator := Self.Separator;
end;

destructor TZxcvbnDateMatch.Destroy;
begin
	//Burn
	year := 0;
	month := 0;
	day := 0;
	BurnString({var}Separator);

	inherited;
end;

procedure TZxcvbnDateMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
		out WarningText, SuggestionsText: string);
begin
	WarningText := GetWarning(zwDatesEasy, LocaleName);

	SuggestionsText := GetSuggestion(TZxcvbnSuggestion.zsAvoidDatesYearsAssociatedYou, LocaleName);
end;

{ TZxcvbnDateMatcher }

constructor TZxcvbnDateMatcher.Create;
var
	arr: TArray<TZxcvbnSplitsArr>;
begin
	FDateSplits := TDictionary < Integer, TArray < TZxcvbnSplitsArr >>.Create;

	// for length-4 strings, eg 1191 or 9111, two ways to split:
	SetLength(arr, 2);
	arr[0][0] := 1; arr[0][1] := 2; // 1 1 91 (2nd split starts at index 1, 3rd at index 2)
	arr[1][0] := 2; arr[1][1] := 3; // 91 1 1
	FDateSplits.Add(4, arr);

	arr[0][0] := 1; arr[0][1] := 3; // 1 11 91
	arr[1][0] := 2; arr[1][1] := 3; // 11 1 91
	FDateSplits.Add(5, arr);

	SetLength(arr, 3);
	arr[0][0] := 1; arr[0][1] := 2; // 1 1 1991
	arr[1][0] := 2; arr[1][1] := 4; // 11 11 91
	arr[2][0] := 4; arr[2][1] := 5; // 1991 1 1
	FDateSplits.Add(6, arr);

	SetLength(arr, 4);
	arr[0][0] := 1; arr[0][1] := 3; // 1 11 1991
	arr[1][0] := 2; arr[1][1] := 3; // 11 1 1991
	arr[2][0] := 4; arr[2][1] := 5; // 1991 1 11
	arr[3][0] := 4; arr[3][1] := 6; // 1991 11 1
	FDateSplits.Add(7, arr);

	SetLength(arr, 2);
	arr[0][0] := 2; arr[0][1] := 4; // 11 11 1991
	arr[1][0] := 4; arr[1][1] := 6; // 1991 11 11
	FDateSplits.Add(8, arr);
end;

destructor TZxcvbnDateMatcher.Destroy;
begin
	FDateSplits.Free;
	inherited;
end;

function TZxcvbnDateMatcher.CalculateEntropy(AMatch: TZxcvbnDateMatch): Double;
var
	Entropy: Double;
	yearSpace: Double;
begin
	yearSpace := Max(Abs(AMatch.year - REFERENCE_YEAR), MIN_YEAR_SPACE);
	Entropy := LogN(2, yearSpace * 365);
	if (AMatch.Separator <> '') then
		Entropy := Entropy + 2;

	Result := Entropy;
end;

function TZxcvbnDateMatcher.MapIntsToDmy(AIntegers: TList<Integer>): TZxcvbnDmy;
var
	over12: Integer;
	over31: Integer;
	under1: Integer;
	i: Integer;
	possibleYearSplits: TList<TPair<Integer, TList<Integer>>>;
	itl: TList<Integer>;
	pair: TPair<Integer, TList<Integer>>;
	possibleYearSplitRef: TPair<Integer, TList<Integer>>;
	y: Integer;
	rest: TList<Integer>;
	dm: TZxcvbnDm;
begin
	Result.valid := False;

	if (AIntegers.Items[1] > 31) or (AIntegers.Items[1] <= 0) then
		Exit;

	over12 := 0;
	over31 := 0;
	under1 := 0;
	for i in AIntegers do
	begin
		if (((99 < i) and (i < DATE_MIN_YEAR)) or (i > DATE_MAX_YEAR)) then
			Exit;

		if (i > 31) then
			Inc(over31);
		if (i > 12) then
			Inc(over12);
		if (i <= 0) then
			Inc(under1);
	end;
	if (over31 >= 2) or (over12 = 3) or (under1 >= 2) then
		Exit;

	possibleYearSplits := TList < TPair < Integer, TList<Integer> >>.Create;
	try
		itl := TList<Integer>.Create;
		for i := 0 to 1 do
			itl.Add(AIntegers.Items[i]);
		pair := TPair < Integer, TList < Integer >>.Create(AIntegers.Items[2], itl);
		possibleYearSplits.Add(pair);
		itl := TList<Integer>.Create;
		for i := 1 to 2 do
			itl.Add(AIntegers.Items[i]);
		pair := TPair < Integer, TList < Integer >>.Create(AIntegers.Items[0], itl);
		possibleYearSplits.Add(pair);
		for possibleYearSplitRef in possibleYearSplits do
		begin
			y := possibleYearSplitRef.Key;
			rest := possibleYearSplitRef.Value;
			if ((DATE_MIN_YEAR <= y) and (y <= DATE_MAX_YEAR)) then
			begin
				dm := MapIntsToDm(rest);
				if dm.valid then
				begin
					Result.valid := True;
					Result.day := dm.day;
					Result.month := dm.month;
					Result.year := y;
				end
				else
					Exit;
			end;
		end;

		for possibleYearSplitRef in possibleYearSplits do
		begin
			y := possibleYearSplitRef.Key;
			rest := possibleYearSplitRef.Value;
			dm := MapIntsToDm(rest);
			if dm.valid then
			begin
				y := TwoToFourDigitYear(y);
				Result.valid := True;
				Result.day := dm.day;
				Result.month := dm.month;
				Result.year := y;
			end
			else
				Exit;
		end;
	finally
		for possibleYearSplitRef in possibleYearSplits do
			possibleYearSplitRef.Value.Free;
		possibleYearSplits.Free;
	end;
end;

function TZxcvbnDateMatcher.MapIntsToDm(AIntegers: TList<Integer>): TZxcvbnDm;
var
	refs: TList<TList<Integer>>;
	copy: TList<Integer>;
	ref: TList<Integer>;
	d, m: Integer;
begin
	Result.valid := False;

	copy := TList<Integer>.Create;
	try
		copy.AddRange(AIntegers);
		copy.Reverse;

		refs := TList < TList < Integer >>.Create;
		try
			refs.Add(AIntegers);
			refs.Add(copy);

			for ref in refs do
			begin
				d := ref.Items[0];
				m := ref.Items[1];
				if (((1 <= d) and (d <= 31)) and ((1 <= m) and (m <= 12))) then
				begin
					Result.valid := True;
					Result.day := d;
					Result.month := m;
					Exit;
				end;
			end;
		finally
			refs.Free;
		end;
	finally
		copy.Free;
	end;
end;

function TZxcvbnDateMatcher.Metric(ACandidate: TZxcvbnDmy): Integer;
begin
	Result := Abs(ACandidate.year - REFERENCE_YEAR);
end;

function TZxcvbnDateMatcher.TwoToFourDigitYear(AYear: Integer): Integer;
begin
	if (AYear > 99) then
		Result := AYear
	else if (AYear > 50) then
		// 87 -> 1987
		Result := AYear + 1900
	else
		// 15 -> 2015
		Result := AYear + 2000;
end;

procedure TZxcvbnDateMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	addMatch: TZxcvbnDateMatch;
	matches: TList<TZxcvbnMatch>;
	curFmt: string;
	fmt: Char;
	fail: Boolean;
	s: string;
	i, j: Integer;
	pSub: string;
	yearLen: Integer;
	prevLen: Integer;
	sep: Char;
	len: Integer;
	year, mon, day: Integer;
	p: Char;
	k, L: Integer;
	Token: string;
	noSep: TRegEx;
	candidates: TList<TZxcvbnDmy>;
	arr: TArray<TZxcvbnSplitsArr>;
	date: TZxcvbnSplitsArr;
	ints: TList<Integer>;
	it: Integer;
	dmy: TZxcvbnDmy;
	bestCandidate: TZxcvbnDmy;
	candidate: TZxcvbnDmy;
	minDistance, distance: Integer;
	canIdx: Integer;
	rxMatch: System.RegularExpressions.TMatch;
	targetMatches: TList<TZxcvbnMatch>;
	match, otherMatch: TZxcvbnMatch;
	isSubmatch: Boolean;
begin
	matches := TList<TZxcvbnMatch>.Create;
	try
		for i := 0 to APassword.Length - 3 do
		begin
			j := i + 3;
			while (j <= i + 7) do
			begin
				if (j >= APassword.Length) then
					Break;
				Token := APassword.Substring(i, j - i + 1);
				try
					if not TRegEx.IsMatch(Token, '^\d{4,8}$') then
						Continue;

					if FDateSplits.TryGetValue(Token.Length, arr) then
					begin
						candidates := TList<TZxcvbnDmy>.Create;
						try
							for date in arr do
							begin
								k := date[0];
								L := date[1];
								ints := TList<Integer>.Create;
								try
									ints.Add(Token.Substring(0, k).ToInteger);
									ints.Add(Token.Substring(k, L - k).ToInteger);
									ints.Add(Token.Substring(L).ToInteger);
									dmy := MapIntsToDmy(ints);
									if dmy.valid then
										candidates.Add(dmy);
								finally
									ints.Free;
								end;
							end;
							if (candidates.Count = 0) then
								Continue;

							bestCandidate := candidates[0];
							minDistance := Metric(candidates[0]);
							for candidate in candidates do
							begin
								distance := Metric(candidate);
								if (distance < minDistance) then
								begin
									bestCandidate := candidate;
									minDistance := distance;
								end;
							end;
							addMatch := TZxcvbnDateMatch.Create;
							addMatch.Pattern := DatePattern;
							addMatch.Token := Token;
							addMatch.i := i;
							addMatch.j := i + Token.Length - 1;
							addMatch.day := bestCandidate.day;
							addMatch.month := bestCandidate.month;
							addMatch.year := bestCandidate.year;
							addMatch.Separator := '';
							addMatch.Entropy := CalculateEntropy(addMatch);
							matches.Add(addMatch);
						finally
							candidates.Free;
						end;
					end;
				finally
					Inc(j);
				end;
			end;
		end;

		for i := 0 to APassword.Length - 6 do
		begin
			j := i + 5;
			while (j <= i + 9) do
			begin
				if (j >= APassword.Length) then
					Break;
				Token := APassword.Substring(i, j - i + 1);
				try
					rxMatch := TRegEx.match(Token, '^(\d{1,4})([\s\/\\_.-])(\d{1,2})\2(\d{1,4})$');
					if not rxMatch.Success then
						Continue;

					ints := TList<Integer>.Create;
					try
						ints.Add(rxMatch.Groups[1].Value.ToInteger);
						ints.Add(rxMatch.Groups[3].Value.ToInteger);
						ints.Add(rxMatch.Groups[4].Value.ToInteger);
						dmy := MapIntsToDmy(ints);
						if not dmy.valid then
							Continue;

						addMatch := TZxcvbnDateMatch.Create;
						addMatch.Pattern := DatePattern;
						addMatch.Token := Token;
						addMatch.i := i;
						addMatch.j := i + Token.Length - 1;
						addMatch.day := dmy.day;
						addMatch.month := dmy.month;
						addMatch.year := dmy.year;
						addMatch.Separator := rxMatch.Groups[2].Value;
						addMatch.Entropy := CalculateEntropy(addMatch);
						matches.Add(addMatch);
					finally
						ints.Free;
					end;
				finally
					Inc(j);
				end;
			end;
		end;

		// remove submatches
		targetMatches := TList<TZxcvbnMatch>.Create;
		try
			for match in matches do
			begin
				isSubmatch := False;
				for otherMatch in matches do
				begin
					if match.Equals(otherMatch) then
						Continue;
					if ((otherMatch.i <= match.i) and (otherMatch.j >= match.j)) then
					begin
						isSubmatch := True;
						Break;
					end;
				end;
				if not isSubmatch then
					targetMatches.Add(match.Clone);
			end;

			for match in matches do
				match.Free;

			AMatches.AddRange(targetMatches);
		finally
			targetMatches.Free;
		end;
	finally
		matches.Free;
	end;
end;

{ TZxcvbnPoint }

procedure TZxcvbnPoint.ZxcvbnPoint(Ax, Ay: Integer);
begin
	x := Ax;
	y := Ay;
end;

function TZxcvbnPoint.ToString: string;
begin
	Result := '{' + IntToStr(x) + ', ' + IntToStr(y) + '}';
end;

{ TZxcvbnSpatialGraph }

constructor TZxcvbnSpatialGraph.Create(AName: string; ALayout: string; ASlanted: Boolean; ATokenSize: Integer);
begin
	FName := AName;
	BuildGraph(ALayout, ASlanted, ATokenSize);
end;

destructor TZxcvbnSpatialGraph.Destroy;
begin
	if Assigned(FAdjacencyGraph) then
		FAdjacencyGraph.Free;
	inherited;
end;

function TZxcvbnSpatialGraph.IsCharAdjacent(Ac: Char; ATestAdjacent: Char): Boolean;
var
	s: string;
begin
	Result := False;
	if FAdjacencyGraph.ContainsKey(Ac) then
	begin
		for s in FAdjacencyGraph[Ac] do
		begin
			Result := s.Contains(ATestAdjacent);
			if Result then
				Exit;
		end;
	end;
end;

function TZxcvbnSpatialGraph.GetAdjacentCharDirection(Ac: Char; AAdjacent: Char; out AShifted: Boolean): Integer;
var
	adjacentEntry: string;
	s: string;
begin
	AShifted := False;
	Result := -1;

	if not FAdjacencyGraph.ContainsKey(Ac) then
		Exit;

	adjacentEntry := '';
	for s in FAdjacencyGraph[Ac] do
	begin
		if s.Contains(AAdjacent) then
			adjacentEntry := s;
	end;
	if (adjacentEntry = '') then
		Exit;

	AShifted := adjacentEntry.IndexOf(AAdjacent) > 0; // i.e. shifted if not first character in the adjacency
	Result := FAdjacencyGraph[Ac].IndexOf(adjacentEntry);
end;

function TZxcvbnSpatialGraph.GetSlantedAdjacent(Ac: TZxcvbnPoint): TZxcvbnPoints;
var
	x, y: Integer;
begin
	x := Ac.x;
	y := Ac.y;

	SetLength(Result, 6);
	Result[0].ZxcvbnPoint(x - 1, y);
	Result[1].ZxcvbnPoint(x, y - 1);
	Result[2].ZxcvbnPoint(x + 1, y - 1);
	Result[3].ZxcvbnPoint(x + 1, y);
	Result[4].ZxcvbnPoint(x, y + 1);
	Result[5].ZxcvbnPoint(x - 1, y + 1);
end;

function TZxcvbnSpatialGraph.GetAlignedAdjacent(Ac: TZxcvbnPoint): TZxcvbnPoints;
var
	x, y: Integer;
begin
	x := Ac.x;
	y := Ac.y;

	SetLength(Result, 8);
	Result[0].ZxcvbnPoint(x - 1, y);
	Result[1].ZxcvbnPoint(x - 1, y - 1);
	Result[2].ZxcvbnPoint(x, y - 1);
	Result[3].ZxcvbnPoint(x + 1, y - 1);
	Result[4].ZxcvbnPoint(x + 1, y);
	Result[5].ZxcvbnPoint(x + 1, y + 1);
	Result[6].ZxcvbnPoint(x, y + 1);
	Result[7].ZxcvbnPoint(x - 1, y + 1);
end;

procedure TZxcvbnSpatialGraph.BuildGraph(ALayout: string; ASlanted: Boolean; ATokenSize: Integer);
var
	positionTable: TDictionary<TZxcvbnPoint, string>;
	x, y: Integer;
	p: TZxcvbnPoint;
	lines: TStringList;
	slant: Integer;
	Token: string;
	trimLine: string;
	i: Integer;
	tokens: TStrings;
	pair: TPair<TZxcvbnPoint, string>;
	c: Char;
	adjacentPoints: TZxcvbnPoints;
	adjacent: TZxcvbnPoint;
	sum: Integer;
	sl: TStringList;
	s: string;
	ss: TStringList;
begin
	positionTable := TDictionary<TZxcvbnPoint, string>.Create;
	try
		lines := TStringList.Create;
		try
			lines.Text := ALayout;
			for y := 0 to lines.Count - 1 do
			begin
				if ASlanted then
					slant := y - 1
				else
					slant := 0;

				tokens := TStringList.Create;
				try
					trimLine := StringReplace(lines[y], #32, '', [rfReplaceAll]);
					for i := 1 to trimLine.Length do
					begin
						if (ATokenSize = 1) then
							tokens.Add(trimLine[i])
						else if (i > 0) and (i mod ATokenSize = 0) then
							tokens.Add(trimLine[i - 1] + trimLine[i]);
					end;
					for i := 0 to tokens.Count - 1 do
					begin
						if Trim(tokens[i]).IsEmpty then
							Continue;

						x := (lines[y].IndexOf(tokens[i]) - slant) div (ATokenSize + 1);
						p.ZxcvbnPoint(x, y);
						positionTable.Add(p, tokens[i]);
					end;
				finally
					tokens.Free;
				end;
			end;

			FAdjacencyGraph := TObjectDictionary<Char, TStringList>.Create([doownsvalues]);
			for pair in positionTable do
			begin
				p := pair.Key;
				for c in pair.Value do
				begin
					FAdjacencyGraph.Add(c, TStringList.Create);
					if ASlanted then
						adjacentPoints := GetSlantedAdjacent(p)
					else
						adjacentPoints := GetAlignedAdjacent(p);

					for adjacent in adjacentPoints do
					begin
						// We want to include nulls so that direction is correspondent with index in the list
						if (positionTable.ContainsKey(adjacent)) then
							FAdjacencyGraph[c].Add(positionTable[adjacent])
						else
							FAdjacencyGraph[c].Add('');
					end;
				end;
			end;

			// Calculate average degree and starting positions, cf. init.coffee
			FStartingPositions := FAdjacencyGraph.Count;
			sum := 0;
			for sl in FAdjacencyGraph.Values do
			begin
				for s in sl do
					if not s.IsEmpty then
						Inc(sum);
			end;
			FAverageDegree := sum / StartingPositions;
		finally
			lines.Free;
		end;
	finally
		positionTable.Free;
	end;
end;

function TZxcvbnSpatialGraph.CalculateEntropy(AMatchLength: Integer; ATurns: Integer; AShiftedCount: Integer): Double;
var
	possibilities: Double;
	i, j: Integer;
	possible_turns: Integer;
	Entropy: Double;
	unshifted: Integer;
	sum: Double;
begin
	possibilities := 0;
	// This is an estimation of the number of patterns with length of matchLength or less with turns turns or less
	for i := 2 to AMatchLength do
	begin
		possible_turns := Min(ATurns, i - 1);
		for j := 1 to possible_turns do
			possibilities := possibilities + (StartingPositions * Power(AverageDegree, j) * Binomial(i - 1, j - 1));
	end;

	Entropy := LogN(2, possibilities);

	// Entropy increaeses for a mix of shifted and unshifted
	if (AShiftedCount > 0) then
	begin
		unshifted := AMatchLength - AShiftedCount;
		sum := 0;
		for i := 0 to Min(AShiftedCount, unshifted) + 1 do
			sum := sum + Binomial(AMatchLength, i);
		Entropy := Entropy + LogN(2, sum);
	end;

	Result := Entropy;
end;

{ TZxcvbnSpatialMatch }

procedure TZxcvbnSpatialMatch.CopyTo(AMatch: TZxcvbnSpatialMatch);
begin
	AMatch.Graph := Self.Graph;
	AMatch.Turns := Self.Turns;
	AMatch.ShiftedCount := Self.ShiftedCount;
end;

procedure TZxcvbnSpatialMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
		out WarningText, SuggestionsText: string);
begin
	if (Self.Turns = 1) then
		WarningText := GetWarning(zwStraightRow, LocaleName)
	else
		WarningText := GetWarning(zwShortKeyboardPatterns, LocaleName);

	SuggestionsText := GetSuggestion(zsUseLongerKeyboardPattern, LocaleName);
end;

{ TZxcvbnSpatialMatcher }

constructor TZxcvbnSpatialMatcher.Create;
begin
	FSpatialGraphs := GenerateSpatialGraphs;
end;

destructor TZxcvbnSpatialMatcher.Destroy;
begin
	if Assigned(FSpatialGraphs) then
		FSpatialGraphs.Free;
	inherited;
end;

procedure TZxcvbnSpatialMatcher.SpatialMatch(AGraph: TZxcvbnSpatialGraph; const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	i, j: Integer;
	turns: Integer;
	shiftedCount: Integer;
	lastDirection: Integer;
	shifted: Boolean;
	addMatch: TZxcvbnSpatialMatch;
	foundDirection: Integer;
	matches: TList<TZxcvbnMatch>;
begin
	matches := TList<TZxcvbnMatch>.Create;
	try
		i := 0;
		while (i < APassword.Length - 1) do
		begin
			turns := 0;
			shiftedCount := 0;
			lastDirection := -1;

			j := i + 1;
			while j < APassword.Length do
			begin
				foundDirection := AGraph.GetAdjacentCharDirection(APassword[j], APassword[j + 1], shifted);

				if (foundDirection <> -1) then
				begin
					// Spatial match continues
					if shifted then
						Inc(shiftedCount);
					if (lastDirection <> foundDirection) then
					begin
						Inc(turns);
						lastDirection := foundDirection;
					end;
				end
				else
					Break; // This character not a spatial match

				Inc(j);
			end;

			// Only consider runs of greater than two
			if (j - i > 2) then
			begin
				addMatch := TZxcvbnSpatialMatch.Create;
				addMatch.Pattern := SpatialPattern;
				addMatch.i := i;
				addMatch.j := j-1;
				addMatch.Token := APassword.Substring(i, j-i);
				addMatch.Graph := AGraph.Name;
				addMatch.Entropy := AGraph.CalculateEntropy(j-i, turns, shiftedCount);
				addMatch.Turns := turns;
				addMatch.ShiftedCount := shiftedCount;
				matches.Add(addMatch);
			end;

			i := j;
		end;

		AMatches.AddRange(matches);
	finally
		matches.Free;
	end;
end;

function TZxcvbnSpatialMatcher.GenerateSpatialGraphs: TObjectList<TZxcvbnSpatialGraph>;

// Keyboard layouts
const
	qwerty = '`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+' + #10 + '    qQ wW eE rR tT yY uU iI oO pP [{ ]} \|' + #10 + '     aA sS dD fF gG hH jJ kK lL ;: ''"' + #10 +
			'      zZ xX cC vV bB nN mM ,< .> /?';

const
	dvorak = '`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) [{ ]}' + #10 + '    ''" ,< .> pP yY fF gG cC rR lL /? =+ \|' + #10 + '     aA oO eE uU iI dD hH tT nN sS -_' + #10 +
			'      ;: qQ jJ kK xX bB mM wW vV zZ';

const
	keypad = '  / * -' + #10 + '7 8 9 +' + #10 + '4 5 6' + #10 + '1 2 3' + #10 + '  0 .';

const
	mac_keypad = '  = / *' + #10 + '7 8 9 -' + #10 + '4 5 6 +' + #10 + '1 2 3' + #10 + '  0 .';

begin
	Result := TObjectList<TZxcvbnSpatialGraph>.Create;

	Result.Add(TZxcvbnSpatialGraph.Create('qwerty', qwerty, True, 2));
	Result.Add(TZxcvbnSpatialGraph.Create('dvorak', dvorak, True, 2));
	Result.Add(TZxcvbnSpatialGraph.Create('keypad', keypad, False, 1));
	Result.Add(TZxcvbnSpatialGraph.Create('mac_keypad', mac_keypad, False, 1));
end;

procedure TZxcvbnSpatialMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	spatialGraph: TZxcvbnSpatialGraph;
begin
	for spatialGraph in FSpatialGraphs do
		SpatialMatch(spatialGraph, APassword, AMatches);
end;

{ TZxcvbnRepeatMatch }

procedure TZxcvbnRepeatMatch.CopyTo(AMatch: TZxcvbnRepeatMatch);
begin
	AMatch.BaseToken := Self.BaseToken;
	AMatch.RepeatCount := Self.RepeatCount;
end;

procedure TZxcvbnRepeatMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
		out WarningText, SuggestionsText: string);
begin
	if (Self.BaseToken.Length = 1) then
		WarningText := GetWarning(zwRepeatsLikeAaaEasy, LocaleName)
	else
		WarningText := GetWarning(zwRepeatsLikeAbcSlighterHarder, LocaleName);

	SuggestionsText := GetSuggestion(zsAvoidRepeatedWordsAndChars, LocaleName);
end;

{ TZxcvbnRepeatMatcher }

function TZxcvbnRepeatMatcher.CalculateEntropy(AMatch: TZxcvbnRepeatMatch): Double;
begin
	Result := LogN(2, PasswordCardinality(AMatch.BaseToken) * AMatch.RepeatCount);
end;

procedure TZxcvbnRepeatMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	addMatch: TZxcvbnRepeatMatch;
	matches: TList<TZxcvbnMatch>;
	i, j: Integer;
	lastIndex: Integer;
	greedy, lazy, lazyAnchored: TRegEx;
	greedyMatch, lazyMatch: System.RegularExpressions.TMatch;
	match, baseMatch: System.RegularExpressions.TMatch;
	BaseToken: string;
	gl: Integer;
begin
	matches := TList<TZxcvbnMatch>.Create;
	try
		greedy := TRegEx.Create('(.+)\1+');
		lazy := TRegEx.Create('(.+?)\1+');
		lazyAnchored := TRegEx.Create('^(.+?)\1+$');
		lastIndex := 0;

		while (lastIndex < APassword.Length) do
		begin
			greedyMatch := greedy.match(APassword, lastIndex, APassword.Length-lastIndex + 1);
			lazyMatch   := lazy.match(  APassword, lastIndex, APassword.Length-lastIndex + 1);
			if not greedyMatch.Success then
				Break;

			if lazyMatch.Success then
				gl := lazyMatch.Groups[0].Length
			else
				gl := 0;

			if (greedyMatch.Groups[0].Length > gl) then
			begin
				match := greedyMatch;
				baseMatch := lazyAnchored.match(match.Groups[0].Value);
				if baseMatch.Success then
					BaseToken := baseMatch.Groups[0].Value
				else
					BaseToken := match.Groups[0].Value;
			end
			else
			begin
				match := lazyMatch;
				BaseToken := match.Groups[1].Value;
			end;

			i := match.Groups[0].Index-1;
			j := match.Groups[0].Index-1 + match.Groups[0].Length-1;

			addMatch := TZxcvbnRepeatMatch.Create;
			addMatch.Pattern := RepeatPattern;
			addMatch.Token := APassword.Substring(i, j-i+1);
			addMatch.i := i;
			addMatch.j := j;
			addMatch.RepeatCount := match.Groups[0].Length div BaseToken.Length;
			addMatch.BaseToken := BaseToken;
			addMatch.Entropy := CalculateEntropy(addMatch);
			matches.Add(addMatch);

			lastIndex := j+1;
		end;

		AMatches.AddRange(matches);
	finally
		matches.Free;
	end;
end;

{ TZxcvbnRegexMatcher }

constructor TZxcvbnRegexMatcher.Create(APattern: string; ACardinality: Integer; APerCharCardinality: Boolean = True; AMatcherName: string = 'regex');
begin
	Create(TRegEx.Create(APattern), ACardinality, APerCharCardinality, AMatcherName);
end;

constructor TZxcvbnRegexMatcher.Create(AMatchRegex: TRegEx; ACardinality: Integer; APerCharCardinality: Boolean = True; AMatcherName: string = 'regex');
begin
	FMatchRegex := AMatchRegex;
	FMatcherName := AMatcherName;
	FCardinality := ACardinality;
	FPerCharCardinality := APerCharCardinality;
end;

procedure TZxcvbnRegexMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	reMatches: System.RegularExpressions.TMatchCollection;
	rem: System.RegularExpressions.TMatch;
	pwMatches: TList<TZxcvbnMatch>;
	addMatch: TZxcvbnMatch;
begin
	reMatches := FMatchRegex.matches(APassword);

	pwMatches := TList<TZxcvbnMatch>.Create;
	try
		for rem in reMatches do
		begin
			addMatch := TZxcvbnMatch.Create;
			addMatch.Pattern := FMatcherName;
			addMatch.i := rem.Index - 1;
			addMatch.j := rem.Index - 1 + rem.Length - 1;
			addMatch.Token := APassword.Substring(rem.Index - 1, rem.Length);
			if FPerCharCardinality then
				addMatch.Entropy := LogN(2, Power(FCardinality, rem.Length))
			else
				addMatch.Entropy := LogN(2, FCardinality);
			pwMatches.Add(addMatch);
		end;

		AMatches.AddRange(pwMatches);
	finally
		pwMatches.Free;
	end;
end;

{ TZxcvbnSequenceMatch }

procedure TZxcvbnSequenceMatch.CopyTo(AMatch: TZxcvbnSequenceMatch);
begin
	AMatch.SequenceName := Self.SequenceName;
	AMatch.SequenceSize := Self.SequenceSize;
	AMatch.Ascending := Self.Ascending;
end;

procedure TZxcvbnSequenceMatch.GetMatchFeedback(AIsSoleMatch: Boolean; LocaleName: string;
		out WarningText, SuggestionsText: string);
begin
	WarningText :=     GetWarning(zwSequenceAbcEasy, LocaleName);
	SuggestionsText := GetSuggestion(zsAvoidSequences, LocaleName);

	// todo: add support for recent_year
end;

{ TZxcvbnSequenceMatcher }

function TZxcvbnSequenceMatcher.CalculateEntropy(AMatch: string; AAscending: Boolean): Double;
var
	firstChar: Char;
	BaseEntropy: Double;
begin
	firstChar := AMatch[1];

	// XXX: This entropy calculation is hard coded, ideally this would (somehow) be derived from the sequences above
	if ((firstChar = 'a') or (firstChar = '1')) then
		BaseEntropy := 1
	else if (('0' <= firstChar) and (firstChar <= '9')) then
		BaseEntropy := LogN(2, 10) // Numbers
	else if (('a' <= firstChar) and (firstChar <= 'z')) then
		BaseEntropy := LogN(2, 26) // Lowercase
	else
		BaseEntropy := LogN(2, 26) + 1; // + 1 for uppercase

	if (not AAscending) then
		BaseEntropy := BaseEntropy + 1; // Descending instead of ascending give + 1 bit of entropy

	Result := BaseEntropy + LogN(2, AMatch.Length);
end;

procedure TZxcvbnSequenceMatcher.MatchPassword(const APassword: string; var AMatches: TList<TZxcvbnMatch>);
var
	seqs: TStringList;
	s: string;
	matches: TList<TZxcvbnMatch>;
	i, j: Integer;
	seq: string;
	ixI, ixJ: Integer;
	Ascending: Boolean;
	startIndex: Integer;
	len: Integer;
	seqIndex: Integer;
	addMatch: TZxcvbnSequenceMatch;
	match: string;
begin
	seqs := TStringList.Create;
	try
		// Sequences to check should be the set of sequences and their reverses (i.e. want to match "abcd" and "dcba")
		for s in Sequences do
			seqs.Add(s);
		for s in Sequences do
			seqs.Add(StringReverse(s));

		matches := TList<TZxcvbnMatch>.Create;
		try
			i := 0;
			while i < APassword.Length - 1 do
			begin
				j := i + 1;

				seq := '';
				// Find a sequence that the current and next characters could be part of
				for s in seqs do
				begin
					ixI := s.IndexOf(APassword[i + 1]);
					ixJ := s.IndexOf(APassword[j + 1]);
					if (ixJ = ixI + 1) then
					begin
						seq := s;
						Break;
					end;
				end;

				// This isn't an ideal check, but we want to know whether the sequence is ascending/descending to keep entropy
				// calculation consistent with zxcvbn
				Ascending := False;
				for s in Sequences do
				begin
					if (seq = s) then
					begin
						Ascending := True;
						Break;
					end;
				end;

				// seq will be empty when there are no matching sequences
				if (seq <> '') then
				begin
					startIndex := seq.IndexOf(APassword[i + 1]);

					// Find length of matching sequence (j should be the character after the end of the matching subsequence)
					while (j < APassword.Length) and (startIndex + j - i < seq.Length) and (seq[startIndex + j - i + 1] = APassword[j + 1]) do
					begin
						Inc(j);
					end;

					len := j - i;

					// Only want to consider sequences that are longer than two characters
					if (len > 2) then
					begin
						// Find the sequence index so we can match it up with its name
						seqIndex := seqs.IndexOf(seq);
						if (seqIndex >= Length(Sequences)) then
							seqIndex := seqIndex - Length(Sequences); // match reversed sequence with its original

						match := APassword.Substring(i, len);

						addMatch := TZxcvbnSequenceMatch.Create;
						addMatch.i := i;
						addMatch.j := j - 1;
						addMatch.Token := match;
						addMatch.Pattern := SequencePattern;
						addMatch.Entropy := CalculateEntropy(match, Ascending);
						addMatch.Ascending := Ascending;
						addMatch.SequenceName := SequenceNames[seqIndex];
						addMatch.SequenceSize := Sequences[seqIndex].Length;
						matches.Add(addMatch);
					end;
				end;

				i := j;
			end;

			AMatches.AddRange(matches);
		finally
			matches.Free;
		end;
	finally
		seqs.Free;
	end;
end;

function Encode85(const InBuffer: RawByteString; InsertLineBreaks: Boolean = True): string;
var
	c: Byte;
	i: Integer;
	Count: Integer;
	tuple: Longword;
	lineLength: Integer;
const
	LINE_LENGTH = 120; // 120 characters ==> 96 bytes

	procedure Encode;
	var
		p: PByte;
		i: Integer;
		buffer: array [0 .. 4] of Byte;
	begin
		p := @buffer[0];
		for i := 0 to 4 do
		begin
			p^ := tuple mod 85;
			tuple := tuple div 85;
			Inc(p);
		end;

		for i := 0 to Count do
		begin
			Dec(p);
			Result := Result + Char(p^ + Ord('!')); // $21);
			Inc(lineLength);
			if (InsertLineBreaks) and (lineLength >= LINE_LENGTH) then
			begin
				Result := Result + #13#10;
				lineLength := 0;
			end;
		end;
	end;

begin
	{
	  InsertLineBreaks:
	  True:  Inserts line breaks after every 120 characters in the string representation.
	  False: Does not insert line breaks after every 120 characters in the string representation.
	}
	Result := '';
	Count := 0;
	tuple := 0;
	lineLength := 0;

	for i := 1 to Length(InBuffer) do
	begin
		c := Byte(InBuffer[i]);
		Inc(Count);
		case Count of
		1:
			tuple := tuple or (c shl 24);
		2:
			tuple := tuple or (c shl 16);
		3:
			tuple := tuple or (c shl 8);
		4:
			begin
				tuple := tuple or c;
				if tuple = 0 then
					Result := Result + 'z'
				else
					Encode;
				Count := 0;
				tuple := 0;
			end;
		end;
	end;

	// Encode any final partial tuple
	if Count > 0 then
		Encode;
end;

/// <summary> Decode a base85 encoded data into bytes </summary>
function Decode85(const s: string): RawByteString;
var
	c: Char;
	i: Integer;
	Count: Integer;
	tuple: Longword;
const
	Pow85: array [0 .. 4] of Longword = (85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1);

	procedure Decode(Count: Integer);
	begin
		case Count of
		4:
			Result := Result + AnsiChar(tuple shr 24) + AnsiChar(tuple shr 16) + AnsiChar(tuple shr 8) + AnsiChar(tuple);
		3:
			Result := Result + AnsiChar(tuple shr 24) + AnsiChar(tuple shr 16) + AnsiChar(tuple shr 8);
		2:
			Result := Result + AnsiChar(tuple shr 24) + AnsiChar(tuple shr 16);
		1:
			Result := Result + AnsiChar(tuple shr 24);
		end;
	end;

begin
	Count := 0;
	tuple := 0;
	Result := '';

	for i := 1 to Length(s) do
	begin
		c := s[i];
		case c of
		'z':
			Result := Result + #$00#$00#$00#$00;
		'!' .. 'u':
			begin
				tuple := tuple + Longword(Byte(AnsiChar(c)) - $21) * Pow85[Count];
				Inc(Count);
				if Count = 5 then
				begin
					Decode(4);
					Count := 0;
					tuple := 0;
				end;
			end;
		#13, #10, #32, #9: { ignore whitespace (CR, LR, Space, Tab) }
			;
		// '~': {"~>" is used to pad short final block};
	else
		raise Exception.CreateFmt('Invalid character "%s" in ASCII85 string', [s[i]]);
		end;
	end;

	if Count > 0 then
	begin
		Dec(Count);
		tuple := tuple + Pow85[Count];
		Decode(Count);
	end;
end;

function CompressString(const s: string): string;
var
	data: Utf8String;
	comp: RawByteString;
begin
	if s = '' then
	begin
		Result := '';
		Exit;
	end;

	data := Utf8String(s); // convert to utf8
	comp := ZLibEx.ZCompressStr(data);
	Result := Encode85(comp, False);
end;

function DecompressString(const s: string): string;
var
	comp: RawByteString;
begin
	if s = '' then
	begin
		Result := '';
		Exit;
	end;

	comp := Decode85(s);
	Result := string(ZDecompressStr(comp));
end;

procedure BuildFrequencyLists(DataPath: string; OutputFilename: string='Zxcvbn_FrequencyLists.inc');
var
	s: string;

	function GetZB64File(AFilePath: string): string;
	var
		comp: string;
	begin
		comp := TFile.ReadAllText(AFilePath);
		comp := CompressString(comp);
		//comp := DecompressString(Result);

		Result := '';
		while Length(comp) > 0 do
		begin
			if Result <> '' then
					Result := Result+#13#10;
			Result := Result+'		'+QuotedStr(Copy(comp, 1, 120));
			Delete(comp, 1, 120);
			if comp <> '' then
				Result := Result+'+'
			else
				Result := Result+';';
		end;
	end;

begin
	{
		Parse the files in DataPath, e.g.:

			english_wikipedia.txt
			female_names.txt
			male_names.txt
			passwords.txt
			surnames.txt
			us_tv_and_film.txt

		And do the same thing as build_frequency_lists.py
		https://github.com/dropbox/zxcvbn/blob/master/data-scripts/build_frequency_lists.py

	To convert them into a Zxcvbn_FrequencyLists.inc include file:

	//Generated by BuildFrequencyLists
	const
		Senglish_wikipedia = 'base85';
		Sfemale_names = 'base85';
		Smale_names = 'base85';
		Spasswords = 'base85';
		Ssurnames = 'base85';
		Sus_tv_and_film = 'base85';
}
	if DataPath = '' then
		DataPath := 'D:\Develop\GitHub\ZXCVBN-Delphi-Pascal\dict\Filtered\';

	DataPath := IncludeTrailingPathDelimiter(DataPath);

	s :=
		'//'+#13#10+
		'//This code was generated by a tool'+#13#10+
		'//'+#13#10+
		'const'+#13#10+
		'	Senglish_wikipedia = '+	#13#10+GetZB64File(DataPath+'english_wikipedia.lst')+#13#10+#13#10+

		'	Sfemale_names = '+		#13#10+GetZB64File(DataPath+'female_names.lst')+#13#10+#13#10+

		'	Smale_names = '+			#13#10+GetZB64File(DataPath+'male_names.lst')+#13#10+#13#10+

		'	Spasswords = '+			#13#10+GetZB64File(DataPath+'passwords.lst')+#13#10+#13#10+

		'	Ssurnames  = '+			#13#10+GetZB64File(DataPath+'surnames.lst')+#13#10+#13#10+

		'	Sus_tv_and_film = '+		#13#10+GetZB64File(DataPath+'us_tv_and_film.lst')+#13#10+#13#10+

		'{$DEFINE zxcvbn-fl}';

	TFile.WriteAllText(OutputFilename, s);
end;

end.

# JWT -json web token

JSON Web Tokens are an open, industry standard `RFC 7519` method for representing claims securely between two parties.
to decode, verify and generate JWT.
A JWT token is a cryptographically signed token which the server generates and gives to the client. The client uses JWT for making various requests to the server.

In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned and must be saved locally (typically in local or session storage, but cookies can also be used), instead of the traditional approach of creating a session in the server and returning a cookie. For unattended processes, the client may also authenticate directly by generating and signing its own JWT with a pre-shared secret and pass it to a OAuth compliant service.

`Authentication` is the process of ascertaining that somebody really is who they claim to be.

for example : `login + password (who you are)`

`Authorization` refers to rules that determine who is allowed to do what. E.g. Adam may be authorized to create and delete databases, while Usama is only authorised to read.

for example :  `permissions (what you are allowed to do)`


# Fields of a JWT token

A JSON Web Token consists of three parts which are separated using `.(dot)`

for example: 
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxZGQ5MDEwYy00MzI4LTRoZjNiOWU2LTc3N2Q4NDhlOTM3NSIsImF1dGhvcml6ZWQiOmZhbHNlfQ.vI7thh64mzXp_WMKZIedaKR4AF4trbvOHEpm2d62qIQ`

`Header` Identifies which algorithm is used to generate the signature. In the below example, HS256 indicates that this token is signed using HMAC-SHA256.

Typical cryptographic algorithms used are HMAC with SHA-256 (HS256) and RSA signature with SHA-256 (RS256). JWA (JSON Web Algorithms) RFC 7518 introduces many more for both authentication and encryption.

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

## Standard Header Fields

`typ (Token type) `	    
If present, it must be set to a registered IANA Media Type.

`cty (Content type)`
If nested signing or encryption is employed, it is recommended to set this to JWT; otherwise, omit this field.[1]

`alg (algorithm)`
Message authentication code algorithm 	The issuer can freely set an algorithm to verify the signature on the token. However, some supported algorithms are insecure.[10]

`kid (Key ID)` 	
A hint indicating which key the client used to generate the token signature. The server will match this value to a key on file in order to verify that the signature is valid and the token is authentic.

`x5c 	(x.509 Certificate Chain)` 
A certificate chain in RFC4945 format corresponding to the private key used to generate the token signature. The server will use this information to verify that the signature is valid and the token is authentic.

`x5u 	(x.509 Certificate Chain URL)` 
A URL where the server can retrieve a certificate chain corresponding to the private key used to generate the token signature. The server will retrieve and use this information to verify that the signature is authentic.

`crit (Critical) `
A list of headers that must be understood by the server in order to accept the token as valid 


`Payload` Contains a set of claims. The JWT specification defines seven Registered Claim Names, which are the standard fields commonly included in tokens.[1] Custom claims are usually also included, depending on the purpose of the token.
This example has the standard Issued At Time claim (`iat`) and a custom claim (`loggedInAs`).


```json
{
  "loggedInAs": "admin",
  "iat": 1422779638
}
```

## Standard Payload Fields

`iss (Issuer)` 	
Identifies principal that issued the JWT.

`sub (Subject)` 
Identifies the subject of the JWT.

`aud (Audience)` 
Identifies the recipients that the JWT is intended for. Each principal intended to process the JWT must identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT must be rejected.

`exp (Expiration Time)` 
Identifies the expiration time on and after which the JWT must not be accepted for processing. The value must be a NumericDate:[9] either an integer or decimal, representing seconds past `1970-01-01 00:00:00Z`.

`nbf (Not Before)` 
Identifies the time on which the JWT will start to be accepted for processing. The value must be a NumericDate.

`iat (Issued at)` 
Identifies the time at which the JWT was issued. The value must be a NumericDate.

`jti (JWT ID)` 
Case-sensitive unique identifier of the token even among different issuers. 


`Signature` It is generated using the secret (provided by the user), encoded header, and payload.
To Securely validates the token. The signature is calculated by encoding the header and payload using Base64url Encoding RFC 4648 and concatenating the two together with a period separator. That string is then run through the cryptographic algorithm specified in the header. This example uses HMAC-SHA256 with a shared secret (public key algorithms are also defined). The Base64url Encoding is similar to base64, but uses different non-alphanumeric characters and omits padding.

```go
HMAC_SHA256(
  secret,
  base64urlEncoding(header) + '.' +
  base64urlEncoding(payload)
)
```


# to use

first make sure you have intialized your root go module like `github.com/shubhammishra-1`

Install jwt go package

```go 
go get github.com/golang-jwt/jwt/v5
```

Import this library in your go program

`import ("github.com/golang-jwt/jwt/v5")`


# Creating a JWT token

there are two methods used to create token

# jwt.New(method SigningMethod, opts ...TokenOption) *Token
New() creates a new Token with the specified signing method and an empty map of claims. Additional options can be specified, but are currently unused. 

# jwt.NewWithClaims(method SigningMethod, claims Claims, opts ...TokenOption) *Token
NewWithClaims() creates a new Token with the specified signing method and claims. Additional options can be specified, but are currently unused.

```go 
mySigningKey := []byte("AllYourBase")

type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}
// Create claims with multiple fields populated
claims := MyCustomClaims{
	"bar",
	jwt.RegisteredClaims{
		// A usual scenario is to set the expiration time relative to the current time
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "test",
		Subject:   "somebody",
		ID:        "1",
		Audience:  []string{"somebody_else"},
	},
}

fmt.Printf("foo: %v\n", claims.Foo)

// Create claims while leaving out some of the optional fields
claims = MyCustomClaims{
	"bar",
	jwt.RegisteredClaims{
		// Also fixed dates can be used for the NumericDate
		ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
		Issuer:    "test",
	},
}

token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
ss, err := token.SignedString(mySigningKey)
fmt.Println(ss, err)
```

# About SigningMethod
SigningMethod is an interface it can be used to add new methods for signing or verifying tokens. It takes a decoded signature as an input in the Verify function and produces a signature in Sign. The signature is then usually base64 encoded as part of a JWT

```go
type SigningMethod interface {
	Verify(signingString string, sig []byte, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) ([]byte, error)     // Returns signature or error
	Alg() string                                                    // returns the alg identifier for this method (example: 'HS256')
}
```

There are many singin methods but mostly `jwt.SigningMethodHMAC` used

`SigningMethodHMAC` implements the HMAC-SHA family of signing methods. Expects key type of []byte for both signing and validation 

```go
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}
```

# About RegisteredClaims
RegisteredClaims are a structured version of the JWT Claims Set, restricted to Registered Claim Names, as referenced at `https://datatracker.ietf.org/doc/html/rfc7519#section-4.1`
This type can be used on its own, but then additional private and public claims embedded in the JWT will not be parsed. The typical use-case therefore is to embedded this in a user-defined claim type. 

```go 
 type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}
```

# About Token
Token represents a JWT Token struct. Different fields will be used depending on whether you're creating or parsing/verifying a token. 

```go 
type Token struct {
	Raw       string                 // Raw contains the raw token.  Populated when you [Parse] a token
	Method    SigningMethod          // Method is the signing method used or to be used
	Header    map[string]interface{} // Header is the first segment of the token in decoded form
	Claims    Claims                 // Claims is the second segment of the token in decoded form
	Signature []byte                 // Signature is the third segment of the token in decoded form.  Populated when you Parse a token
	Valid     bool                   // Valid specifies if the token is valid.  Populated when you Parse/Verify a token
}
```

# About Claims

Claims is an interface that represent any form of a JWT Claims Set according to `https://datatracker.ietf.org/doc/html/rfc7519#section-4`. In order to have a common basis for validation, it is required that an implementation is able to supply at least the claim names provided in `https://datatracker.ietf.org/doc/html/rfc7519#section-4.1` namely `exp`, `iat`, `nbf`, `iss`, `sub` and `aud`. 


```go 
type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}
```

# About jwt.MapClaims map[string]interface{}

MapClaims is a claims type that uses the map[string]interface{} for JSON decoding. This is the default claims type if you don't supply one. 

# Verification of a jwt token

just like creating a token there exits two ways with and without `Claims`
Verifcation can also be done in two ways depending upon token.

# jwt.Parse(tokenString string, keyFunc Keyfunc, options ...ParserOption) (*Token, error)

Parse() parses, validates, verifies the signature and returns the parsed token. keyFunc will receive the parsed token and should return the cryptographic key for verifying the signature. The caller is strongly encouraged to set the WithValidMethods option to validate the 'alg' claim in the token matches the expected algorithm. For more details about the importance of validating the 'alg' claim, see https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/


# jwt.ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, options ...ParserOption) (*Token, error)

ParseWithClaims() is a shortcut for NewParser().ParseWithClaims().

Note: If you provide a custom claim implementation that embeds one of the standard claims (such as RegisteredClaims), make sure that a) you either embed a non-pointer version of the claims or b) if you are using a pointer, allocate the proper memory for it before passing in the overall claims, otherwise you might run into a panic. 


# About Keyfunc func(*Token) (interface{}, error)
Keyfunc will be used by the Parse methods as a callback function to supply the key for verification. The function receives the parsed, but unverified Token. This allows you to use properties in the Header of the token (such as `kid`) to identify which key to use.
The returned interface{} may be a single key or a VerificationKeySet containing multiple keys. 

# About ParserOption func(*Parser)

ParserOption is used to implement functional-style options that modify the behavior of the parser. To add new options, just create a function (ideally beginning with With or Without) that returns an anonymous function that takes a *Parser type as input and manipulates its configuration accordingly. 

```go 
type Parser struct {
	// contains filtered or unexported fields
}
// explore about parser here https://pkg.go.dev/github.com/golang-jwt/jwt/v5#Parser
```

# Refernces

```https://jwt.io/```

```https://pkg.go.dev/github.com/golang-jwt/jwt/v5```

```https://datatracker.ietf.org/doc/html/rfc7519```

For Cookie based Authentication see these articles

```https://www.sohamkamani.com/golang/jwt-authentication/```

```https://www.sohamkamani.com/golang/session-cookie-authentication/```
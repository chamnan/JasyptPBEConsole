# Jasypt PBE Console

Interactive console application for encrypting and decrypting strings using [Jasypt](http://www.jasypt.org/) Password-Based Encryption (PBE). Fully compatible with the `PooledPBEStringEncryptor` produced by [jasypt-spring-boot-starter](https://github.com/ulisesbocchio/jasypt-spring-boot).

Use this tool to generate `ENC(...)` values for Spring Boot `application.properties` / `application.yml`, or to decrypt existing ones for inspection.

## Build

```bash
mvn clean package
```

## Usage

```bash
java -jar target/jasypt-pbe-console-1.0.0.jar [password=xxx] [algorithm=xxx] [iterations=xxx]
```

All flags are optional and can appear in any order. Argument values may contain `${ENV_VAR}` placeholders, which are resolved against environment variables at runtime (e.g. `password=${ENV_VAR_PASSWORD}`). An unresolvable placeholder is left verbatim, mirroring `jasypt-spring-boot-starter`.

If `password` is omitted from the command line, it is read from the `ENV_VAR_PASSWORD` environment variable.

### Arguments

| Flag         | Required | Default                                   | Description                      |
|--------------|----------|-------------------------------------------|----------------------------------|
| password=    | No       | `$ENV_VAR_PASSWORD`                       | Encryption/decryption password   |
| algorithm=   | No       | `PBEWithMD5AndDES`                        | PBE algorithm                    |
| iterations=  | No       | `1000`                                    | Key obtention iterations         |

### Examples

```bash
# Password from the environment variable
java -jar target/jasypt-pbe-console-1.0.0.jar

# With password only
java -jar target/jasypt-pbe-console-1.0.0.jar password=mySecretPassword

# Password via a ${...} placeholder resolved against the environment
java -jar target/jasypt-pbe-console-1.0.0.jar 'password=${ENV_VAR_PASSWORD}'

# With all flags, any order
java -jar target/jasypt-pbe-console-1.0.0.jar algorithm=PBEWithMD5AndDES password=mySecretPassword iterations=2000

# Equivalent, different order
java -jar target/jasypt-pbe-console-1.0.0.jar iterations=2000 password=mySecretPassword
```

### Interactive Menu

Once started, choose from:

1. **Encrypt a string** — outputs the encrypted value in both raw Base64 and `ENC(...)` wrapped formats
2. **Decrypt a string** — accepts raw Base64 or `ENC(Base64)` format, outputs the original plaintext
3. **Exit**

### Encryption Output

When you encrypt a string, two formats are displayed:

```
--- Encrypted ---
Raw : AbCdEf123...
ENC : ENC(AbCdEf123...)
-----------------
```

- **Raw** — the Base64 ciphertext. Use this when decrypting again with this tool.
- **ENC** — the raw value wrapped in `ENC(...)`. Paste this directly into your Spring Boot properties file (e.g. `my.secret=ENC(AbCdEf123...)`).

### Decryption

Decryption accepts either format — raw Base64 or `ENC(Base64)`. The `ENC()` wrapper is automatically stripped.

If decryption fails (wrong password, invalid input, or mismatched algorithm/iterations), a clear error message is shown instead of a stack trace.

## Compatibility

The encryptor configuration mirrors exactly what `jasypt-spring-boot-starter` creates:

- `PooledPBEStringEncryptor` with `SimpleStringPBEConfig`
- `RandomSaltGenerator` for salt generation
- `RandomIvGenerator` for IV generation
- `base64` string output type

Encrypted values produced by this tool can be used directly in Spring Boot `application.properties` as `ENC(...)` values, and vice versa.

## Requirements

- Java 17+
- Maven 3.6+

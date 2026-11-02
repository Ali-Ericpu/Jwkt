# JWKT Spring Boot Starter

JWKT 的 Spring Boot 自动配置模块，支持 **Spring Boot 3.5.x** 与 **Spring Boot 4.1.x**。

它把 JWKT 的 `JwtParser`、`JwktSigner` 和 `JwktTemplate` 注册为 Spring Bean，并根据 `jwkt.*` 配置加载 HMAC、RSA 或 EC 密钥。starter 本身不依赖任何 JSON 框架；如果 classpath 中存在 Jackson 2（Boot 3）或 Jackson 3（Boot 4），会自动注册对应的 `JsonCodec`，也可以完全使用自定义 codec。

- **坐标**：`com.rainccup:jwkt-spring-boot-starter:0.1.0`
- **包名**：`com.rainccup.jwkt.spring`
- **Java**：17+
- **Boot 基线**：编译于 Boot 3.5.16，并在 Boot 4.1.2 上通过独立测试

## 安装

先在项目根目录发布到本地 Maven 仓库：

```bash
./gradlew publishToMavenLocal
```

然后引入：

```kotlin
dependencies {
    implementation("com.rainccup:jwkt-spring-boot-starter:0.1.0")
    // 已经是 Web 应用时通常不需要再显式引入
    implementation("org.springframework.boot:spring-boot-starter-web")
}
```

如果使用 Boot 4 的 Jackson 3，请确保项目中有：

```kotlin
implementation("org.springframework.boot:spring-boot-starter-jackson")
```

Boot 3 对应的是 `spring-boot-starter-json`。这两个 starter 通常已经由 Web starter 传递引入。

## 快速开始

### application.yml

```yaml
jwkt:
  algorithm: HS256
  issuer: https://example.com
  audience:
    - api
  secret: "0123456789abcdef0123456789abcdef" # 至少 32 字节
  expires-in: 15m
  include-issued-at: true
  required-claims:
    - tenant
```

### 注入并使用

```kotlin
import com.rainccup.jwkt.spring.JwktTemplate
import org.springframework.stereotype.Service

@Service
class TokenService(
    private val jwkt: JwktTemplate,
) {

    fun issue(userId: String, tenant: String): String =
        jwkt.issue {
            subject(userId)
            claim("tenant", tenant)
            claim("role", "user")
        }

    fun verify(token: String) =
        jwkt.parse(token)
}
```

`JwktTemplate` 同时持有 signer 和 parser，适合大多数签发 + 校验场景。也可以分别注入：

- `JwktSigner`：只负责签发
- `JwtParser`：只负责校验
- `JwsAlgorithm`：当前算法
- `JwktProperties`：原始配置

## 自动配置行为

| 条件 | 注册的 Bean |
| --- | --- |
| 任意 key 配置 | `JwktKeyMaterial` |
| 可验签的 key（secret 或 public-key） | `JwtParser` |
| 可签发的 key（secret 或 private-key） | `JwktSigner` |
| 同时有 parser 和 signer | `JwktTemplate` |
| 未定义 `Clock` | `Clock.systemUTC()` |
| 未定义 `JwsAlgorithm` | 按 `jwkt.algorithm` 解析内置算法 |
| classpath 有 Jackson 2 且无 `JsonCodec` | `Jackson2JsonCodec` |
| classpath 有 Jackson 3 且无 `JsonCodec` | `Jackson3JsonCodec` |

所有 Bean 都使用 `@ConditionalOnMissingBean`，应用可以通过定义同类型 Bean 完全接管。设置 `jwkt.enabled=false` 可关闭整套自动配置。

## 密钥配置

### HMAC

```yaml
jwkt:
  algorithm: HS256
  secret: "0123456789abcdef0123456789abcdef"
```

或使用 Base64（标准 Base64 与 URL-safe Base64 均可）：

```yaml
jwkt:
  algorithm: HS256
  secret-base64: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
```

`HS256` / `HS384` / `HS512` 分别要求至少 32 / 48 / 64 字节。`secret` 与 `secret-base64` 只能配置一个，且不能与 PEM 同时使用。

### RSA

```yaml
jwkt:
  algorithm: RS256
  private-key: classpath:keys/private.pem   # 签发
  public-key: classpath:keys/public.pem    # 校验
```

- 私钥必须是 PKCS#8 PEM（`BEGIN PRIVATE KEY`）
- 公钥必须是 X.509 PEM（`BEGIN PUBLIC KEY`）
- RSA 密钥至少 2048 位
- 只配置私钥时只有 signer；只配置公钥时只有 parser

PKCS#1 需要转换：

```bash
openssl pkcs8 -topk8 -nocrypt -in private-pkcs1.pem -out private.pem
openssl rsa -in private-pkcs1.pem -pubout -out public.pem
```

### ECDSA

```yaml
jwkt:
  algorithm: ES256
  private-key: classpath:keys/ec-private.pem
  public-key: classpath:keys/ec-public.pem
```

`ES256` / `ES384` / `ES512` 分别要求 P-256 / P-384 / P-521 曲线。曲线不匹配会在启动时直接失败。

### 自定义算法

先注册一个 `JwsAlgorithm` Bean，并让 `jwkt.algorithm` 与它的 `name` 一致：

```kotlin
@Configuration
class JwtAlgorithmConfiguration {

    @Bean
    fun ed25519(): JwsAlgorithm = object : JwsAlgorithm {
        override val name: String = "EdDSA"

        // 实现 sign / verify
    }
}
```

使用 PEM 时还需要指定 `jwkt.key-algorithm`（例如 `Ed25519`）：

```yaml
jwkt:
  algorithm: EdDSA
  key-algorithm: Ed25519
  private-key: classpath:keys/ed25519-private.pem
  public-key: classpath:keys/ed25519-public.pem
```

## 自定义 JsonCodec

starter 不强制使用 Jackson。定义自己的 `JsonCodec` Bean 即可，例如 Gson、kotlinx.serialization 或公司内部协议：

```kotlin
@Configuration
class JsonConfiguration {

    @Bean
    fun jsonCodec(): JsonCodec = MyJsonCodec()
}
```

只要容器中存在 `JsonCodec`，Jackson 自动适配器就会退让。

## Jackson 适配器

### Boot 3 / Jackson 2

```kotlin
val codec = Jackson2JsonCodec(objectMapper)
```

### Boot 4 / Jackson 3

```kotlin
val codec = Jackson3JsonCodec(jsonMapper)
```

两个适配器都是公开类，也可以不经过自动配置直接使用。它们会把 Jackson 异常包装成 `JwtException.JsonCodecException`。

## 自定义校验器

实现 `JwtValidator` 并注册为 Bean，starter 会自动把它加到 parser：

```kotlin
@Bean
fun tenantValidator(): JwtValidator = JwtValidator { jwt ->
    if (jwt.claims["tenant"] == null) {
        throw JwtException.MissingClaim("tenant")
    }
}
```

也可以直接定义自己的 `JwtParser`、`JwktSigner` 或 `JwktTemplate` Bean，自动配置会回退。

## 自定义 Clock

```kotlin
@Bean
fun clock(): Clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC)
```

签发和 `exp` / `nbf` 校验都会使用这个 `Clock`。

## 配置项

| 属性 | 默认值 | 说明 |
| --- | --- | --- |
| `jwkt.enabled` | `true` | 是否启用 starter |
| `jwkt.algorithm` | `HS256` | JOSE 算法名 |
| `jwkt.issuer` | 无 | 写入并校验 `iss` |
| `jwkt.audience` | 空 | 写入并校验 `aud`，可多个 |
| `jwkt.key-id` | 无 | 写入 `kid` |
| `jwkt.secret` | 无 | UTF-8 HMAC secret |
| `jwkt.secret-base64` | 无 | Base64 HMAC secret |
| `jwkt.private-key` | 无 | PKCS#8 PEM 私钥 Resource |
| `jwkt.public-key` | 无 | X.509 PEM 公钥 Resource |
| `jwkt.key-algorithm` | 无 | PEM 的 JCA 算法；RS*/ES* 可自动推断 |
| `jwkt.clock-skew` | `0s` | `exp` / `nbf` 允许偏差 |
| `jwkt.expires-in` | `15m` | signer 默认有效期 |
| `jwkt.include-issued-at` | `true` | 是否自动写 `iat` |
| `jwkt.require-expiration` | `true` | 是否拒绝缺少 `exp` 的 token |
| `jwkt.headers` | 空 | 额外 protected header |
| `jwkt.claims` | 空 | 额外默认 claims |
| `jwkt.required-claims` | 空 | parser 必须存在的 claims |

`jwkt.headers` 不允许设置 `alg`、`b64`、`crit`（大小写不敏感）。显式配置的 `jwkt.headers` / `jwkt.claims` 最后应用，可覆盖 `expires-in` / `include-issued-at` 生成的默认值；如无特殊需要，不要在这里设置注册声明。

## 与核心库的关系

starter 通过 `api(project(":"))` 暴露核心库，因此应用不需要再单独声明 `jwkt`。核心库仍然是零 JSON 运行时依赖；starter 也不会把 Jackson 2 或 Jackson 3 传递为运行时依赖，只有对应适配器在应用 classpath 有该 Jackson 版本时才会启用。

## 测试

```bash
# Boot 3.5.16
./gradlew :jwkt-spring-boot-starter:test

# Boot 4.1.2
./gradlew :jwkt-spring-boot-starter:boot4Test

# 两个版本一起跑
./gradlew :jwkt-spring-boot-starter:check
```

测试覆盖 HMAC/RSA/EC 密钥加载、PEM 解析、自动配置回退、必需声明、Jackson 2/3 适配器，以及通过 `AutoConfiguration.imports` 的完整上下文启动。

## License

Apache License 2.0，见 [../LICENSE](../LICENSE)。

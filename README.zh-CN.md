# JWKT

一个轻量、无 JSON 运行时依赖的 Kotlin/JVM JWT（JWS Compact）生成与解析库。

JWKT 只做一件事：把 header / claims 交给你选择的 JSON 实现来编码，然后完成签名、验签和标准声明校验。库本身不绑定 Jackson、Gson、kotlinx.serialization 或任何其他 JSON 框架，运行时只依赖 Kotlin 标准库。

- **包名**：`com.rainccup.jwkt`
- **JVM**：17+
- **Kotlin**：2.4.20
- **Gradle**：9.8.0
- **支持算法**：HS256/384/512、RS256/384/512、ES256/384/512，以及用户自定义 `JwsAlgorithm`
- **支持格式**：JWS Compact Serialization（三段式）

## 特性

- JSON 通过 `JsonCodec` 注入，库不传递任何 JSON 类型
- header / claims 以 `Map<String, Any?>` 暴露，同时提供 `iss`、`sub`、`aud`、`exp`、`nbf`、`iat`、`jti` 类型化访问
- `JwtClaims.asType<T>()` 可用同一个 codec 把原始 payload 解码为应用自己的 claims 模型
- 签名算法、验签密钥解析器、应用层校验器均可扩展
- 严格校验 `alg` 与配置算法，防止算法混淆
- HMAC 常量时间比较，并强制 RFC 7518 最小密钥长度
- 支持 `clockSkew`，按 `exp` / `nbf` 校验有效期
- 明确区分 token 格式错误、header 错误、签名错误、过期、缺少声明等异常

## 不支持的场景

JWKT 有意保持轻量，不支持：

- JWE（加密 token）
- 未签名的 `alg=none`
- RFC 7797 `b64=false`
- 未理解的 `crit` 扩展
- 自动下载 JWKS；请通过 `JwsKeyResolver` 自行接入

## 安装

项目尚未发布到 Maven Central。先在本地发布：

```bash
./gradlew publishToMavenLocal
```

然后使用：

```kotlin
dependencies {
    implementation("com.rainccup.jwkt:jwkt:0.1.0")
}
```

如果直接把源码放入项目，也可以只依赖 Kotlin 标准库。

## Spring Boot Starter

多模块中的 `jwkt-spring-boot-starter` 提供 Spring Boot 自动配置，支持 Boot 3.5.x 与 4.1.x：

```kotlin
dependencies {
    implementation("com.rainccup.jwkt:jwkt-spring-boot-starter:0.1.0")
}
```

```yaml
jwkt:
  algorithm: HS256
  issuer: https://example.com
  audience: [api]
  secret: "0123456789abcdef0123456789abcdef"
```

```kotlin
@Service
class TokenService(private val jwkt: JwktTemplate) {
    fun issue(userId: String): String = jwkt.issue { subject(userId) }
    fun verify(token: String) = jwkt.parse(token)
}
```

starter 会根据配置自动创建 `JwtParser`、`JwktSigner`、`JwktTemplate`，并在 classpath 存在 Jackson 2/3 时注册对应 `JsonCodec`；也支持用户自定义 codec、算法、校验器和 Clock。完整配置与密钥格式见 [jwkt-spring-boot-starter/README.md](jwkt-spring-boot-starter/README.md)。

## 快速开始

### 1. 实现 JsonCodec

以 Jackson 为例（Jackson 只是使用方依赖，JWKT 不依赖它）：

```kotlin
import com.fasterxml.jackson.databind.ObjectMapper
import com.rainccup.jwkt.JsonCodec

class JacksonJsonCodec(
    private val mapper: ObjectMapper = ObjectMapper(),
) : JsonCodec {

    override fun encode(value: Any?): String =
        mapper.writeValueAsString(value)

    override fun decode(json: String, type: Class<*>): Any? =
        mapper.readValue(json, type)
}
```

`JsonCodec` 的约定：

1. `encode` 必须能序列化 `Map`、`Collection`、`String`、`Number`、`Boolean` 和 `null`。
2. 用 `Map::class.java` 调用 `decode` 时，必须返回 `Map<String, Any?>`；只要顶层是 JSON 对象即可。
3. `decode` 应尊重传入的 `type`，它是 `JwtClaims.asType` 的入口。
4. 如果 codec 会被多个线程共享，实现必须线程安全。

### 2. 生成 token

```kotlin
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.JwsAlgorithms
import java.time.Duration

val codec = JacksonJsonCodec()
val secret = ByteArray(32) { (it + 1).toByte() } // HS256 至少 32 字节

val token = Jwkt.builder(codec)
    .issuer("https://example.com")
    .subject("user-42")
    .audience("api")
    .jwtId("token-001")
    .issuedAt(Instant.now())
    .expiresIn(Duration.ofMinutes(15))
    .keyId("key-2026-01")
    .claim("role", "admin")
    .claim("tenant", "acme")
    .signWith(JwsAlgorithms.HS256, secret)
    .compact()
```

`typ` 默认是 `JWT`。自定义 header 使用 `.header(name, value)`；`alg`、`b64`、`crit` 不允许通过该接口设置。

### 3. 解析与校验

```kotlin
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.JwsAlgorithms
import java.time.Duration

val parser = Jwkt.parser(codec)
    .verifyWith(JwsAlgorithms.HS256, secret)
    .requireIssuer("https://example.com")
    .requireAudience("api")
    .requireClaim("tenant", "acme")
    .clockSkew(Duration.ofSeconds(30))
    .build()

val jwt = parser.parse(token)

check(jwt.isVerified)
println(jwt.claims.subject)     // user-42
println(jwt.claims["role"])     // admin
println(jwt.header.keyId)       // key-2026-01
```

`parse` 的顺序是：解析 header → 选择并校验签名 → 解码 claims → 校验 `exp` / `nbf` → 校验必需声明 → 执行自定义 validator。只有全部通过，`Jwt.isVerified` 才为 `true`。

## 自定义 claims 类型

不需要把 claims 先转成 `Map` 再手动映射：

```kotlin
class AccountClaims {
    @JvmField var sub: String? = null
    @JvmField var role: String? = null
    @JvmField var tenant: String? = null
}

val account = jwt.claims.asType<AccountClaims>()
```

使用 Jackson 反序列化 Kotlin `data class` 时，需要额外引入 `jackson-module-kotlin` 并注册 Kotlin module；这是 codec 实现的责任，与 JWKT 无关。

## 自定义签名算法

实现 `JwsAlgorithm` 即可接入内置算法之外的方案。下面以 JDK 17 自带的 Ed25519 为例：

```kotlin
import com.rainccup.jwkt.JwsAlgorithm
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

object Ed25519Algorithm : JwsAlgorithm {

    override val name: String = "EdDSA"

    override fun sign(input: ByteArray, key: Any): ByteArray =
        Signature.getInstance("Ed25519").run {
            initSign(key as PrivateKey)
            update(input)
            sign()
        }

    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        key: Any,
    ): Boolean =
        Signature.getInstance("Ed25519").run {
            initVerify(key as PublicKey)
            update(input)
            verify(signature)
        }
}

val token = Jwkt.builder(codec)
    .subject("user-42")
    .signWith(Ed25519Algorithm, privateKey)
    .compact()

val jwt = Jwkt.parser(codec)
    .verifyWith(Ed25519Algorithm, publicKey)
    .build()
    .parse(token)
```

约定：

- `sign` / `verify` 收到的是 `base64url(header) + "." + base64url(payload)` 的 ASCII 字节。
- `sign` 返回原始签名字节，JWKT 负责 base64url 编码。
- `key` 是调用方原样传入的对象。
- 算法实现应当线程安全。

## 密钥轮换

静态密钥每个算法只能配置一个；需要按 `kid` 轮换时使用 `JwsKeyResolver`：

```kotlin
val parser = Jwkt.parser(codec)
    .verifyWith { header ->
        when (header.keyId) {
            "2026-01" -> JwsVerificationKey(JwsAlgorithms.HS256, oldSecret)
            "2026-02" -> JwsVerificationKey(JwsAlgorithms.HS256, newSecret)
            else -> null
        }
    }
    .build()
```

resolver 收到的是未经验证的 header，不能直接信任其中的任意字段；JWKT 会再次检查返回算法的名称是否与 header 的 `alg` 一致。需要从远程 JWKS 获取密钥时，可在 resolver 内完成缓存和刷新。

## 有效期与时钟

```kotlin
val parser = Jwkt.parser(codec)
    .verifyWith(JwsAlgorithms.HS256, secret)
    .clock(Clock.systemUTC())          // 默认
    .clockSkew(Duration.ofSeconds(30)) // 允许 30 秒偏差
    .build()
```

- `exp`：`now >= exp + skew` 时抛出 `ExpiredToken`
- `nbf`：`now + skew < nbf` 时抛出 `NotYetValidToken`
- `iat` 只暴露为 `Instant`，默认不参与有效性判断

## 内置算法

| `JwsAlgorithm` | JCA 名称 | 密钥 |
| --- | --- | --- |
| `HS256` / `HS384` / `HS512` | `HmacSHA256/384/512` | `ByteArray` 或 `SecretKey`，最小 32/48/64 字节 |
| `RS256` / `RS384` / `RS512` | `SHA256/384/512withRSA` | `PrivateKey` / `PublicKey` / `KeyPair` |
| `ES256` / `ES384` / `ES512` | `SHA256/384/512withECDSAinP1363Format` | P-256 / P-384 / P-521 的 EC 密钥 |

HMAC 最小长度是 RFC 7518 的要求；需要兼容历史短密钥时，可以自行构造 `HmacJwsAlgorithm(name, jcaName, minimumKeySizeBytes)`，但不建议降低安全强度。

## API 速览

| 类型 | 作用 |
| --- | --- |
| `Jwkt` | 工厂入口：`builder`、`parser`、`parseUnverified` |
| `JsonCodec` | JSON 编解码扩展点 |
| `JwsAlgorithm` | 签名算法扩展点 |
| `JwsKeyResolver` | 按 header 选择验签密钥 |
| `JwsVerificationKey` | 算法 + 密钥组合 |
| `JwtBuilder` | 构建并签名 token |
| `JwtParserBuilder` / `JwtParser` | 配置并执行验签/校验 |
| `Jwt` | header、claims、signature、原始 token、`isVerified` |
| `JwtHeader` / `JwtClaims` | 带类型的 header / claims 访问 |
| `JwtValidator` | 应用层校验扩展点 |
| `JwtException` | 所有错误的基类 |

### 异常

| 异常 | 场景 |
| --- | --- |
| `MalformedToken` | 不是三段式、base64url 非法、UTF-8 非法、JSON 非法、payload 不是对象 |
| `InvalidHeader` | 缺 `alg`、`alg` 类型错误、`alg=none`、`crit` / `b64` 不支持 |
| `UnsupportedAlgorithm` | 没有匹配 header `alg` 的验证密钥 |
| `AlgorithmMismatch` | resolver 返回的算法与 header `alg` 不一致 |
| `InvalidSignature` | 签名验证失败 |
| `InvalidClaims` | 注册声明类型错误或自定义 validator 拒绝 |
| `ExpiredToken` / `NotYetValidToken` | `exp` / `nbf` 校验失败 |
| `MissingClaim` / `ClaimMismatch` | 必需声明缺失或不匹配 |
| `JsonCodecException` | codec 编码/解码失败 |
| `InvalidKeyException` | 密钥类型或长度不合适 |
| `SigningException` / `VerificationException` | 算法执行失败 |
| `ConfigurationException` | builder/parser 缺少必要配置 |

## 安全提示

- 只使用 `parse` 做授权判断。`parseUnverified` 不验签，只适合在选 key 前读取 `kid` / `alg`。
- 不要根据 token 里的 `alg` 动态选择任意算法；JWKT 通过配置的算法名和 header 双重校验来避免算法混淆。
- HMAC 密钥至少使用 32 字节；RSA 建议至少 2048 位；EC 必须使用与算法匹配的曲线。
- 生产环境应固定可接受的算法集合，不要把算法选择权交给不可信输入。
- `kid` 来自未验证的 header；resolver 应只把它当作查找索引，并校验查到的 key 的归属。
- 如果所有 token 都必须带 `exp`，请调用 `requireExpiration()`；Spring Boot starter 默认开启。
- token 的机密性不在 JWS 范围内；需要加密时使用 JWE 或应用层加密。
- 妥善保护私钥和 HMAC secret，不要记录 `JwsVerificationKey` / builder 的密钥字段。

## 开发

```bash
./gradlew test
./gradlew build
```

测试覆盖 HS/RS/ES 签名、非 JSON codec、自定义算法、`kid` 轮换、有效期/时钟偏差、必需声明、畸形 token、算法混淆、密钥类型错误等场景。测试中的 Jackson 只用于提供 `JsonCodec` 实现。

## 发布

Maven Central 发布由 `.github/workflows/release.yml` 通过 [GradleUp NMCP](https://gradleup.com/nmcp/) 和 Central Portal 完成。请配置以下仓库 secrets：

| Secret | 用途 |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` / `MAVEN_CENTRAL_PASSWORD` | Central Portal 用户令牌 |
| `SIGNING_KEY` | ASCII armor 格式的 GPG 私钥 |
| `SIGNING_PASSWORD` | GPG 私钥密码（无密码时留空） |

推送 `v*` tag，或手动运行 **Release** workflow 并填写版本号（例如 `0.2.0`）。workflow 会构建两个模块、对全部 publication 签名，并把聚合包上传到 Central Portal。

## License

Apache License 2.0，见 [LICENSE](LICENSE)。

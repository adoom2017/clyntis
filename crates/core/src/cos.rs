//! Publishing a file to Tencent Cloud COS (Cloud Object Storage): one PUT
//! Object request signed with COS's `q-sign-algorithm=sha1` scheme, so the
//! apps can replace a subscription file other devices update from.
use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full, Limited};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where a file goes: `https://<bucket>.cos.<region>.myqcloud.com/<key>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CosTarget {
    /// With the APPID suffix, e.g. `examplebucket-1250000000`.
    pub bucket: String,
    /// e.g. `ap-shanghai`.
    pub region: String,
    /// The object path without a leading `/`, e.g. `config/home.txt`.
    pub key: String,
}

/// A key pair from Tencent Cloud's API keys; a sub-user allowed only
/// `cos:PutObject` on the bucket is enough.
#[derive(Clone, Deserialize, Serialize)]
pub struct CosCredentials {
    pub secret_id: String,
    pub secret_key: String,
}
impl std::fmt::Debug for CosCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CosCredentials")
            .field("secret_id", &self.secret_id)
            .finish_non_exhaustive()
    }
}

impl CosTarget {
    /// The target behind a COS object URL (a subscription URL, say), or
    /// None for any other URL.
    pub fn from_url(url: &str) -> Option<Self> {
        let rest = url.trim().strip_prefix("https://")?;
        let (host, path) = rest.split_once('/')?;
        let (bucket, region) = host
            .to_ascii_lowercase()
            .strip_suffix(".myqcloud.com")?
            .split_once(".cos.")
            .map(|(b, r)| (b.to_owned(), r.to_owned()))?;
        let key = percent_decode(path.split(['?', '#']).next()?)?;
        let target = Self {
            bucket,
            region,
            key,
        };
        target.validate().ok()?;
        Some(target)
    }
    pub fn validate(&self) -> Result<()> {
        let label = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !value.starts_with('-')
                && !value.ends_with('-')
        };
        ensure!(
            label(&self.bucket)
                && self
                    .bucket
                    .rsplit_once('-')
                    .is_some_and(|(_, appid)| appid.bytes().all(|b| b.is_ascii_digit())),
            "存储桶名称应形如 examplebucket-1250000000（含 APPID）"
        );
        ensure!(label(&self.region), "地域应形如 ap-shanghai");
        ensure!(
            !self.key.is_empty()
                && !self.key.starts_with('/')
                && !self.key.ends_with('/')
                && !self
                    .key
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                && !self.key.chars().any(char::is_control),
            "文件路径不能为空，不能以 / 开头或结尾，也不能包含空的段、. 或 .."
        );
        Ok(())
    }
    pub fn host(&self) -> String {
        format!("{}.cos.{}.myqcloud.com", self.bucket, self.region)
    }
    /// The object's URL, as other devices subscribe to it.
    pub fn url(&self) -> String {
        format!("https://{}{}", self.host(), self.encoded_path())
    }
    fn encoded_path(&self) -> String {
        self.key
            .split('/')
            .map(percent_encode)
            .fold(String::new(), |path, part| path + "/" + &part)
    }
}

/// COS's `Authorization` header value for a request valid from `start` to
/// `end` (Unix seconds). `path` is decoded (`/a b.txt`); parameters and
/// headers are signed under their lowercase names.
pub fn authorization(
    credentials: &CosCredentials,
    method: &str,
    path: &str,
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
    start: u64,
    end: u64,
) -> String {
    fn hmac_hex(key: &[u8], data: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        hex(&mac.finalize().into_bytes())
    }
    fn canonical(pairs: &[(&str, &str)]) -> (String, String) {
        let mut pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (percent_encode(&k.to_ascii_lowercase()), percent_encode(v)))
            .collect();
        pairs.sort();
        let list = pairs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>();
        let joined = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>();
        (list.join(";"), joined.join("&"))
    }
    let key_time = format!("{start};{end}");
    let sign_key = hmac_hex(credentials.secret_key.as_bytes(), key_time.as_bytes());
    let (param_list, http_params) = canonical(params);
    let (header_list, http_headers) = canonical(headers);
    let http_string = format!(
        "{}\n{path}\n{http_params}\n{http_headers}\n",
        method.to_ascii_lowercase()
    );
    let string_to_sign = format!(
        "sha1\n{key_time}\n{}\n",
        hex(&Sha1::digest(http_string.as_bytes()))
    );
    let signature = hmac_hex(sign_key.as_bytes(), string_to_sign.as_bytes());
    format!(
        "q-sign-algorithm=sha1&q-ak={}&q-sign-time={key_time}&q-key-time={key_time}\
         &q-header-list={header_list}&q-url-param-list={param_list}&q-signature={signature}",
        credentials.secret_id
    )
}

/// Uploads `body` to `target`, replacing the object there.
pub async fn put_object(
    target: &CosTarget,
    credentials: &CosCredentials,
    body: Vec<u8>,
    content_type: &str,
) -> Result<()> {
    target.validate()?;
    ensure!(
        !credentials.secret_id.trim().is_empty() && !credentials.secret_key.trim().is_empty(),
        "请先填写 COS 的 SecretId 和 SecretKey"
    );
    let host = target.host();
    let length = body.len().to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs();
    // A little slack for a device clock slightly ahead of COS's.
    let authorization = authorization(
        credentials,
        "PUT",
        &format!("/{}", target.key),
        &[],
        &[
            ("Host", &host),
            ("Content-Length", &length),
            ("Content-Type", content_type),
        ],
        now.saturating_sub(60),
        now + 600,
    );
    let request = http::Request::put(target.encoded_path())
        .header(http::header::HOST, &host)
        .header(http::header::CONTENT_LENGTH, &length)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::AUTHORIZATION, authorization)
        .header(http::header::USER_AGENT, "clyntis")
        .body(Full::new(bytes::Bytes::from(body)))?;
    let exchange = async {
        let address = tokio::net::lookup_host((host.as_str(), 443))
            .await
            .with_context(|| format!("无法解析 {host}"))?
            .next()
            .with_context(|| format!("无法解析 {host}"))?;
        let socket = tokio::net::TcpStream::connect(address)
            .await
            .with_context(|| format!("无法连接 {host}"))?;
        let tls = clyntis_protocol::tls::SecureConnector::new(Default::default())
            .connect(
                Box::new(socket),
                &clyntis_protocol::tls::TlsConnectConfig {
                    server_name: host.clone(),
                    alpn: vec!["http/1.1".into()],
                    verify_cert: true,
                    fingerprint: clyntis_protocol::tls::TlsFingerprint::Native,
                    reality: None,
                },
            )
            .await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await?;
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = Limited::new(response.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(anyhow::Error::from_boxed)?
            .to_bytes();
        anyhow::Ok((status, body))
    };
    let (status, body) = tokio::time::timeout(Duration::from_secs(30), exchange)
        .await
        .map_err(|_| anyhow::anyhow!("上传到 COS 超时"))??;
    if status.is_success() {
        return Ok(());
    }
    bail!(
        "{}",
        describe_error(status, &String::from_utf8_lossy(&body))
    )
}

/// COS's XML error (`<Code>`, `<Message>`) as a message, in Chinese for the
/// usual causes.
fn describe_error(status: http::StatusCode, body: &str) -> String {
    let field = |name: &str| {
        let start = body.find(&format!("<{name}>"))? + name.len() + 2;
        let end = body[start..].find(&format!("</{name}>"))? + start;
        Some(body[start..end].trim().to_owned())
    };
    let code = field("Code").unwrap_or_default();
    let hint = match code.as_str() {
        "SignatureDoesNotMatch" => "签名不匹配，请检查 SecretKey",
        "InvalidAccessKeyId" => "SecretId 不存在或已停用",
        "AccessDenied" => "没有写入权限，请为该密钥授予此存储桶的 PutObject 权限",
        "NoSuchBucket" => "存储桶不存在，请检查名称和地域",
        "RequestTimeTooSkewed" => "设备时间与服务器相差过大，请校准系统时间",
        "EntityTooLarge" => "文件过大",
        _ => "",
    };
    let detail = match (code.is_empty(), field("Message")) {
        (false, Some(message)) => format!("{code}: {message}"),
        (false, None) => code.clone(),
        (true, _) => format!("HTTP {status}"),
    };
    if hint.is_empty() {
        format!("上传到 COS 失败（{detail}）")
    } else {
        format!("上传到 COS 失败：{hint}（{detail}）")
    }
}

/// RFC 3986 encoding, as COS signs it: everything but `A-Z a-z 0-9 - _ . ~`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PUT Object example from COS's signature documentation. Its
    /// SecretId is split so secret scanners do not mistake it for a real key.
    #[test]
    fn signs_like_the_cos_documentation_example() {
        let secret_id = ["AKID", "Qjz3ltompVjBni5LitkWHFlFpwkn9U5q"].concat();
        let credentials = CosCredentials {
            secret_id: secret_id.clone(),
            secret_key: "BQYIM75p8x0iWVFSIgqEKwFprpRSVHlz".into(),
        };
        let header = authorization(
            &credentials,
            "PUT",
            "/exampleobject(腾讯云)",
            &[],
            &[
                ("Date", "Thu, 16 May 2019 06:45:51 GMT"),
                (
                    "Host",
                    "examplebucket-1250000000.cos.ap-beijing.myqcloud.com",
                ),
                ("Content-Type", "text/plain"),
                ("Content-Length", "13"),
                ("Content-MD5", "mQ/fVh815F3k6TAUm8m0eg=="),
                ("x-cos-acl", "private"),
                ("x-cos-grant-read", "uin=\"100000000011\""),
            ],
            1557989151,
            1557996351,
        );
        assert_eq!(
            header,
            format!(
                "q-sign-algorithm=sha1&q-ak={secret_id}\
             &q-sign-time=1557989151;1557996351&q-key-time=1557989151;1557996351\
             &q-header-list=content-length;content-md5;content-type;date;host;x-cos-acl;x-cos-grant-read\
             &q-url-param-list=&q-signature=3b8851a11a569213c17ba8fa7dcf2abec6935172"
            )
        );
    }

    #[test]
    fn reads_targets_from_cos_urls_only() {
        let target = CosTarget::from_url(
            "https://image-1308520206.cos.ap-shanghai.myqcloud.com/conf/config-enc.txt?sign=x",
        )
        .unwrap();
        assert_eq!(
            target,
            CosTarget {
                bucket: "image-1308520206".into(),
                region: "ap-shanghai".into(),
                key: "conf/config-enc.txt".into(),
            }
        );
        let spaced = CosTarget::from_url(
            "https://image-1308520206.cos.ap-shanghai.myqcloud.com/my%20config.txt",
        )
        .unwrap();
        assert_eq!(spaced.key, "my config.txt");
        assert_eq!(
            spaced.url(),
            "https://image-1308520206.cos.ap-shanghai.myqcloud.com/my%20config.txt"
        );
        for url in [
            "http://image-1308520206.cos.ap-shanghai.myqcloud.com/a.txt",
            "https://example.com/a.txt",
            "https://image-1308520206.cos.ap-shanghai.myqcloud.com/",
            "https://image.cos.ap-shanghai.myqcloud.com/a.txt",
        ] {
            assert_eq!(CosTarget::from_url(url), None, "{url}");
        }
    }

    #[test]
    fn rejects_unsafe_object_keys() {
        let target = |key: &str| CosTarget {
            bucket: "image-1308520206".into(),
            region: "ap-shanghai".into(),
            key: key.into(),
        };
        assert!(target("config/home.txt").validate().is_ok());
        for key in ["", "/a.txt", "a/", "a//b", "../a", "a/./b", "a\nb"] {
            assert!(target(key).validate().is_err(), "{key:?}");
        }
    }

    #[test]
    fn explains_cos_errors() {
        let body = "<?xml version='1.0'?><Error><Code>AccessDenied</Code>\
                    <Message>Access Denied.</Message></Error>";
        let text = describe_error(http::StatusCode::FORBIDDEN, body);
        assert!(text.contains("PutObject"), "{text}");
        assert!(text.contains("AccessDenied: Access Denied."), "{text}");
        assert!(describe_error(http::StatusCode::BAD_GATEWAY, "").contains("502"));
    }
}

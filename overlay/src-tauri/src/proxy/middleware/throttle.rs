//! 出站流限速：给「用户令牌」的 SSE 响应按字符数加延迟。
//!
//! 语义：每输出 100 个字符，额外等待 X 毫秒（X ∈ 0..=150，0 = 不限速）。
//! 标定依据：实测自然速度 ≈ 2089 字符/秒。
//!
//! 硬约束：
//!   · 只作用于用户令牌；主密钥不会在 extensions 里留下 identity → 原样放行
//!   · 三道闸门缺一不可：API 路径 + 2xx + text/event-stream
//!   · 前 256 个字符免费（不是「前 N 个块」—— 两条协议块大小差 4 倍，按块不公平）
//!   · 尾帧（[DONE] / message_stop）不延迟
//!   · 单块上限 500ms、整条流上限 30s
//!   · 债务累加，只扣「真睡掉的部分」
//!   · 配置文件被删 → 真的停掉限速；读/解析失败 → 沿用上一份，且同一个坏文件只报一次
//!   · 响应里不加任何「你被限速了」的痕迹
//!   · 全程无 unwrap() / expect()

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use axum::{
    body::Body,
    extract::Request,
    http::header,
    middleware::Next,
    response::Response,
};
use futures::StreamExt;
use once_cell::sync::Lazy;

use crate::proxy::middleware::auth::UserTokenIdentity;

/// 配置文件：面板写、本进程只读。
/// 格式：{"version":1,"default_ms":0,
///        "by_token_id":{"<uuid>":45},
///        "by_user":{"杨明亮":45}}
const CFG_PATH: &str = "/root/.antigravity_tools/key_throttle.json";

/// 整条流累计最多延迟 30s（60s 叠加后最坏 76.5s，会贴客户端读超时）。
const MAX_TOTAL_MS: u64 = 30_000;
/// 单块最多睡 500ms，避免一个大块把心跳/保活卡太久。
const MAX_CHUNK_MS: u64 = 500;
/// 攒够 10ms 再睡，避免 1ms 级 sleep 把 runtime 唤醒打满。
const MIN_SLEEP_MS: f64 = 10.0;
/// 开头这么多字符免费：SSE 的 message_start / role 帧不是正文。
/// 用「字符数」而不是「块数」豁免，两条协议才公平（块大小差 4 倍）。
const EXEMPT_CHARS: usize = 256;

#[derive(serde::Deserialize, Default, Clone)]
struct Cfg {
    /// 未匹配到任何令牌时的兜底值。
    /// ⚠️ 单位是「每 100 个字符多少毫秒」，不是每块、也不是每 KB。
    #[serde(default)]
    default_ms: u32,
    #[serde(default)]
    by_token_id: HashMap<String, u32>,
    #[serde(default)]
    by_user: HashMap<String, u32>,
}

/// (文件 mtime, 解析结果)。用 SystemTime 而不是秒，同秒内两次改动也能察觉。
static CACHE: Lazy<Mutex<Option<(Option<SystemTime>, Cfg)>>> = Lazy::new(|| Mutex::new(None));

/// mtime 缓存；失败语义分三种：
///   · 文件不存在 → 真的停掉限速，缓存 (None, 空配置)
///   · 读失败 / 解析失败 → 沿用上一份，**同时把当前 mtime 记进缓存**
///     （同一个坏文件只读一次、只报一次；文件被改 → mtime 变 → 自动重试）
///   · 成功 → 缓存 (mtime, 新配置)
async fn load_cfg() -> Cfg {
    let mtime = tokio::fs::metadata(CFG_PATH)
        .await
        .ok()
        .and_then(|m| m.modified().ok());

    // 命中缓存直接返回（不跨 await 持锁）
    if let Ok(guard) = CACHE.lock() {
        if let Some((cached_mtime, cached)) = guard.as_ref() {
            if *cached_mtime == mtime {
                return cached.clone();
            }
        }
    }

    // 读/解析失败时的兜底：沿用上一份，而不是「全 0 放行」
    let fallback = CACHE
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|(_, c)| c.clone()))
        .unwrap_or_default();

    let parsed = match tokio::fs::read_to_string(CFG_PATH).await {
        Ok(text) => match serde_json::from_str::<Cfg>(&text) {
            Ok(cfg) => {
                tracing::info!(
                    "[Throttle] 配置已加载: default={}ms by_id={} by_user={}",
                    cfg.default_ms,
                    cfg.by_token_id.len(),
                    cfg.by_user.len()
                );
                cfg
            }
            Err(err) => {
                tracing::warn!(
                    "[Throttle] 配置解析失败，沿用上一份（{} 个令牌）: {err}",
                    fallback.by_token_id.len() + fallback.by_user.len()
                );
                if let Ok(mut guard) = CACHE.lock() {
                    *guard = Some((mtime, fallback.clone()));
                }
                return fallback;
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("[Throttle] 配置文件不存在，已停止限速: {}", CFG_PATH);
            let empty = Cfg::default();
            if let Ok(mut guard) = CACHE.lock() {
                *guard = Some((mtime, empty.clone()));
            }
            return empty;
        }
        Err(err) => {
            tracing::warn!(
                "[Throttle] 配置读取失败，沿用上一份（{} 个令牌）: {err}",
                fallback.by_token_id.len() + fallback.by_user.len()
            );
            if let Ok(mut guard) = CACHE.lock() {
                *guard = Some((mtime, fallback.clone()));
            }
            return fallback;
        }
    };

    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((mtime, parsed.clone()));
    }
    parsed
}

/// API 面路径。
/// 注意 `/responses` 系列在 v4.9.8 是真实路由（server.rs:634/636/648/652），不能去掉。
fn is_api_path(path: &str) -> bool {
    path == "/v1"
        || path.starts_with("/v1/")
        || path.starts_with("/v1beta/")
        || path.starts_with("/responses")
}

/// 按「字符」而不是「字节」计数：UTF-8 续字节是 10xxxxxx，跳过即可。
/// 中文 1 字（3 字节）与英文 1 字（1 字节）同权。
fn char_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| (b & 0xC0) != 0x80).count()
}

/// 尾帧判定：只看最后 64 字节，避免整块扫描。
fn is_tail_frame(bytes: &[u8]) -> bool {
    let tail = if bytes.len() > 64 {
        &bytes[bytes.len() - 64..]
    } else {
        bytes
    };
    tail.windows(6).any(|w| w == b"[DONE]") || tail.windows(14).any(|w| w == b"\"message_stop\"")
}

pub async fn throttle_middleware(req: Request, next: Next) -> Response {
    // 闸门 1：路径（必须在 next.run 之前，否则 /api/* 也会被卷进来）
    let path = req.uri().path().to_string();
    if !is_api_path(&path) {
        return next.run(req).await;
    }

    // identity 必须在 next.run 之前克隆出来（req 随后会被移走）；
    // 拆成两条语句，保证借用在 else 之前结束，避免 E0505。
    let identity = req.extensions().get::<UserTokenIdentity>().cloned();

    let response = next.run(req).await;

    // 主密钥 / 未识别身份 → 不限速，直接把响应还回去
    let Some(UserTokenIdentity { token_id, username, .. }) = identity else {
        return response;
    };

    // 闸门 2：2xx。
    // 注：WebSocket 升级返回 101，is_success() 为 false → 这里原样透传、不加延迟，
    //     升级本身不受影响。这是预期行为，不是漏判。
    if !response.status().is_success() {
        return response;
    }

    // 闸门 3：SSE
    let is_sse = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("text/event-stream"))
        .unwrap_or(false);
    if !is_sse {
        return response;
    }

    // 三道闸门都过了才读配置：/v1/models 这类 JSON 请求完全不碰磁盘。
    let cfg = load_cfg().await;
    // 优先级：token_id → username（空用户名不参与匹配）→ 全局默认
    let throttle_ms = cfg
        .by_token_id
        .get(&token_id)
        .copied()
        .or_else(|| {
            if username.is_empty() {
                None
            } else {
                cfg.by_user.get(&username).copied()
            }
        })
        .unwrap_or(cfg.default_ms);

    if throttle_ms == 0 {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    // 包成流式 body 后长度未知，必须摘掉上游给的 Content-Length
    parts.headers.remove(header::CONTENT_LENGTH);
    // 同理摘掉 Transfer-Encoding：hyper 会自己为流式 body 补 chunked，
    // 上游残留的 chunked 头若原样带过去，个别版本会报「协议错」。
    parts.headers.remove(header::TRANSFER_ENCODING);
    // 刻意不写任何「被限速」的响应头：需求是用户只感觉慢，不该有任何可发现的痕迹。

    let out = async_stream::stream! {
        let mut chars_seen: usize = 0;
        let mut debt: f64 = 0.0;
        let mut spent_ms: u64 = 0;
        let mut upstream = body.into_data_stream();

        while let Some(item) = upstream.next().await {
            if let Ok(bytes) = &item {
                let chars = char_count(bytes);
                if chars > 0 {
                    let tail = is_tail_frame(bytes);

                    // 前 EXEMPT_CHARS 个字符免费，只对超出的部分计费。
                    // 必须先算 charge、再更新 chars_seen —— 顺序反了会让
                    // 「免费额度」变成「256 减去本块自身大小」，静默失效。
                    let free_left = EXEMPT_CHARS.saturating_sub(chars_seen);
                    let charge = chars.saturating_sub(free_left);

                    if charge > 0 && !tail && spent_ms < MAX_TOTAL_MS {
                        // charge: usize、throttle_ms: u32 —— 两个都要 as f64
                        debt += charge as f64 * throttle_ms as f64 / 100.0;
                        if debt >= MIN_SLEEP_MS {
                            let want = (debt.floor() as u64)
                                .min(MAX_CHUNK_MS)
                                .min(MAX_TOTAL_MS.saturating_sub(spent_ms));
                            if want > 0 {
                                tokio::time::sleep(Duration::from_millis(want)).await;
                                spent_ms += want;
                                debt -= want as f64;   // 只扣真睡掉的
                            }
                        }
                    }
                    if spent_ms >= MAX_TOTAL_MS {
                        debt = 0.0;                    // 触顶后欠账无意义
                    }
                    chars_seen = chars_seen.saturating_add(chars);
                }
            }
            yield item;
        }
    };

    Response::from_parts(parts, Body::from_stream(out))
}

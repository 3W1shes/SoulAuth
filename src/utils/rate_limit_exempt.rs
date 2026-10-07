//! 受信内部地址免限流（`RATE_LIMIT_EXEMPT`）。
//!
//! ## 为什么需要
//!
//! 限流按「客户端 IP × 端点」计数。当一个**受信的后端服务**代表许多用户调用本服务时
//! （例如 App 后端替每个用户登录、换 token），所有请求都来自同一个 IP：
//! 登录 5 次 / 5 分钟、注册 3 次 / 5 分钟的配额会被它一个人用完，
//! 正常业务被当成暴力破解锁 15 分钟。
//!
//! ## 只认 TCP 直连地址
//!
//! 判断用的是 `ConnectInfo` 的对端地址，**不看** `X-Forwarded-For` / `X-Real-IP` ——
//! 那两个头谁都能伪造，拿它来免限流等于把限流整个送掉（与 `trust_proxy_headers` 无关）。
//!
//! ## 写法
//!
//! 逗号分隔，每一项是 IP、网段（`172.18.0.0/16`）或主机名（`backend`）。
//! 主机名在请求时解析并缓存 30 秒：容器重建后地址会变，写死 IP 会悄悄失效。
//! 不配置（默认）就没有任何豁免。
//!
//! ⚠️ 只该填**不对外**的内部服务。若将来有对外的反向代理与本服务同网段，
//! 不要用覆盖它的网段 —— 否则经它进来的所有请求都免限流。

use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const HOST_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq)]
enum Entry {
    Net { base: IpAddr, prefix: u8 },
    Host(String),
}

#[derive(Debug)]
pub struct RateLimitExempt {
    entries: Vec<Entry>,
    resolved: RwLock<Option<(Instant, Vec<IpAddr>)>>,
}

impl RateLimitExempt {
    /// 解析配置。写不对的项**启动时就报错**，而不是静默忽略 ——
    /// 静默忽略的话，运维以为配上了，App 照样被锁。
    pub fn parse(spec: Option<&str>) -> Result<Self, String> {
        let mut entries = Vec::new();
        for raw in spec.unwrap_or_default().split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            entries.push(parse_entry(item)?);
        }
        Ok(Self { entries, resolved: RwLock::new(None) })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 给启动日志用：配了哪些。
    pub fn describe(&self) -> String {
        self.entries
            .iter()
            .map(|e| match e {
                Entry::Net { base, prefix } => format!("{base}/{prefix}"),
                Entry::Host(h) => format!("host:{h}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// 这个 TCP 对端地址是否免限流。
    pub async fn is_exempt(&self, peer: IpAddr) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let peer = canonical(peer);
        if self.entries.iter().any(|e| matches!(e, Entry::Net { base, prefix } if in_net(peer, *base, *prefix))) {
            return true;
        }
        let hosts: Vec<&str> = self
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Host(h) => Some(h.as_str()),
                _ => None,
            })
            .collect();
        if hosts.is_empty() {
            return false;
        }
        if let Some((at, ips)) = self.resolved.read().await.as_ref() {
            if at.elapsed() < HOST_CACHE_TTL {
                return ips.contains(&peer);
            }
        }
        let mut ips = Vec::new();
        for h in hosts {
            // 解析失败（服务暂时没起来）就当这一项此刻不存在 —— 不放行，也不报错打断请求。
            if let Ok(addrs) = tokio::net::lookup_host((h, 0)).await {
                ips.extend(addrs.map(|a| canonical(a.ip())));
            }
        }
        let hit = ips.contains(&peer);
        *self.resolved.write().await = Some((Instant::now(), ips));
        hit
    }
}

fn parse_entry(item: &str) -> Result<Entry, String> {
    if let Some((ip, prefix)) = item.split_once('/') {
        let base: IpAddr = ip
            .parse()
            .map_err(|_| format!("RATE_LIMIT_EXEMPT: 「{item}」不是合法网段"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| format!("RATE_LIMIT_EXEMPT: 「{item}」前缀长度不对"))?;
        return Ok(Entry::Net { base: canonical(base), prefix });
    }
    if let Ok(ip) = item.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return Ok(Entry::Net { base: canonical(ip), prefix });
    }
    let host_ok = item
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if host_ok {
        Ok(Entry::Host(item.to_string()))
    } else {
        Err(format!("RATE_LIMIT_EXEMPT: 「{item}」既不是 IP、网段，也不是主机名"))
    }
}

/// IPv4 映射的 IPv6（`::ffff:1.2.3.4`）按 IPv4 比，否则双栈监听下永远对不上。
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn in_net(ip: IpAddr, base: IpAddr, prefix: u8) -> bool {
    match (ip, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn nothing_is_exempt_by_default() {
        let e = RateLimitExempt::parse(None).unwrap();
        assert!(e.is_empty());
        assert!(!e.is_exempt(ip("127.0.0.1")).await);
    }

    #[tokio::test]
    async fn ips_and_networks() {
        let e = RateLimitExempt::parse(Some("10.0.0.5, 172.18.0.0/16")).unwrap();
        assert!(e.is_exempt(ip("10.0.0.5")).await);
        assert!(!e.is_exempt(ip("10.0.0.6")).await);
        assert!(e.is_exempt(ip("172.18.3.4")).await);
        assert!(!e.is_exempt(ip("172.19.0.1")).await);
        // 双栈监听下对端可能是 IPv4 映射地址。
        assert!(e.is_exempt(ip("::ffff:172.18.0.4")).await);
    }

    #[tokio::test]
    async fn hostnames_are_resolved() {
        let e = RateLimitExempt::parse(Some("localhost")).unwrap();
        assert!(e.is_exempt(ip("127.0.0.1")).await);
        assert!(!e.is_exempt(ip("192.0.2.1")).await);
    }

    #[test]
    fn bad_entries_fail_loudly() {
        for bad in ["10.0.0.0/33", "1.2.3.4/x", "not a host!", "::1/129"] {
            assert!(RateLimitExempt::parse(Some(bad)).is_err(), "{bad}");
        }
    }
}

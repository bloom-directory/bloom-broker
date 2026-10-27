//! Broker-controlled keyless prices. Caller-supplied URLs, keys and prices are forbidden.
use bloom_broker_api::*;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Default)]
struct Cache {
    quotes: HashMap<String, SessionPriceQuote>,
    last_primary_ms: Option<u64>,
    last_fallback_ms: Option<u64>,
}
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::default()));
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

trait QuoteSource: Send + Sync + 'static {
    fn primary(&self, mapping: &SessionPricedAsset) -> Result<SessionPriceQuote, ProtocolError>;
    fn fallback(
        &self,
        mappings: &[SessionPricedAsset],
    ) -> Result<Vec<SessionPriceQuote>, ProtocolError>;
}
struct HttpQuotes;
impl QuoteSource for HttpQuotes {
    fn primary(&self, mapping: &SessionPricedAsset) -> Result<SessionPriceQuote, ProtocolError> {
        fetch_primary(mapping)
    }
    fn fallback(
        &self,
        mappings: &[SessionPricedAsset],
    ) -> Result<Vec<SessionPriceQuote>, ProtocolError> {
        fetch_fallback(mappings)
    }
}
fn key(provider: &str, mapping: &SessionPricedAsset) -> String {
    // Include metadata/mappings and policy, so a cached price never crosses versions.
    format!(
        "{}:{provider}:{}",
        session_pricing_policy_digest().as_str(),
        serde_json::to_string(mapping).expect("serializable price mapping")
    )
}
fn fresh(quote: &SessionPriceQuote, now: u64) -> bool {
    quote.timestamp_ms.get() <= now.saturating_add(5_000)
        && now.saturating_sub(quote.timestamp_ms.get()) <= SESSION_QUOTE_MAX_AGE_MS
}
fn unavailable() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::PriceUnavailable,
        "No acceptable CoinGecko or DefiLlama quote; owner approval is required",
    )
}
fn elapsed_now(now: u64, start: Instant) -> u64 {
    now.saturating_add(start.elapsed().as_millis().min(u64::MAX as u128) as u64)
}

pub(crate) async fn prices(
    assets: &[AssetId],
    now: u64,
) -> Result<(Vec<SessionPricedAsset>, Vec<SessionPriceQuote>), ProtocolError> {
    if assets.is_empty() || assets.len() > 128 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "price request needs 1-128 assets",
        ));
    }
    let mappings = assets
        .iter()
        .map(|asset| {
            approved_session_asset(asset).ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::AssetUnsupported,
                    "No approved metadata/price mapping for asset",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quotes = bounded_prices(
        &CACHE,
        Arc::new(HttpQuotes),
        &mappings,
        now,
        REQUEST_DEADLINE,
    )
    .await?;
    Ok((mappings, quotes))
}
async fn bounded_prices(
    cache: &Mutex<Cache>,
    source: Arc<dyn QuoteSource>,
    mappings: &[SessionPricedAsset],
    now: u64,
    deadline: Duration,
) -> Result<Vec<SessionPriceQuote>, ProtocolError> {
    // Includes contention for the coalescing lock and every provider/asset lookup.
    tokio::time::timeout(deadline, select_prices(cache, source, mappings, now))
        .await
        .map_err(|_| unavailable())?
}
async fn select_prices(
    cache: &Mutex<Cache>,
    source: Arc<dyn QuoteSource>,
    mappings: &[SessionPricedAsset],
    now: u64,
) -> Result<Vec<SessionPriceQuote>, ProtocolError> {
    let start = Instant::now();
    // Coalesce concurrent requests and apply a conservative process-wide keyless budget.
    let mut cache = cache.lock().await;
    let mut result = Vec::new();
    for mapping in mappings {
        let current = elapsed_now(now, start);
        let primary_key = key("coingecko", mapping);
        if let Some(quote) = cache.quotes.get(&primary_key).filter(|q| fresh(q, current)) {
            result.push(quote.clone());
            continue;
        }
        if cache
            .last_primary_ms
            .is_none_or(|last| current.saturating_sub(last) >= 12_000)
        {
            cache.last_primary_ms = Some(current);
            let mapping_copy = mapping.clone();
            let fetch = source.clone();
            if let Ok(Ok(quote)) =
                tokio::task::spawn_blocking(move || fetch.primary(&mapping_copy)).await
            {
                if quote.asset == mapping.asset
                    && quote.provider.as_str() == "coingecko"
                    && fresh(&quote, elapsed_now(now, start))
                {
                    cache.quotes.insert(primary_key, quote.clone());
                    result.push(quote);
                    continue;
                }
            }
        }
        let fallback_key = key("defillama", mapping);
        if let Some(quote) = cache
            .quotes
            .get(&fallback_key)
            .filter(|q| fresh(q, elapsed_now(now, start)))
        {
            result.push(quote.clone());
            continue;
        }
        let current = elapsed_now(now, start);
        if cache
            .last_fallback_ms
            .is_some_and(|last| current.saturating_sub(last) < 1_000)
        {
            return Err(unavailable());
        }
        cache.last_fallback_ms = Some(current);
        // A single fallback request covers all spend and fee assets.
        let pending = mappings.to_vec();
        let fetch = source.clone();
        if let Ok(Ok(quotes)) = tokio::task::spawn_blocking(move || fetch.fallback(&pending)).await
        {
            for quote in quotes {
                if quote.provider.as_str() == "defillama" && fresh(&quote, elapsed_now(now, start))
                {
                    if let Some(mapped) = mappings.iter().find(|m| m.asset == quote.asset) {
                        cache.quotes.insert(key("defillama", mapped), quote);
                    }
                }
            }
        }
        result.push(
            cache
                .quotes
                .get(&fallback_key)
                .filter(|q| fresh(q, elapsed_now(now, start)))
                .ok_or_else(unavailable)?
                .clone(),
        );
    }
    // The first asset's observation may have expired while later assets were fetched.
    if result.iter().any(|q| !fresh(q, elapsed_now(now, start))) {
        return Err(unavailable());
    }
    Ok(result)
}
fn get_json(url: &str) -> Result<Value, ProtocolError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .max_redirects(0)
        .build()
        .into();
    let response = agent.get(url).call().map_err(|_| unavailable())?;
    let body = response
        .into_body()
        .with_config()
        .limit(256 * 1024)
        .read_to_string()
        .map_err(|_| unavailable())?;
    // Workspace enables arbitrary_precision: Number retains the original decimal lexeme.
    serde_json::from_str(&body).map_err(|_| unavailable())
}
/// Expand scientific decimal notation without any binary floating-point conversion.
fn decimal_price(value: &Value) -> Result<String, ProtocolError> {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err(unavailable()),
    };
    if text.len() > 128 {
        return Err(unavailable());
    }
    let mut pieces = text.split(['e', 'E']);
    let mantissa = pieces.next().ok_or_else(unavailable)?;
    let exponent = pieces
        .next()
        .map(|s| s.parse::<i32>().map_err(|_| unavailable()))
        .transpose()?
        .unwrap_or(0);
    if pieces.next().is_some() || !(-77..=77).contains(&exponent) {
        return Err(unavailable());
    }
    let mut decimal = mantissa.split('.');
    let whole = decimal.next().ok_or_else(unavailable)?;
    let fraction = decimal.next().unwrap_or("");
    if decimal.next().is_some()
        || whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err(unavailable());
    }
    let digits = format!("{whole}{fraction}");
    let point = whole.len() as i32 + exponent;
    let expanded = if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}", "0".repeat(point as usize - digits.len()))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    };
    session_usd_charge(&DecimalU256::parse("1").unwrap(), 0, &expanded)
        .map_err(|_| unavailable())?;
    Ok(expanded)
}
fn quote(
    asset: &AssetId,
    value: &Value,
    timestamp: &Value,
    provider: &str,
) -> Result<SessionPriceQuote, ProtocolError> {
    let price = decimal_price(value)?;
    let timestamp = timestamp
        .as_u64()
        .and_then(|t| t.checked_mul(1_000))
        .ok_or_else(unavailable)?;
    Ok(SessionPriceQuote {
        asset: asset.clone(),
        price_usd: price,
        provider: Token::new(provider).unwrap(),
        timestamp_ms: DecimalU64::new(timestamp),
    })
}
fn fetch_primary(mapping: &SessionPricedAsset) -> Result<SessionPriceQuote, ProtocolError> {
    let (url, id) = if let Some(id) = &mapping.coingecko_id {
        (
            format!(
                "https://api.coingecko.com/api/v3/simple/price?ids={id}&vs_currencies=usd&include_last_updated_at=true&precision=full"
            ),
            id.as_str(),
        )
    } else {
        let platform = mapping
            .coingecko_platform
            .as_ref()
            .ok_or_else(unavailable)?;
        (
            format!(
                "https://api.coingecko.com/api/v3/simple/token_price/{platform}?contract_addresses={}&vs_currencies=usd&include_last_updated_at=true&precision=full",
                mapping.asset.asset
            ),
            mapping.asset.asset.as_str(),
        )
    };
    let json = get_json(&url)?;
    quote(
        &mapping.asset,
        &json[id]["usd"],
        &json[id]["last_updated_at"],
        "coingecko",
    )
}
fn fetch_fallback(
    mappings: &[SessionPricedAsset],
) -> Result<Vec<SessionPriceQuote>, ProtocolError> {
    let ids = mappings
        .iter()
        .map(|a| a.defillama_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let json = get_json(&format!("https://coins.llama.fi/prices/current/{ids}"))?;
    Ok(mappings
        .iter()
        .filter_map(|m| {
            let row = &json["coins"][&m.defillama_id];
            quote(&m.asset, &row["price"], &row["timestamp"], "defillama").ok()
        })
        .collect())
}
pub(crate) async fn valuation(
    budget: &SessionBudget,
    values: &[SessionAssetAmount],
    now: u64,
) -> Result<SessionValuation, ProtocolError> {
    let values = SessionAccounting::canonical_values(values)?;
    let assets = values.iter().map(|v| v.asset.clone()).collect::<Vec<_>>();
    let (_, quotes) = prices(&assets, now).await?;
    let mut record = SessionRecordedUse {
        accepted_at_ms: now,
        signature_count: 1,
        values,
        valuation: Some(SessionValuation {
            accepted_at_ms: DecimalU64::new(now),
            quotes,
            usd_microdollars: DecimalU256::parse("0").unwrap(),
        }),
    };
    use num_bigint::BigUint;
    use std::str::FromStr;
    let mut total = BigUint::from(0u8);
    for value in &record.values {
        let policy = budget.usd_policy.as_ref().ok_or_else(unavailable)?;
        let metadata = policy
            .assets
            .iter()
            .find(|a| a.asset == value.asset)
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::AssetUnsupported,
                    "Asset outside reviewed session scope",
                )
            })?;
        let quote = record
            .valuation
            .as_ref()
            .unwrap()
            .quotes
            .iter()
            .find(|q| q.asset == value.asset)
            .ok_or_else(unavailable)?;
        total += BigUint::from_str(
            session_usd_charge(&value.amount, metadata.decimals, &quote.price_usd)?.as_str(),
        )
        .map_err(|_| unavailable())?;
    }
    record.valuation.as_mut().unwrap().usd_microdollars =
        DecimalU256::parse(total.to_string()).map_err(|_| unavailable())?;
    budget.recorded_quantity(&record)?;
    Ok(record.valuation.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const NOW: u64 = 2_000_000;
    struct Fake {
        primary: Result<SessionPriceQuote, ProtocolError>,
        fallback: Vec<SessionPriceQuote>,
        primary_calls: AtomicUsize,
        fallback_calls: AtomicUsize,
        delay: Duration,
    }
    impl QuoteSource for Fake {
        fn primary(&self, _: &SessionPricedAsset) -> Result<SessionPriceQuote, ProtocolError> {
            self.primary_calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.primary.clone()
        }
        fn fallback(
            &self,
            _: &[SessionPricedAsset],
        ) -> Result<Vec<SessionPriceQuote>, ProtocolError> {
            self.fallback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.fallback.clone())
        }
    }
    fn mapping() -> SessionPricedAsset {
        approved_session_asset(&AssetId {
            chain: Token::new("evm-1").unwrap(),
            asset: "native".into(),
        })
        .unwrap()
    }
    fn q(provider: &str, timestamp: u64) -> SessionPriceQuote {
        SessionPriceQuote {
            asset: mapping().asset,
            provider: Token::new(provider).unwrap(),
            price_usd: "2300.123456789012345678901".into(),
            timestamp_ms: DecimalU64::new(timestamp),
        }
    }
    fn fake(
        primary: Result<SessionPriceQuote, ProtocolError>,
        fallback: Vec<SessionPriceQuote>,
    ) -> Arc<Fake> {
        Arc::new(Fake {
            primary,
            fallback,
            primary_calls: AtomicUsize::new(0),
            fallback_calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        })
    }
    #[test]
    fn exact_decimal_json_and_scientific_prices_never_round_through_float() {
        let json: Value = serde_json::from_str(
            r#"{"price":1.000000000000000000000001,"tiny":1.234567890123456789e-8}"#,
        )
        .unwrap();
        assert_eq!(
            decimal_price(&json["price"]).unwrap(),
            "1.000000000000000000000001"
        );
        assert_eq!(
            decimal_price(&json["tiny"]).unwrap(),
            "0.00000001234567890123456789"
        );
        assert_eq!(
            session_usd_charge(
                &DecimalU256::parse("1000000").unwrap(),
                6,
                &decimal_price(&json["price"]).unwrap()
            )
            .unwrap()
            .as_str(),
            "1000001"
        );
        for text in ["0", "-1", "NaN", "1e999999", "1.2.3", ""] {
            assert!(
                decimal_price(&Value::String(text.into())).is_err(),
                "{text}"
            );
        }
    }
    #[test]
    fn freshness_uses_source_timestamp_inclusive_age_and_future_skew() {
        assert!(fresh(&q("coingecko", NOW - 900_000), NOW));
        assert!(!fresh(&q("coingecko", NOW - 900_001), NOW));
        assert!(fresh(&q("coingecko", NOW + 5_000), NOW));
        assert!(!fresh(&q("coingecko", NOW + 5_001), NOW));
    }
    #[tokio::test]
    async fn primary_precedence_cache_and_mapping_isolation() {
        let cache = Mutex::new(Cache::default());
        let source = fake(Ok(q("coingecko", NOW)), vec![q("defillama", NOW)]);
        let result = bounded_prices(&cache, source.clone(), &[mapping()], NOW, REQUEST_DEADLINE)
            .await
            .unwrap();
        assert_eq!(result[0].provider.as_str(), "coingecko");
        bounded_prices(
            &cache,
            source.clone(),
            &[mapping()],
            NOW + 1,
            REQUEST_DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(source.primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.fallback_calls.load(Ordering::SeqCst), 0);
        let mut different = mapping();
        different.decimals -= 1;
        assert_ne!(key("coingecko", &mapping()), key("coingecko", &different));
        assert_ne!(key("coingecko", &mapping()), key("defillama", &mapping()));
    }
    #[tokio::test]
    async fn stale_failed_and_wrong_asset_primary_fall_back_then_primary_recovers() {
        let mut wrong = q("coingecko", NOW);
        wrong.asset.asset = "wrong".into();
        for primary in [
            Err(unavailable()),
            Ok(q("coingecko", NOW - 900_001)),
            Ok(wrong),
        ] {
            let cache = Mutex::new(Cache::default());
            let source = fake(primary, vec![q("defillama", NOW)]);
            let result =
                bounded_prices(&cache, source.clone(), &[mapping()], NOW, REQUEST_DEADLINE)
                    .await
                    .unwrap();
            assert_eq!(result[0].provider.as_str(), "defillama");
            assert_eq!(source.fallback_calls.load(Ordering::SeqCst), 1);
            let recovered = fake(Ok(q("coingecko", NOW + 12_001)), vec![]);
            let result = bounded_prices(
                &cache,
                recovered,
                &[mapping()],
                NOW + 12_001,
                REQUEST_DEADLINE,
            )
            .await
            .unwrap();
            assert_eq!(result[0].provider.as_str(), "coingecko");
        }
    }
    #[tokio::test]
    async fn mixed_provider_spend_and_fee_assets_use_one_fallback_batch() {
        let cache = Mutex::new(Cache::default());
        let eth = mapping();
        let usdc = approved_session_asset(&AssetId {
            chain: Token::new("evm-1").unwrap(),
            asset: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        })
        .unwrap();
        let mut usdc_quote = q("defillama", NOW);
        usdc_quote.asset = usdc.asset.clone();
        usdc_quote.price_usd = "0.9994".into();
        let source = fake(Ok(q("coingecko", NOW)), vec![usdc_quote.clone()]);
        let result = bounded_prices(
            &cache,
            source.clone(),
            &[eth.clone(), usdc.clone()],
            NOW,
            REQUEST_DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(result[0].provider.as_str(), "coingecko");
        assert_eq!(result[1], usdc_quote);
        bounded_prices(
            &cache,
            source.clone(),
            &[eth, usdc],
            NOW + 1,
            REQUEST_DEADLINE,
        )
        .await
        .unwrap();
        assert_eq!(source.primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.fallback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn both_stale_or_missing_fail_and_fallback_does_not_refresh_age() {
        for fallback in [
            vec![],
            vec![q("defillama", NOW - 900_001)],
            vec![q("defillama", NOW + 5_001)],
        ] {
            let cache = Mutex::new(Cache::default());
            let source = fake(Err(unavailable()), fallback);
            assert!(
                bounded_prices(&cache, source, &[mapping()], NOW, REQUEST_DEADLINE)
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn concurrent_requests_coalesce_and_deadline_includes_cache_lock() {
        let cache = Mutex::new(Cache::default());
        let source = fake(Ok(q("coingecko", NOW)), vec![]);
        let mappings = [mapping()];
        let (a, b) = tokio::join!(
            bounded_prices(&cache, source.clone(), &mappings, NOW, REQUEST_DEADLINE),
            bounded_prices(&cache, source.clone(), &mappings, NOW, REQUEST_DEADLINE)
        );
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(source.primary_calls.load(Ordering::SeqCst), 1);
        let _guard = cache.lock().await;
        assert!(
            bounded_prices(&cache, source, &mappings, NOW, Duration::from_millis(10))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn provider_work_cannot_extend_aggregate_deadline() {
        let cache = Mutex::new(Cache::default());
        let source = Arc::new(Fake {
            delay: Duration::from_millis(80),
            ..Arc::try_unwrap(fake(Ok(q("coingecko", NOW)), vec![]))
                .ok()
                .unwrap()
        });
        assert!(
            bounded_prices(
                &cache,
                source.clone(),
                &[mapping()],
                NOW,
                Duration::from_millis(10)
            )
            .await
            .is_err()
        );
        assert_eq!(source.fallback_calls.load(Ordering::SeqCst), 0);
    }
}

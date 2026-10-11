//! The active model: provider, model and effort from `august.json`. Every
//! provider lives in an extension and is reached through `remote`.

use crate::config::{Config, Root};
use crate::extensions::Extensions;
use crate::llm::{self, LlmProvider};
use anyhow::Result;
use std::sync::Arc;

/// Active provider (empty: none chosen yet), model (empty: the provider's default) and effort.
pub struct Selection {
    pub provider: String,
    pub model: String,
    pub effort: String,
}

/// The selection saved in `august.json`.
pub fn selection(root: &Root) -> Result<Selection> {
    let cfg: Config = root.app()?;
    Ok(Selection {
        provider: cfg.provider.unwrap_or_default(),
        model: cfg.model.unwrap_or_default(),
        effort: cfg.effort.unwrap_or_else(|| "medium".into()),
    })
}

/// The selected provider. Retries and a fallback are `llm_error` handlers (the `retry`
/// extension).
pub fn build(ext: &Arc<Extensions>, sel: Selection) -> Arc<dyn LlmProvider> {
    Arc::new(llm::remote::Remote::new(ext, &sel.provider, &sel.model, &sel.effort))
}

/// `provider:model` (`provider:` for its default) when `provider` is one the extensions
/// offer; else a model of the active provider (model names may hold a colon: `llama3:8b`).
pub fn parse_spec(root: &Root, spec: &str, providers: &[String]) -> Result<Selection> {
    let mut sel = selection(root)?;
    match spec.split_once(':').filter(|(id, _)| providers.iter().any(|p| p == id)) {
        Some((id, model)) => {
            sel.provider = id.into();
            sel.model = model.into();
        }
        None => sel.model = spec.into(),
    }
    Ok(sel)
}

/// A provider for `spec` (see `parse_spec`).
pub fn build_spec(ext: &Arc<Extensions>, spec: &str) -> Result<Arc<dyn LlmProvider>> {
    let ids: Vec<String> = ext.providers().into_iter().map(|(_, p)| p.id).collect();
    Ok(build(ext, parse_spec(ext.root(), spec, &ids)?))
}

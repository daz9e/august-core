//! Model providers: the types and the `LlmProvider` trait live in the SDK
//! (`august_ext::llm`), the wire formats in `august-llm`.

pub mod providers;
pub mod remote;

pub use august_ext::llm::*;

/// Images as hooks and tools give them (`[{path, mime}]`), as blocks for the model.
pub fn image_blocks(images: &serde_json::Value) -> Vec<Block> {
    let list = images.as_array().into_iter().flatten();
    list.filter_map(|i| Some(Block::Image { media_type: i["mime"].as_str()?.into(), path: i["path"].as_str()?.into() })).collect()
}

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

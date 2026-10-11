//! Tools the agent can call: all of them come from extensions (the default `tools` one has
//! `bash`, `read`, `write`, `edit`) and run through the `tool_call` / `tool_result` hooks.

use crate::db::Db;
use crate::extensions::Extensions;
use crate::llm::ToolSpec;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone)]
pub struct ToolCtx {
    pub db: Arc<Db>,
    /// The thread and turn this runs for.
    pub origin: crate::extensions::Origin,
    /// Messages the user sends while the turn runs.
    pub inbox: Option<Arc<crate::agent::Inbox>>,
    /// Who asks for tools: `model`, or `ext:<name>` for an extension's `callTool`.
    pub caller: String,
}

/// What a tool call gave back.
pub struct Output {
    pub text: String,
    /// `[{path, mime}]`: images for the model to see.
    pub images: Value,
    pub is_error: bool,
}

impl Output {
    fn error(text: String) -> Self {
        Self { text, images: json!([]), is_error: true }
    }
}

#[derive(Clone, Default)]
pub struct ToolRegistry {
    /// Extension tools and the `tool_call` / `tool_result` hooks.
    ext: Option<Arc<Extensions>>,
    /// Tools the model is not offered and may not call.
    hidden: HashSet<String>,
    /// When set, only these tools are offered.
    only: Option<HashSet<String>>,
}

impl ToolRegistry {
    /// Hides tools by name (e.g. what a sub-agent may not use).
    pub fn without<S: AsRef<str>>(mut self, names: &[S]) -> Self {
        self.hidden.extend(names.iter().map(|n| n.as_ref().to_string()));
        self
    }

    /// Offers only these tools.
    pub fn only<S: AsRef<str>>(mut self, names: &[S]) -> Self {
        self.only = Some(names.iter().map(|n| n.as_ref().to_string()).collect());
        self
    }

    fn offered(&self, name: &str) -> bool {
        !self.hidden.contains(name) && self.only.as_ref().is_none_or(|o| o.contains(name))
    }

    pub fn with_extensions(mut self, ext: Arc<Extensions>) -> Self {
        self.ext = Some(ext);
        self
    }

    pub fn extensions(&self) -> Option<&Arc<Extensions>> {
        self.ext.as_ref()
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        let mut specs = self.ext.as_ref().map(|e| e.tool_specs()).unwrap_or_default();
        let mut seen = HashSet::new();
        specs.retain(|s| self.offered(&s.name) && seen.insert(s.name.clone()));
        specs
    }

    /// Runs a tool through the extension hooks; errors become outputs with `is_error` so
    /// the model can react to them.
    /// `id` is the model's id of the call (`None` for calls from elsewhere).
    pub async fn call(&self, id: Option<&str>, name: &str, input: &Value, ctx: &ToolCtx) -> Output {
        let out = self.call_hooked(id, name, input, ctx).await;
        let mut data = json!({"tool": name, "id": id, "input": input, "output": out.text, "isError": out.is_error});
        if out.images.as_array().is_some_and(|i| !i.is_empty()) {
            data["images"] = out.images.clone();
        }
        let mut e = crate::db::Entry::new("tool", data);
        e.session = ctx.origin.thread.as_ref().and_then(|t| ctx.db.current_session(&t.key()).ok().flatten());
        e.turn = ctx.origin.turn.as_ref().map(|t| t.id);
        e.caller = Some(ctx.caller.clone());
        crate::agent::SessionStore::journal(&*ctx.db, &e);
        out
    }

    async fn call_hooked(&self, id: Option<&str>, name: &str, input: &Value, ctx: &ToolCtx) -> Output {
        if ctx.origin.turn.as_ref().and_then(|t| t.callable.as_ref()).is_some_and(|c| !c.contains(name)) {
            return Output::error(format!("`{name}` is not available here"));
        }
        let Some(ext) = self.ext.as_ref().filter(|_| self.offered(name)) else {
            return Output::error(format!("unknown tool: {name}"));
        };
        let mut input = input.clone();
        if ext.listens("tool_call") {
            let data = ext.emit("tool_call", json!({"tool": name, "input": input, "id": id, "caller": ctx.caller}), &ctx.origin).await;
            match &data["block"] {
                Value::String(reason) if !reason.is_empty() => {
                    return Output::error(format!("blocked by an extension: {reason}"));
                }
                Value::Bool(true) => return Output::error("blocked by an extension".into()),
                _ => {}
            }
            input = data["input"].clone();
        }
        let mut out = match ext.has_tool(name).then(|| ext.call_tool(name, &input, &ctx.origin)) {
            Some(call) => match call.await {
                Some(Ok((text, images))) => Output { text, images, is_error: false },
                Some(Err(e)) => Output::error(format!("error: {e}")),
                None => Output::error(format!("unknown tool: {name}")),
            },
            None => Output::error(format!("unknown tool: {name}")),
        };
        if ext.listens("tool_result") {
            let data = json!({"tool": name, "input": input, "id": id, "caller": ctx.caller, "output": out.text, "isError": out.is_error, "images": out.images});
            let data = ext.emit("tool_result", data, &ctx.origin).await;
            if let Some(o) = data["output"].as_str() {
                out.text = o.to_string();
            }
            if let Some(e) = data["isError"].as_bool() {
                out.is_error = e;
            }
            if data["images"].is_array() {
                out.images = data["images"].clone();
            }
        }
        out
    }
}

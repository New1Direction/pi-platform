//! Port of `pi_micro_agents/pi_vertex_ai_model_id_validator.py`.
//!
//! Validator agent for GCP Vertex AI Model IDs to detect deprecated or
//! unsupported models. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

// Catalog mapping task type to standard list of supported models.
// NOTE: order matters because the Python code iterates `_SUPPORTED_MODELS.items()`
// to build `supported_tasks`, and Python dicts preserve insertion order.
const SUPPORTED_TASKS_ORDER: [&str; 4] = ["generation", "embedding", "vision", "routing"];

fn supported_models(task: &str) -> &'static [&'static str] {
    match task {
        "generation" => &[
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-2.0-pro",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash-8b",
            "gemini-2.5-flash",
            "gemini-2.5-pro",
        ],
        "embedding" => &[
            "text-embedding-004",
            "text-embedding-005",
            "text-multilingual-embedding-002",
            "multimodalembedding@001",
        ],
        "vision" => &[
            "gemini-2.0-flash",
            "gemini-2.0-pro",
            "gemini-1.5-pro",
            "gemini-2.5-pro",
        ],
        "routing" => &["gemini-2.0-flash", "gemini-2.0-flash-lite"],
        _ => &[],
    }
}

// Deprecated models -> recommended alternative.
// Preserve insertion order for `_ALL_KNOWN_MODELS` membership (order does not
// affect membership semantics, but kept for clarity).
const DEPRECATED_MODELS: [(&str, &str); 5] = [
    ("gemini-1.0-pro", "gemini-2.0-flash"),
    ("gemini-1.0-ultra", "gemini-2.0-flash"),
    ("text-bison", "gemini-2.0-flash"),
    ("chat-bison", "gemini-2.0-flash"),
    ("textembedding-gecko", "text-embedding-004"),
];

fn deprecated_alternative(model_id: &str) -> Option<&'static str> {
    DEPRECATED_MODELS
        .iter()
        .find(|(k, _)| *k == model_id)
        .map(|(_, v)| *v)
}

fn is_known_model(model_id: &str) -> bool {
    for task in SUPPORTED_TASKS_ORDER.iter() {
        if supported_models(task).contains(&model_id) {
            return true;
        }
    }
    DEPRECATED_MODELS.iter().any(|(k, _)| *k == model_id)
}

#[derive(Debug, Deserialize)]
pub struct Input {
    pub model_id: String,
    #[serde(default = "default_task_type")]
    pub task_type: String,
}

fn default_task_type() -> String {
    "generation".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_valid: bool,
    pub model_family: String,
    pub is_deprecated: bool,
    pub recommended_alternative: String,
    pub supported_tasks: Vec<String>,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

pub fn execute(input: &Input) -> Output {
    let model_id = &input.model_id;
    let task_type = &input.task_type;

    // Determine model family
    let model_family = if model_id.starts_with("gemini-2.5") {
        "gemini-2.5"
    } else if model_id.starts_with("gemini-2.0") {
        "gemini-2.0"
    } else if model_id.starts_with("gemini-1.5") {
        "gemini-1.5"
    } else if model_id.starts_with("gemini-1.0") {
        "gemini-1.0"
    } else if model_id.starts_with("text-embedding") {
        "text-embedding"
    } else if model_id.starts_with("text-multilingual-embedding")
        || model_id.starts_with("textembedding-gecko")
    {
        "text-embedding"
    } else if model_id.starts_with("multimodalembedding") || model_id.contains("multimodal") {
        "multimodal"
    } else if model_id.contains("bison") {
        "bison"
    } else {
        "unknown"
    }
    .to_string();

    let is_deprecated = deprecated_alternative(model_id).is_some();
    let recommended_alternative = deprecated_alternative(model_id).unwrap_or("").to_string();

    // Find supported tasks
    let mut supported_tasks: Vec<String> = Vec::new();
    for task in SUPPORTED_TASKS_ORDER.iter() {
        if supported_models(task).contains(&model_id.as_str()) {
            supported_tasks.push((*task).to_string());
        }
    }

    let mut issues: Vec<String> = Vec::new();
    let mut risk_score = 0.0_f64;

    let known = is_known_model(model_id);

    if !known {
        issues.push(format!("Model ID '{model_id}' is unknown."));
        risk_score += 30.0;
    } else if is_deprecated {
        issues.push(format!(
            "Model ID '{model_id}' is deprecated. Recommended alternative: {recommended_alternative}"
        ));
        risk_score += 50.0;
    }

    let valid_task_types = ["generation", "embedding", "vision", "routing"];
    if !valid_task_types.contains(&task_type.as_str()) {
        issues.push(format!("Invalid task type '{task_type}'."));
        risk_score += 25.0;
    } else if known && !supported_models(task_type).contains(&model_id.as_str()) {
        issues.push(format!(
            "Model ID '{model_id}' does not support task type '{task_type}'."
        ));
        risk_score += 25.0;
    }

    risk_score = risk_score.min(100.0);
    let is_valid = known && !is_deprecated;

    let status = if !is_valid || risk_score > 60.0 {
        "FAIL"
    } else if risk_score >= 30.0 {
        "WARN"
    } else {
        "PASS"
    }
    .to_string();

    Output {
        is_valid,
        model_family,
        is_deprecated,
        recommended_alternative,
        supported_tasks,
        issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = execute(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(model_id: &str, task_type: &str) -> Output {
        execute(&Input {
            model_id: model_id.into(),
            task_type: task_type.into(),
        })
    }

    #[test]
    fn clean_supported_model_passes() {
        let o = run("gemini-2.0-flash", "generation");
        assert!(o.is_valid);
        assert!(!o.is_deprecated);
        assert_eq!(o.model_family, "gemini-2.0");
        assert_eq!(o.status, "PASS");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
        assert_eq!(
            o.supported_tasks,
            vec![
                "generation".to_string(),
                "vision".to_string(),
                "routing".to_string()
            ]
        );
    }

    #[test]
    fn deprecated_model_fails() {
        let o = run("text-bison", "generation");
        assert!(!o.is_valid);
        assert!(o.is_deprecated);
        assert_eq!(o.recommended_alternative, "gemini-2.0-flash");
        assert_eq!(o.model_family, "bison");
        assert_eq!(o.status, "FAIL");
        // deprecated (+50) and not supported for task (+25) => 75 capped
        assert_eq!(o.risk_score, 75.0);
    }

    #[test]
    fn unknown_model_warns() {
        let o = run("gemini-9.9-omega", "generation");
        assert!(!o.is_valid);
        assert!(!o.is_deprecated);
        assert_eq!(o.model_family, "unknown");
        assert_eq!(o.risk_score, 30.0);
        // is_valid is false so status is FAIL
        assert_eq!(o.status, "FAIL");
    }

    #[test]
    fn invalid_task_type_flagged() {
        let o = run("gemini-2.5-pro", "classification");
        assert!(o.is_valid);
        assert_eq!(o.model_family, "gemini-2.5");
        assert!(o
            .issues
            .iter()
            .any(|s| s.contains("Invalid task type 'classification'")));
        assert_eq!(o.risk_score, 25.0);
        assert_eq!(o.status, "PASS");
    }
}

use graphql_parser::query::{Definition, OperationDefinition, parse_query};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

#[derive(Debug, Serialize)]
pub struct Request<'a> {
    pub query: &'a str,
    pub variables: Value,
    #[serde(rename = "operationName", skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub data: Option<Value>,
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GraphqlError {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

pub fn ensure_read_only(source: &str, requested_operation: Option<&str>) -> Result<()> {
    let doc = parse_query::<String>(source)
        .map_err(|e| Error::Input(format!("invalid GraphQL document: {e}")))?;
    if doc.definitions.is_empty() {
        return Err(Error::Input("GraphQL document is empty".into()));
    }
    let mut operations = Vec::new();
    for definition in doc.definitions {
        if let Definition::Operation(operation) = definition {
            let name = match &operation {
                OperationDefinition::Query(query) => query.name.as_deref(),
                OperationDefinition::SelectionSet(_) => None,
                OperationDefinition::Mutation(mutation) => mutation.name.as_deref(),
                OperationDefinition::Subscription(subscription) => subscription.name.as_deref(),
            };
            operations.push(name.map(str::to_owned));
            if matches!(
                operation,
                OperationDefinition::Mutation(_) | OperationDefinition::Subscription(_)
            ) {
                return Err(Error::Input(
                    "raw GraphQL is read-only; mutations and subscriptions are not allowed".into(),
                ));
            }
        }
    }
    if operations.is_empty() {
        return Err(Error::Input(
            "GraphQL document contains no query operation".into(),
        ));
    }
    if operations.len() > 1 && requested_operation.is_none() {
        return Err(Error::Input(
            "GraphQL documents with multiple operations require --operation-name".into(),
        ));
    }
    if let Some(requested) = requested_operation
        && !operations
            .iter()
            .any(|name| name.as_deref() == Some(requested))
    {
        return Err(Error::Input(format!(
            "GraphQL operation {requested:?} was not found"
        )));
    }
    Ok(())
}

pub fn parse_object(source: &str, label: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(source)
        .map_err(|e| Error::Input(format!("invalid {label} JSON: {e}")))?;
    if !value.is_object() {
        return Err(Error::Input(format!("{label} must be a JSON object")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_query_and_fragments() {
        ensure_read_only(
            "query Read { viewer { ...Fields } } fragment Fields on User { id }",
            None,
        )
        .unwrap();
    }

    #[test]
    fn permits_shorthand_query() {
        ensure_read_only("{ viewer { id } }", None).unwrap();
    }

    #[test]
    fn rejects_mutation_hidden_after_query() {
        let error = ensure_read_only(
            "query Safe { viewer { id } } mutation Bad { deleteAll }",
            Some("Safe"),
        )
        .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn rejects_subscription_and_fragment_only_documents() {
        assert!(ensure_read_only("subscription Events { events { id } }", None).is_err());
        assert!(ensure_read_only("fragment Fields on User { id }", None).is_err());
    }

    #[test]
    fn requires_and_validates_operation_name() {
        let source = "query One { one } query Two { two }";
        assert!(ensure_read_only(source, None).is_err());
        ensure_read_only(source, Some("Two")).unwrap();
        assert!(ensure_read_only(source, Some("Missing")).is_err());
    }

    #[test]
    fn requires_object_variables() {
        assert!(parse_object("[]", "variables").is_err());
        assert!(parse_object("{", "variables").is_err());
    }
}

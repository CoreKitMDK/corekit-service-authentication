# Knative Function: rights-get

This Knative function, `rights-get`, is an integral part of the `corekit-service-authorization` microservice, designed to retrieve all active access rights associated with a specific entity within the CoreKit ecosystem.

**Functionality:**
- **Input:** It expects an HTTP POST request containing a JSON payload that conforms to the `GetRightsRequest` structure. This request primarily specifies the `Entity` (a UUID) for which the rights are to be retrieved.
- **Processing:** Upon receiving a request, the function queries the underlying PostgreSQL database through the Authorization Data Access Layer (DAL). It fetches all `Right` entries where the `entity` matches the provided `Entity` ID and the `active` status is `true`. The retrieved rights are then aggregated into a map, where each key is the `UID` of the right (as a string) and the value is the `Right` object itself.
- **Output:** The function responds with an HTTP 200 OK status and a JSON payload representing a `GetRightsResponse`. This response includes the `Entity` whose rights were queried, a map of the retrieved `Rights`, a `Valid` boolean flag indicating the success of the operation, and an `Error` string if any issues occurred during processing.

This function provides a comprehensive view of an entity's current permissions, enabling other services to make informed authorization decisions.
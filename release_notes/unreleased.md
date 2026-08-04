**Unreleased**
* Reject dot-segment identifiers before constructing Microsoft Graph request paths.
* Reject empty group identifiers before attempting to remove a user from a group.
* Require the pending flow nonce before returning the OAuth authorization redirect.
* Stop reading Graph responses that exceed the connector response-size limit.
* Bound the cumulative response bytes retained by paginated Graph actions and reject redirects.
* Bound individual paginated rows and continuation tokens before retaining them.

**Unreleased**

* - Encoded user and group identifiers before placing them in Azure AD request paths.
* - Escaped user values rendered by the Azure AD widget.
* - Bound OAuth callbacks to a high-entropy, one-time state value.
* - Added page and item limits and loop detection to paginated Azure AD requests.
* - Prevented OAuth token responses and headers from being written to debug data.
* - Prevented temporary password values from being copied into persisted action-result parameters.
* - Verified that a group exists before reporting a missing membership as a successful removal.
* - Invalidated refresh tokens after disabling a user and documented the remaining access-token lifetime.

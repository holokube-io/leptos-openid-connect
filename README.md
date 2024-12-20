# Leptos OpenID Connect

Simple OpenID connect implementation for Leptos.
This library is based on [`leptos_oidc`](https://gitlab.com/kerkmann/leptos_oidc).

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| 0.1           | 0.7                       |

## Features

Currently, the following features are supported:

- OIDC Init flow
- Generating Login/Logout URL from OIDC Discovery
- Refreshing access tokens, storing them in local storage
- PKCE Challenge
- Support for server-side rendering (enable feature `ssr` on server-side).

## Tested backends

- Zitadel

## Usage

Inside a `Router`, call `provide_auth()` with appropriate parameters.

```rust
#[component]
fn AppWithRouter() -> impl IntoView {
  provide_auth(AuthParameters {
    issuer: "http://zitadel.local".into(),
    client_id: "<Client ID>".into(),
    redirect_uri: "http://openid-test.local".into(),
    post_logout_redirect_uri: "http://openid-test.local".into(),
    challenge: Challenge::Sha256,
    scope: Some("openid%20offline_access%20email".into()),
    audience: None,
  });
  
  // use Transition instead of this...
  move || {
    let auth = expect_auth();
    if auth.authenticated() {
      view! {
        <span>"Authenticated!"</span>
        <a href=move || auth.logout_url().get()>"Logout"</a>
      }.into_any()
    } else {
      view! {
        <span>"Not authenticated :("</span>
        <a href=move || auth.login_url().get()>"Login"</a>
      }.into_any()
    }
  }
 
}

```

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Daniél Kerkmann <daniel@kerkmann.dev>
 * Copyright (c) 2024 Leonard Seibold <git@zrtx.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#![cfg_attr(feature = "ssr", allow(unused, dead_code))]

use std::str::FromStr;
use std::sync::Arc;

use chrono::Local;
use codee::string::JsonSerdeCodec;
use error::AuthError;
use jsonwebtoken::{
  decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, TokenData,
  Validation,
};
use jwt::Claims;
use leptos::{logging::log, prelude::*};
use leptos_router::{
  hooks::{use_navigate, use_query},
  NavigateOptions,
};
use leptos_use::{
  storage::{use_local_storage, use_session_storage},
  use_timeout_fn, UseTimeoutFnReturn,
};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use reqwest::Client;
use response::{
  CallbackResponse, ErrorResponse, SuccessCallbackResponse,
  SuccessTokenResponse,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use storage::{TokenStorage, CODE_VERIFIER_KEY, LOCAL_STORAGE_KEY};
use utils::ParamBuilder;


mod error;
mod response;
mod storage;
mod utils;

pub type MaybeIssuer = ReadSignal<Option<(Configuration, Keys)>>;
pub type MaybeAuth =
  ReadSignal<Option<Result<Option<TokenStorage>, AuthError>>>;

type SetMaybeAuth =
  WriteSignal<Option<Result<Option<TokenStorage>, AuthError>>>;

const REFRESH_TOKEN_SECONDS_BEFORE: usize = 30;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthParameters {
  pub issuer: String,
  pub client_id: String,
  pub redirect_uri: String,
  pub post_logout_redirect_uri: String,
  pub challenge: Challenge,
  pub scope: Option<String>,
  pub audience: Option<String>,
}

#[derive(
  Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
pub enum Challenge {
  #[default]
  Sha256,
  Plain,
  None,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Configuration {
  pub issuer: String,
  pub authorization_endpoint: String,
  pub token_endpoint: String,
  pub end_session_endpoint: String,
  pub jwks_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Keys {
  keys: Vec<Jwk>,
}

#[derive(Clone)]
pub struct Auth {
  parameters: AuthParameters,
  issuer: MaybeIssuer,
  auth: MaybeAuth,
  redirect_uri: RwSignal<String>,
}

impl Auth {
  pub fn login_url(&self) -> Signal<Option<String>> {
    #[cfg(feature = "ssr")]
    return signal(None).0.into();

    let (code_verifier, set_code_verifier, remove_code_verifier) =
      use_session_storage::<Option<String>, JsonSerdeCodec>(CODE_VERIFIER_KEY);

    let auth = self.clone();
    Signal::derive(move || {
      let (configuration, _) = auth.issuer.get()?;

      let mut params = configuration
        .authorization_endpoint
        .clone()
        .push_param_query("response_type", "code")
        .push_param_query("client_id", &auth.parameters.client_id)
        .push_param_query("redirect_uri", &auth.redirect_uri.get_untracked())
        .push_param_query(
          "scope",
          auth.parameters.scope.clone().unwrap_or("openid".into()),
        );

      if let Some(audience) = &auth.parameters.audience {
        params = params.push_param_query("audience", audience);
      }

      match &auth.parameters.challenge {
        Challenge::Sha256 | Challenge::Plain => {
          let code_challenge =
            if let Some(code_verifier_secret) = code_verifier.get_untracked() {
              let verifier = PkceCodeVerifier::new(code_verifier_secret);
              match &auth.parameters.challenge {
                Challenge::Sha256 => {
                  PkceCodeChallenge::from_code_verifier_sha256(&verifier)
                }
                Challenge::Plain => {
                  PkceCodeChallenge::from_code_verifier_plain(&verifier)
                }
                Challenge::None => unreachable!(),
              }
            } else {
              let (code, verifier) = match auth.parameters.challenge {
                Challenge::Sha256 => PkceCodeChallenge::new_random_sha256(),
                Challenge::Plain => PkceCodeChallenge::new_random_plain(),
                Challenge::None => unreachable!(),
              };
              set_code_verifier
                .update(|s| *s = Some(verifier.secret().to_owned()));
              code
            };

          params = params
            .push_param_query("code_challenge", code_challenge.as_str())
            .push_param_query(
              "code_challenge_method",
              code_challenge.method().as_str(),
            );
        }
        Challenge::None => {
          set_code_verifier.set(None);
          remove_code_verifier();
        }
      }

      Some(params)
    })
  }

  pub fn logout_url(&self) -> Signal<Option<String>> {
    let auth = self.clone();
    Signal::derive(move || {
      let (configuration, _) = auth.issuer.get()?;
      let url = configuration.end_session_endpoint.clone().push_param_query(
        "post_logout_redirect_uri",
        auth
          .parameters
          .post_logout_redirect_uri
          .clone()
          .push_param_query("destroy_session", "true"),
      );

      if let Some(token) = auth.auth.get().and_then(Result::ok).flatten() {
        Some(url.push_param_query("id_token_hint", token.id_token))
      } else {
        Some(url)
      }
    })
  }

  pub fn loading(&self) -> bool {
    self.auth.get().is_none()
  }

  pub fn authenticated(&self) -> bool {
    self.auth.get().and_then(Result::ok).flatten().is_some()
  }

  pub fn set_redirect_uri(&self, uri: impl ToString) {
    self.redirect_uri.set(uri.to_string());
  }

  pub fn id_token(&self) -> Signal<Option<String>> {
    let auth = self.clone();
    Signal::derive(move || {
      auth
        .auth
        .get()
        .and_then(Result::ok)
        .flatten()
        .map(|response| response.id_token)
    })
  }

  pub fn decoded_id_token<T: DeserializeOwned + Sync + Send + 'static>(
    &self,
    algorithm: Algorithm,
    audience: &[&str],
  ) -> Signal<Option<Option<TokenData<T>>>> {
    let auth = self.clone();
    let mut validation = Validation::new(algorithm);
    validation.set_audience(audience);

    Signal::derive(move || {
      let (_, Keys { keys }) = auth.issuer.get()?;
      auth
        .auth
        .get()
        .and_then(Result::ok)
        .flatten()
        .map(|response| {
          for key in keys {
            let Ok(decoding_key) = DecodingKey::from_jwk(&key) else {
              continue;
            };

            match decode::<T>(&response.id_token, &decoding_key, &validation) {
              Ok(data) => return Some(data),
              Err(_) => continue,
            }
          }

          None
        })
    })
  }

  pub fn access_token(&self) -> Signal<Option<String>> {
    let auth = self.clone();
    Signal::derive(move || {
      auth
        .auth
        .get()
        .and_then(Result::ok)
        .flatten()
        .map(|response| response.access_token)
    })
  }

  pub fn decoded_access_token<T: DeserializeOwned + Sync + Send + 'static>(
    &self,
    algorithm: Algorithm,
    audience: &[&str],
  ) -> Signal<Option<Option<TokenData<T>>>> {
    let auth = self.clone();
    let mut validation = Validation::new(algorithm);
    validation.set_audience(audience);

    Signal::derive(move || {
      let (_, Keys { keys }) = auth.issuer.get()?;
      auth
        .auth
        .get()
        .and_then(Result::ok)
        .flatten()
        .map(|response| {
          for key in keys {
            let Ok(decoding_key) = DecodingKey::from_jwk(&key) else {
              continue;
            };

            match decode::<T>(&response.id_token, &decoding_key, &validation) {
              Ok(data) => return Some(data),
              Err(_) => continue,
            }
          }
          None
        })
    })
  }
}

pub fn provide_auth(params: AuthParameters) {
  let issuer = run_openid_discovery(&params);
  let redirect_uri = RwSignal::new(params.redirect_uri.clone());
  let (auth, set_auth) =
    create_auth_effect(issuer, params.clone(), redirect_uri);

  create_handle_refresh_effect(params.clone(), issuer, auth, set_auth);

  let auth = Auth {
    parameters: params,
    issuer,
    auth,
    redirect_uri,
  };
  provide_context(auth);
}

pub fn expect_auth() -> Auth {
  expect_context::<Auth>()
}

fn run_openid_discovery(params: &AuthParameters) -> MaybeIssuer {
  let (get_issuer, set_issuer) = signal(None);

  #[cfg(not(feature = "ssr"))]
  {
    let issuer = params.issuer.clone();
    leptos::task::spawn_local(async move {
      let res: Result<(Configuration, Keys), reqwest::Error> = async move {
        let configuration = get_openid_configuration(&issuer).await?;
        let keys = get_jwks_keys(&configuration.jwks_uri).await?;
        Ok((configuration, keys))
      }
      .await;

      match res {
        Ok(issuer) => {
          set_issuer.set(Some(issuer));
        }
        Err(err) => {
          leptos::logging::error!("OpenID discovery failed: {}", err);
        }
      }
    });
  }

  get_issuer
}

async fn get_openid_configuration(
  issuer: &str,
) -> Result<Configuration, reqwest::Error> {
  let configuration = reqwest::Client::new()
    .get(format!("{}/.well-known/openid-configuration", issuer))
    .send()
    .await?
    .json::<Configuration>()
    .await?;
  Ok(configuration)
}

async fn get_jwks_keys(jwks_uri: &str) -> Result<Keys, reqwest::Error> {
  let keys = reqwest::Client::new()
    .get(jwks_uri)
    .send()
    .await?
    .json::<Keys>()
    .await?;
  Ok(keys)
}

fn create_auth_effect(
  issuer: MaybeIssuer,
  params: AuthParameters,
  redirect_uri: RwSignal<String>,
) -> (MaybeAuth, SetMaybeAuth) {
  let auth_query = use_query::<CallbackResponse>();
  let navigate = use_navigate();

  let (auth, set_auth) = signal(None);

  let _ = Effect::new(move || {
    if let Some((configuration, _keys)) = issuer.get() {
      let (local_storage, set_local_storage, remove_local_storage) =
        use_local_storage::<Option<TokenStorage>, JsonSerdeCodec>(
          LOCAL_STORAGE_KEY,
        );

      let local_storage = local_storage.get_untracked();

      if issuer.get().is_none() {
        return;
      }

      match auth_query.get_untracked() {
        Ok(CallbackResponse::SuccessLogin(response)) => {
          navigate(
            &redirect_uri.get_untracked(),
            NavigateOptions {
              resolve: false,
              replace: true,
              scroll: true,
              state: leptos_router::location::State::new(None),
            },
          );

          if let Some(token_storage) = local_storage {
            if token_storage.expires_in >= Local::now().naive_utc() {
              set_auth.set(Some(Ok(Some(token_storage))));
              return;
            }
          }

          leptos::task::spawn_local({
            let params = params.clone();
            // let navigate = navigate.clone();
            async move {
              let res =
                fetch_token(&params, &configuration, response, redirect_uri)
                  .await;
              match res {
                Ok(token_storage) => {
                  set_local_storage
                    .update(|s| *s = Some(token_storage.clone()));
                  set_auth.set(Some(Ok(Some(token_storage))));
                }
                Err(err) => {
                  set_auth.set(Some(Err(err)));
                }
              }
            }
          });
        }
        Ok(CallbackResponse::SuccessLogout(response)) => {
          navigate(
            &params.post_logout_redirect_uri,
            NavigateOptions {
              resolve: false,
              replace: true,
              scroll: true,
              state: leptos_router::location::State::new(None),
            },
          );
          if response.destroy_session {
            set_local_storage.set(None);
            remove_local_storage();
          }
          set_auth.set(Some(Ok(None)));
        }
        Ok(CallbackResponse::Error(err)) => {
          set_auth.set(Some(Err(AuthError::Provider(err))));
        }
        Err(_) => {
          if let Some(token_storage) = local_storage {
            if token_storage.expires_in >= Local::now().naive_utc() {
              set_auth.set(Some(Ok(Some(token_storage))));
            } else {
              set_local_storage.set(None);
              remove_local_storage();
            }
          } else {
            set_auth.set(Some(Ok(None)));
          }
        }
      }
    }
  });

  (auth, set_auth)
}

/// This will handle the refresh, if there is an refresh token.
fn create_handle_refresh_effect(
  parameters: AuthParameters,
  issuer: MaybeIssuer,
  auth: MaybeAuth,
  set_auth: SetMaybeAuth,
) {
  let _ = Effect::new(move |_| {
    let Some(issuer) = issuer.get() else {
      return;
    };
    let Some(Ok(Some(token_storage))) = auth.get() else {
      return;
    };

    let expires_in = token_storage.expires_in - Local::now().naive_utc();
    #[allow(clippy::cast_precision_loss)]
    let wait = (expires_in.num_seconds() as f64
      - REFRESH_TOKEN_SECONDS_BEFORE as f64)
      .max(0.0)
      * 1000.0;

    let UseTimeoutFnReturn { start, .. } = use_timeout_fn(
      move |(parameters, configuration, set_auth, token): (
        AuthParameters,
        Configuration,
        SetMaybeAuth,
        String,
      )| {
        leptos::task::spawn_local(async move {
          match refresh_token(&parameters, &configuration, token)
            .await
            .map(Option::Some)
          {
            Ok(token_storage) => {
              use_local_storage::<Option<TokenStorage>, JsonSerdeCodec>(
                LOCAL_STORAGE_KEY,
              )
              .1
              .update(|u| *u = token_storage);
            }
            Err(err) => {
              set_auth.set(Some(Err(err)));
            }
          }
        });
      },
      wait,
    );

    start((
      parameters.clone(),
      issuer.0,
      set_auth,
      token_storage.refresh_token.clone(),
    ));
  });
}

/// Asynchronous function for fetching an authentication token.
/// This function is used to exchange an authorization code for an access token.
async fn fetch_token(
  parameters: &AuthParameters,
  configuration: &Configuration,
  auth_response: SuccessCallbackResponse,
  redirect_uri: RwSignal<String>,
) -> Result<TokenStorage, AuthError> {
  let mut body = "&grant_type=authorization_code"
    .to_string()
    .push_param_body("client_id", &parameters.client_id)
    .push_param_body("redirect_uri", &redirect_uri.get_untracked())
    .push_param_body("code", &auth_response.code);

  if let Some(state) = &auth_response.session_state {
    body = body.push_param_body("state", state);
  }

  let (code_verifier, _, remove_code_verifier) =
    use_session_storage::<Option<String>, JsonSerdeCodec>(CODE_VERIFIER_KEY);

  if let Some(code_verifier) = code_verifier.get_untracked() {
    body = body.push_param_body("code_verifier", code_verifier);

    remove_code_verifier();
  }

  let response = reqwest::Client::new()
    .post(configuration.token_endpoint.clone())
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(body)
    .send()
    .await
    .map_err(Arc::new)?;

  if response.status().is_success() {
    Ok(
      response
        .json::<SuccessTokenResponse>()
        .await
        .map_err(Arc::new)?
        .into(),
    )
  } else {
    Err(AuthError::Provider(
      response.json::<ErrorResponse>().await.map_err(Arc::new)?,
    ))
  }
}

/// Asynchronous function for refetching an authentication token.
/// This function is used to exchange a new access token and refresh token.
async fn refresh_token(
  parameters: &AuthParameters,
  configuration: &Configuration,
  refresh_token: String,
) -> Result<TokenStorage, AuthError> {
  let response = reqwest::Client::new()
    .post(configuration.token_endpoint.clone())
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(
      "&grant_type=refresh_token"
        .to_string()
        .push_param_body("client_id", &parameters.client_id)
        .push_param_body("refresh_token", refresh_token),
    )
    .send()
    .await
    .map_err(Arc::new)?;

  if response.status().is_success() {
    Ok(
      response
        .json::<SuccessTokenResponse>()
        .await
        .map_err(Arc::new)?
        .into(),
    )
  } else {
    Err(AuthError::Provider(
      response.json::<ErrorResponse>().await.map_err(Arc::new)?,
    ))
  }
}

//////////////////////////////////////////////////
//////////////////////////////////////////////////
//////////////////////////////////////////////////
//////////////////////////////////////////////////
//////////////////////////////////////////////////
//////////////////////////////////////////////////

async fn fetch_jwks(
  jwks_url: &str,
) -> Result<Vec<Jwk>, Box<dyn std::error::Error>> {
  let client = Client::new();
  let response = client.get(jwks_url).send().await?;
  let jwks = response.json::<Keys>().await?;
  Ok(jwks.keys)
}


#[derive(Debug, Deserialize)]
struct MyClaims {
  sub: String, // User ID
  exp: usize,  // Expiration timestamp
               // Add other claim fields as needed
}

async fn verify_token(
  token: &str,
  jwks_uri: &str,
) -> Result<String, AuthError> {
  let jwks = fetch_jwks(&jwks_uri).await?;

  // Decode the token header to get the `kid`
  let header = decode_header(token).unwrap();
  let kid = header.kid.ok_or("No kid in token header")?;

  // Find the matching JWK
  let jwk = jwks.iter().find(|jwk| jwk.common.key_id.unwrap().as_str() == kid).unwrap();


  if let(Some(decoding_key)) = DecodingKey::from_jwk(jwk).ok() {
    if let (Some(key_algorithm)) = jwk.common.key_algorithm {
      if let (Some(algorithm)) = Algorithm::from_str(key_algorithm.to_string().as_str()).ok() {
        let validation = Validation::new(algorithm);
        let token_data: TokenData<Claims> =
            decode(token, &decoding_key, &validation).unwrap();

        // Step 7: Extract the user ID from the claims
        Ok(token_data.claims.sub)
      }
    }
  }
  Err(AuthError::Provider(ErrorResponse {
    error: "invalid_token".to_string(),
    error_description: "Invalid token".to_string(),
  }))
}

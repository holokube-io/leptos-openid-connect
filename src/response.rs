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

use leptos_router::params::{Params, ParamsError, ParamsMap};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackResponse {
  SuccessLogin(SuccessCallbackResponse),
  SuccessLogout(SuccessLogoutResponse),
  Error(ErrorResponse),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessCallbackResponse {
  pub session_state: Option<String>,
  pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessLogoutResponse {
  pub destroy_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenResponse {
  Success(SuccessTokenResponse),
  Error(ErrorResponse),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessTokenResponse {
  pub access_token: String,
  pub expires_in: i64,
  pub refresh_expires_in: Option<i64>,
  pub refresh_token: String,
  pub token_type: Option<String>,
  pub id_token: String,
  #[serde(rename = "not-before-policy")]
  pub not_before_policy: Option<i64>,
  pub session_state: Option<String>,
  pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
  pub error: String,
  pub error_description: String,
}

impl Params for SuccessCallbackResponse {
  fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
    if let (session_state, Some(code)) =
      (map.get("session_state"), map.get("code"))
    {
      Ok(SuccessCallbackResponse {
        session_state,
        code,
      })
    } else {
      Err(ParamsError::MissingParam("Missing parameter 'code'".into()))
    }
  }
}

impl Params for SuccessLogoutResponse {
  fn from_map(
    map: &ParamsMap,
  ) -> Result<Self, leptos_router::params::ParamsError> {
    if let Some(destroy_session) = map.get("destroy_session") {
      Ok(SuccessLogoutResponse {
        destroy_session: destroy_session.parse().unwrap_or_default(),
      })
    } else {
      Err(ParamsError::MissingParam(
        "Missing parameter 'destroy_session'".into(),
      ))
    }
  }
}

impl Params for ErrorResponse {
  fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
    if let (Some(error), Some(error_description)) =
      (map.get("error"), map.get("error_description"))
    {
      Ok(ErrorResponse {
        error,
        error_description,
      })
    } else {
      Err(ParamsError::MissingParam(
        "Missing parameter 'error' and/or 'error_description'".into(),
      ))
    }
  }
}

impl Params for CallbackResponse {
  fn from_map(map: &ParamsMap) -> Result<Self, ParamsError> {
    if let Ok(response) = SuccessCallbackResponse::from_map(map) {
      Ok(CallbackResponse::SuccessLogin(response))
    } else if let Ok(response) = SuccessLogoutResponse::from_map(map) {
      Ok(CallbackResponse::SuccessLogout(response))
    } else if let Ok(response) = ErrorResponse::from_map(map) {
      Ok(CallbackResponse::Error(response))
    } else {
      Err(ParamsError::MissingParam(
        "Missing parameter 'session_state' and 'code' or 'error' and \
         'error_description'"
          .into(),
      ))
    }
  }
}

//! <https://developers.yubico.com/WebAuthn/WebAuthn_Walk-Through.html>
//! <https://www.w3.org/TR/webauthn-2/>

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize, de::Visitor};
use tokio::{fs::read_to_string, sync::Mutex};

#[derive(Serialize, Deserialize)]
struct PublicKey {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Serialize, Deserialize)]
struct PublicKeyCredentialCreationOptions {
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntity,
    challenge: Vec<u8>, // Should be at least 16 bytes
    #[serde(rename = "pubKeyCredParams")]
    pubkey_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(
        rename = "authenticatorSelection",
        skip_serializing_if = "Option::is_none"
    )]
    authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<Attestation>,
    hints: Vec<PublicKeyCredentialHint>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PublicKeyCredentialHint {
    SecurityKey,
    ClientDevice,
    Hybrid,
}

#[derive(Serialize, Deserialize)]
struct PublicKeyCredentialRpEntity {
    id: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct PublicKeyCredentialUserEntity {
    id: Vec<u8>,  // Max 64 bytes
    name: String, // Has to be non-zero length

    #[serde(rename = "displayName")]
    display_name: String, // Has to be non-zero length
}

#[derive(Serialize, Deserialize)]
struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    type_: PublicKeyCredentialType,
    alg: Algorithm,
}

#[derive(Serialize, Deserialize)]
enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

/// <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
/// - Keys with algorithm ES256 (-7) MUST specify P-256 (1) as the crv parameter and MUST NOT use the
///   compressed point form.
/// - Keys with algorithm ES384 (-35) MUST specify P-384 (2) as the crv parameter and MUST NOT use
///   the compressed point form.
#[derive(Clone, Copy)]
#[repr(i8)]
enum Algorithm {
    ES256 = -7,
    ES384 = -35,
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i8(*self as i8)
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_i8(I8Algorithm)
    }
}

struct I8Algorithm;

impl<'de> Visitor<'de> for I8Algorithm {
    type Value = Algorithm;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expected an i8")
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let v = i32::from(v);
        Ok(match v {
            -7 => Algorithm::ES256,
            -35 => Algorithm::ES384,
            _ => return Err(E::custom("the only valid values are -7 and -35")),
        })
    }
}

#[derive(Default)]
struct AppState {
    users: Vec<User>,
    registration_challenges: Vec<(String, [u8; 32])>,
    login_challenges: Vec<(String, [u8; 32])>,
}

#[derive(Serialize, Deserialize)]
struct AuthenticatorSelectionCriteria {
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    authenticator_attatchment: Option<AuthenticatorAttachment>,
    #[serde(rename = "userVerification")]
    user_verification: UserVerificationRequirement,
    #[serde(rename = "residentKey")]
    resident_key: ResidentKeyRequirement,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Attestation {
    None,
    Indirect,
    Direct,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

struct User {
    id: [u8; 32],
    name: String,
    pub_key: Option<Vec<u8>>,
}

const DOMAIN: &str = "localhost";

#[tokio::main]
async fn main() {
    let test_user = User {
        id: rand::random(),
        name: String::from("mroik"),
        pub_key: None,
    };

    let (opts, _) = create_PublicKey(&test_user);
    println!("{}", serde_json::to_string(&opts).unwrap());

    let state = Arc::new(Mutex::new(AppState::default()));
    state.lock().await.users.push(test_user);

    let app = Router::new()
        .route("/", get(handle_static))
        .route("/register", post(handle_post_register))
        .route("/register/finish", post(handle_post_register_finish))
        .route("/login", post(handle_post_login))
        .route("/login/finish", post(handle_post_login_finish))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_static(State(_): State<Arc<Mutex<AppState>>>) -> String {
    read_to_string("index.html").await.unwrap()
}

async fn handle_post_register(State(state): State<Arc<Mutex<AppState>>>) -> String {
    let mut state = state.lock().await;
    let (opts, challenge) = create_PublicKey(state.users.first().unwrap());
    state.registration_challenges.push((
        String::from("this-is-the-id-associated-to-mroik"),
        challenge,
    ));
    serde_json::to_string(&opts).unwrap()
}

/// Saves attestation returned by the browser after `navigator.credentials.create()` used for logins
async fn handle_post_register_finish(State(state): State<Arc<Mutex<AppState>>>) -> String {
    todo!()
}

async fn handle_post_login(State(state): State<Arc<Mutex<AppState>>>) -> String {
    todo!()
}

async fn handle_post_login_finish(State(state): State<Arc<Mutex<AppState>>>) -> String {
    todo!()
}

/// Credential registration on a yubikey works using these parameters. It's important to set
/// `AuthenticatorSelectionCriteria.resident_key = ResidentKeyRequirement::Required`.
#[allow(non_snake_case)]
fn create_PublicKey(user: &User) -> (PublicKey, [u8; 32]) {
    let challenge = rand::random::<[u8; 32]>();
    (
        PublicKey {
            public_key: PublicKeyCredentialCreationOptions {
                rp: PublicKeyCredentialRpEntity {
                    id: String::from(DOMAIN),
                    name: String::from("WebAuthn demo"),
                },
                user: PublicKeyCredentialUserEntity {
                    id: user.id.to_vec(),
                    name: user.name.clone(),
                    display_name: user.name.clone(),
                },
                challenge: challenge.to_vec(),
                pubkey_cred_params: vec![
                    PublicKeyCredentialParameters {
                        type_: PublicKeyCredentialType::PublicKey,
                        alg: Algorithm::ES256,
                    },
                    PublicKeyCredentialParameters {
                        type_: PublicKeyCredentialType::PublicKey,
                        alg: Algorithm::ES384,
                    },
                ],
                attestation: Some(Attestation::Direct),
                authenticator_selection: Some(AuthenticatorSelectionCriteria {
                    user_verification: UserVerificationRequirement::Required,
                    authenticator_attatchment: None,
                    resident_key: ResidentKeyRequirement::Required,
                }),
                hints: vec![
                    PublicKeyCredentialHint::SecurityKey,
                    PublicKeyCredentialHint::ClientDevice,
                    PublicKeyCredentialHint::Hybrid,
                ],
            },
        },
        challenge,
    )
}

use sqlx::Row;
use ras_service::{
	*,
	ras_auth_client::{
		RasAuthClient,
		AccessToken,
		Token
	}
};
use std::{
	time::{SystemTime, UNIX_EPOCH},
	io::Read,
};
use sqlx::sqlite::{
	SqlitePoolOptions,
	SqlitePool,
};
use serde::{Deserialize, Serialize};
use openssl::{
	sign::{Signer},
	rsa::Rsa,
};

#[derive(Deserialize, Debug)]
struct RasAuthConfig {
	threads: usize,
	socket_url: String,
	path_to_sqlite: String,
	password_for_sign_pass: String,
	default_user_role: u8,
	life_time_token: u128,
}

struct RasAuth {
	sqlite_pool: SqlitePool,
	default_user_role: u8,
	key_for_sign_pass: ring::hmac::Key,
	private_key_for_token: openssl::pkey::PKey<openssl::pkey::Private>,
	public_key_for_token: openssl::pkey::PKey<openssl::pkey::Public>,
	public_key_for_token_bytes: String,
	session_ids: Mutex<HashMap<String, u32>>,
	config: RasAuthConfig,
}

impl RasAuth {
	async fn new(config: RasAuthConfig) -> RasAuth {
		let pool = SqlitePoolOptions::new()
			.max_connections(config.threads as u32 * 2)
			.connect(&format!("sqlite:{}", config.path_to_sqlite))
			.await
			.expect("Panic! Can't connect to Sqlite");

		let key_for_sign_pass = ring::hmac::Key::new(
			ring::hmac::HMAC_SHA256,
			config.password_for_sign_pass.as_bytes()
		);

		let keypair = Rsa::generate(2048)
			.unwrap();
		let private_key = PKey::from_rsa(keypair)
			.unwrap();
		let public_key_bytes = private_key.public_key_to_pem()
			.unwrap();
		let public_key = PKey::public_key_from_pem(&public_key_bytes[..])
			.unwrap();
		let public_key_bytes = base64::encode(public_key_bytes);

		RasAuth {
			sqlite_pool: pool,
			default_user_role: config.default_user_role,
			key_for_sign_pass: key_for_sign_pass,
			private_key_for_token: private_key,
			public_key_for_token: public_key,
			public_key_for_token_bytes: public_key_bytes,
			session_ids: Mutex::new(HashMap::new()),
			config: config,
		}
	}

	fn sign_pass(&self, password: &str) -> String {
		let signature
			= ring::hmac::sign(&self.key_for_sign_pass, password.as_bytes());
		base64::encode(signature)
	}

	fn get_name_and_password_from_query(&self, params: Option<&str>)
	-> Result<(String, String), Option<String>> {
		let params: HashMap<String, Option<String>> = 
		if let Some(query_str) = params {
			match serde_json::from_str(query_str) {
				Ok(query) => query,
				Err(err) => {
					eprintln!("Error! Bad json format: {:?}", err);
					return Err(None);
				}
			}
		} else {
			return Err(None);
		};
		let name = match params.get("name") {
			Some(value) => match value {
				Some(value) => value.clone(),
				_ => return Err(Some("Name don't exist".to_string())),
			},
			_ => return Err(Some("Name don't exist".to_string())),
		};
		let password = self.sign_pass( 
			match params.get("password").as_ref() {
				Some(&value) => match value {
					Some(value) => value,
					_ => return Err(Some("Password don't exist".to_string())),
				},
				_ => return Err(Some("Password don't exist".to_string())),
			}
		);
		Ok((name, password))
	}

	fn sign_token(&self, b64_str: &str)
	-> Result<String, openssl::error::ErrorStack> {
		let mut signer = Signer::new(
			MessageDigest::sha256(),
			&self.private_key_for_token
		)?;
		signer.update(b64_str.as_bytes())?;
		Ok(format!("{}@@{}", b64_str, base64::encode(signer.sign_to_vec()?)))		
	}

	fn create_access_token(&self, name: &String, role: &u8) -> AccessToken {
		AccessToken{
			user_name: name.clone(),
			user_role: role.clone(),
			date_spawn: SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap_or(std::time::Duration::ZERO)
				.as_millis(),
		}
	}

	fn create_refresh_token(&self, name: &String, user_role: &u8)
	-> Result<RefreshToken, ()> {
		let session_id = rand::random::<u32>();
		{
			let mut lock = match self.session_ids.lock() {
				Ok(lock) => lock,
				Err(err) => {
					eprintln!("Error! Fatal! Mutex Session Ids was poisoned: {:?}", err);
					return Err(());
				}
			};
			(*lock).insert(name.clone(), session_id.clone());
		}
		Ok(RefreshToken {
			user_name: name.clone(),
			session_id: session_id,
			user_role: user_role.clone()
		})
	}

	fn check_and_get_refresh_token(&self, token: &str)
	-> Result<RefreshToken, ()> {
		let splited_token: Vec<&str> = token.split("@@").collect();
		if splited_token.len() < 2 
		|| !self.check_token_sign(splited_token[0], splited_token[1]) {
			return Err(());
		}
		let token = RefreshToken::new_from_str(splited_token[0])?;
		let new_session_id = rand::random::<u32>();
		let old_session_id = match {
			let mut lock = match self.session_ids.lock() {
				Ok(lock) => lock,
				Err(err) => {
					eprintln!("Error! Fatal! Mutex Session Ids was poisoned: {:?}", err);
					return Err(());
				}
			};
			(*lock).insert(token.user_name.clone(), new_session_id.clone())
		} {
			Some(val) => val,
			None => return Err(()),
		};
		if old_session_id != token.session_id {
			return Err(());
		}
		Ok(RefreshToken {
			user_name: token.user_name.clone(),
			session_id: new_session_id,
			user_role: token.user_role.clone(),
		})
	}

	fn get_token_from_post_query(&self, params: Option<&str>)
	-> Result<String, ()> {
		let params: HashMap<String, Option<String>> = 
		if let Some(query_str) = params {
			match serde_json::from_str(query_str) {
				Ok(query) => query,
				Err(err) => {
					eprintln!("Error! Bad json format: {:?}", err);
					return Err(());
				}
			}
		} else {
				return Err(());
		};
		match params.get("token") {
			Some(value) => match value {
				Some(val) => Ok(val.clone()),
				None => return Err(()),
			},
			None => return Err(()),
		}
	}
}

impl RasAuthClient for RasAuth {
	fn get_verifier(&self) -> std::result::Result<Verifier, ErrorStack> {
		Verifier::new(MessageDigest::sha256(), &self.public_key_for_token)
	}

	fn get_life_time_token(&self) -> u128 {
		self.config.life_time_token
	}
}

#[derive(Serialize, Deserialize)]
#[derive(Debug)]
struct RefreshToken {
	user_name: String,
	user_role: u8,
	session_id: u32,
}

impl RefreshToken {	
	pub fn new_from_str(b64_json: &str) -> Result<RefreshToken, ()> {
		match serde_json::from_str(
			std::str::from_utf8(
				&base64::decode(b64_json).unwrap()
			).unwrap()
		) {
			Ok(token) => Ok(token),
			Err(err) => {
				eprintln!("Error! Can't create refresh token from str: {:?}", err);
				return Err(());
			},
		}
	}
}

impl Token for RefreshToken {}

fn ping(
	runtime: Handle,
	_self_service: Arc<RasAuth>,
	_params: Option<&str>
) -> RasResult {
	RasResult::Async(runtime.spawn(async move {
		(HttpStatus::OK, Some("pong".to_string()))
	}))
}

fn registration(
	runtime: Handle,
	self_service: Arc<RasAuth>,
	params: Option<&str>	
) -> RasResult {
	let (name, password) = 
		match self_service.get_name_and_password_from_query(params) {
			Ok((name, password)) => (name, password),
			Err(message) => return RasResult::Sync(HttpStatus::BadRequest, message),
		};
	RasResult::Async(runtime.spawn(async move {		
		match sqlx::query("INSERT INTO users VALUES ($1, $2, $3);")
			.bind(name)
			.bind(password)
			.bind(&self_service.default_user_role)
			.execute(&self_service.sqlite_pool)
			.await {
			Err(err) => {
				eprintln!("Error! Can't create user: {:?}", err);
						(HttpStatus::BadRequest, None)				
			},
			_ => (HttpStatus::OK, None)
		}
	}))
}

fn login(
	runtime: Handle,
	self_service: Arc<RasAuth>,
	params: Option<&str>
) -> RasResult {
	let (name, password) = 
		match self_service.get_name_and_password_from_query(params) {
			Ok((name, password)) => (name, password),
			Err(message) => return RasResult::Sync(HttpStatus::BadRequest, message),
		};
 	RasResult::Async(runtime.spawn(async move {
 		let role: u8 = match sqlx::query("
 			SELECT role from users where name=$1 and password=$2;
 		")
			.bind(&name)
			.bind(password)
			.fetch_one(&self_service.sqlite_pool)
			.await {
				Ok(val) => val.get("role"),
				Err(err) => match err {
					sqlx::Error::RowNotFound => return (
						HttpStatus::Forbidden,
						Some("Bad name or password".to_string())
					),
					_ => {
						eprintln!("Error! Can't read data from sqlite: {:?}", err);
						return (HttpStatus::InternalServerError, None);
					},
				}
			};
		let access_token
			= match self_service.create_access_token(&name, &role).get_b64() {
				Ok(val) => val,
				Err(err) => {
					eprintln!("Error! Can't create token: {:?}", err);
					return (HttpStatus::InternalServerError, None);
				},
			};
		let refresh_token = match self_service.create_refresh_token(&name,  &role) {
			Ok(val) => val,
			Err(_) => {
				return (HttpStatus::InternalServerError, None);
			}
		};
		let refresh_token = match refresh_token.get_b64() {
			Ok(val) => val,
			Err(err) => {
				eprintln!("Error! Can't create token: {:?}", err);
				return (HttpStatus::InternalServerError, None);
			},
		};
		let access_token = match self_service.sign_token(&access_token) {
			Ok(val) => val,
			Err(err) => {
				eprintln!("Error! Can't sign token: {:?}", err);
				return (HttpStatus::InternalServerError, None);
			}
		};
		let refresh_token = match self_service.sign_token(&refresh_token) {
			Ok(val) => val,
			Err(err) => {
				eprintln!("Error! Can't sign token: {:?}", err);
				return (HttpStatus::InternalServerError, None);
			}
		};
		(HttpStatus::OK, Some(format!(
			"{{\"access_token\": \"{}\", \"refresh_token\":\"{}\"}}",
			access_token,
			refresh_token
		)))
 	}))
}

fn change_role(
	runtime: Handle,
	self_service: Arc<RasAuth>,
	params: Option<&str>
) -> RasResult {
	let params: HashMap<String, Option<String>> = 
	if let Some(query_str) = params {
		match serde_json::from_str(query_str) {
			Ok(query) => query,
			Err(err) => {
				eprintln!("Error! Bad json format: {:?}", err);
				return RasResult::Sync(HttpStatus::BadRequest, None);
			}
		}
	} else {
			return RasResult::Sync(HttpStatus::BadRequest, None);
	};
	RasResult::Async(runtime.spawn(async move {
		let access_token = match self_service.check_and_get_access_token(
			match params.get("token") {
				Some(value) => match value {
					Some(val) => &val,
					None => return (HttpStatus::BadRequest, None),
				},
				None => return (HttpStatus::BadRequest, None),
			}
		)
		{
			Ok(token) => token,
			Err(()) => return (HttpStatus::AuthenticationTimeout, None),
		};
		if 0b_0000_0110 & access_token.user_role != 0 {
			let name = match params.get("name") {
				Some(value) => match value {
					Some(val) => val.clone(),
					None => return (HttpStatus::BadRequest, None),
				},
				None => return (HttpStatus::BadRequest, None),
			};
			let role = match params.get("role") {
				Some(value) => match value {
					Some(val) => val.clone(),
					None => return (HttpStatus::BadRequest, None),
				},
				None => return (HttpStatus::BadRequest, None),
			};
			let query = "
				UPDATE users SET role=$1 WHERE name = $2;
			";
			match sqlx::query(query)
				.bind(&role)
				.bind(&name)
				.execute(&self_service.sqlite_pool)
				.await
			{
				Ok(_) => (HttpStatus::OK, None),
				Err(err) => {
					eprintln!("Error! Can't update user role: {:?}", err);
					(HttpStatus::InternalServerError, None)
				},
			}
		} else {
			(HttpStatus::Forbidden, None)
		}
	}))
}

fn refresh_token(
	_runtime: Handle,
	self_service: Arc<RasAuth>,
	params: Option<&str>
) -> RasResult {
	let token = match self_service.get_token_from_post_query(params) {
		Ok(token) => token,
		_ => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	//check and gen new token	
	let refresh_token = 
		match self_service.check_and_get_refresh_token(&token) {
			Ok(val) => val,
			Err(_) => {
				return RasResult::Sync(HttpStatus::Forbidden, None);
			}
		};
	let access_token = match self_service.create_access_token(
		&refresh_token.user_name,
		&refresh_token.user_role
	).get_b64() {
		Ok(val) => val,
		Err(err) => {
			eprintln!("Error! Can't create token: {:?}", err);
			return RasResult::Sync(HttpStatus::InternalServerError, None);
		},
	};
	let refresh_token = match refresh_token.get_b64() {
		Ok(val) => val,
		Err(err) => {
			eprintln!("Error! Can't create token: {:?}", err);
			return RasResult::Sync(HttpStatus::InternalServerError, None);
		},
	};
	let access_token = match self_service.sign_token(&access_token) {
		Ok(val) => val,
		Err(err) => {
			eprintln!("Error! Can't sign token: {:?}", err);
			return RasResult::Sync(HttpStatus::InternalServerError, None);
		}
	};
	let refresh_token = match self_service.sign_token(&refresh_token) {
		Ok(val) => val,
		Err(err) => {
			eprintln!("Error! Can't sign token: {:?}", err);
			return RasResult::Sync(HttpStatus::InternalServerError, None);
		}
	};
	RasResult::Sync(HttpStatus::OK, Some(format!(
		"{{\"access_token\": \"{}\", \"refresh_token\":\"{}\"}}",
		access_token,
		refresh_token
	)))
}

fn get_public_key(
	_runtime: Handle,
	self_service: Arc<RasAuth>,
	params: Option<&str>
) -> RasResult {
	let token = match self_service.get_token_from_post_query(params) {
		Ok(token) => token,
		_ => return RasResult::Sync(HttpStatus::BadRequest, None),
	};
	let token = match self_service.check_and_get_access_token(&token) {
		Ok(token) => token,
		Err(()) => return RasResult::Sync(HttpStatus::AuthenticationTimeout, None),
	};
	if 1 & token.user_role != 0 {
		RasResult::Sync(
			HttpStatus::OK,
			Some(format!(
				"{{\"public_key\":\"{}\"}}",
				self_service.public_key_for_token_bytes
			))
		)
	} else {
		RasResult::Sync(HttpStatus::Forbidden, Some("Bad role".to_string()))
	}
}

fn main() {
	let mut config = String::new();
	{
		std::fs::File::open("config.json")
			.unwrap()
			.read_to_string(&mut config)
			.unwrap();
	}
	let config: RasAuthConfig = serde_json::from_str(&config).unwrap();
	let socket_url = config.socket_url.clone();
	let runtime = RasServiceBuilder::<RasAuth>::get_runtime(config.threads);
	let service = runtime.block_on(async move {RasAuth::new(config).await});
	RasServiceBuilder::new(runtime, service)
		.set_socket_url(&socket_url)
		.add_get_function("ping".to_string(), ping)
		.add_post_function("registration".to_string(), registration)
		.add_post_function("login".to_string(), login)
		.add_post_function("refresh".to_string(), refresh_token)
		.add_post_function("get_public_key".to_string(), get_public_key)
		.add_post_function("change_role".to_string(), change_role)
		.run();
}

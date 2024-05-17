//
//  Copyright 2024 Ram Flux, LLC.
//

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Response<T> {
    pub code: u32,
    pub message: String,
    pub result: Option<T>,
}

impl<T> From<Result<T, crate::Error>> for Response<T>
where
    T: serde::Serialize + Sized,
{
    fn from(res: Result<T, crate::Error>) -> Self {
        match res {
            Ok(ok) => ok.into(),
            Err(err) => {
                let (code, message) = err.into();
                Response {
                    code,
                    message,
                    result: None,
                }
            }
        }
    }
}

impl<T> From<T> for Response<T>
where
    T: serde::Serialize + Sized,
{
    fn from(msg: T) -> Self {
        Self {
            code: 200,
            message: String::new(),
            result: Some(msg),
        }
    }
}

impl From<crate::Error> for (u32, String) {
    fn from(err: crate::Error) -> Self {
        let (code, message) = match err {
            crate::error::Error::Wallet(_) => (203, err.to_string()),
            crate::error::Error::Bip39(_) => (204, err.to_string()),
            crate::error::Error::BadRequest(_) => (204, err.to_string()),
            crate::error::Error::System(_) => (204, err.to_string()),
            crate::error::Error::UnAuthorize => (204, err.to_string()),
            crate::error::Error::Parse(_) => (204, err.to_string()),
        };
        (code, message)
    }
}

impl<T> std::ops::FromResidual<Result<std::convert::Infallible, crate::Error>> for Response<T> {
    fn from_residual(residual: Result<std::convert::Infallible, crate::Error>) -> Self {
        match residual {
            Err(err) => {
                let (code, message) = err.into();
                Response {
                    code,
                    message,
                    result: None,
                }
            }
            Ok(_) => panic!("Infallible"),
        }
    }
}

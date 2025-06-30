use actix_web::{
    dev::{ServiceRequest, ServiceResponse, Transform, Service},
    Error,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

pub struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestLoggerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware { service }))
    }
}

pub struct RequestLoggerMiddleware<S> { service: S }

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        println!("Incoming Request: {} {}", req.method(), req.path());
        println!("Headers: {:?}", req.headers());
        
        let method = req.method().clone();
        let path = req.path().to_string();
        
        if method == "POST" {
            if let Some(content_type) = req.headers().get("content-type") {
                let content_type = content_type.to_str().unwrap_or("");
                if content_type.contains("application/json") {
                    println!("Content-Type: {}", content_type);
                    if let Some(content_length) = req.headers().get("content-length") {
                        println!("Content-Length: {:?}", content_length);
                    }
                }
            }
        }
        
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            println!("Response Status: {} for {} {}", res.status(), method, path);
            Ok(res)
        })
    }
}

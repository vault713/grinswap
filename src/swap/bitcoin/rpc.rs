// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::swap::ErrorKind;
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct LineStream {
	inner: TcpStream,
	reader: BufReader<TcpStream>,
	connected: bool,
}

impl LineStream {
	pub fn new(address: String) -> Result<Self, ErrorKind> {
		let address = address
			.to_socket_addrs()?
			.next()
			.ok_or(ErrorKind::Generic("Unable to parse address".into()))?;

		let timeout = Duration::from_secs(10);
		let stream = TcpStream::connect_timeout(&address, timeout)?;
		stream.set_read_timeout(Some(timeout))?;
		stream.set_write_timeout(Some(timeout))?;

		let reader = BufReader::new(stream.try_clone()?);
		Ok(Self {
			inner: stream,
			reader,
			connected: true,
		})
	}

	pub fn is_connected(&self) -> bool {
		self.connected
	}

	pub fn read_line(&mut self) -> Result<String, ErrorKind> {
		let mut line = String::new();
		match self.reader.read_line(&mut line) {
			Err(e) => {
				self.connected = false;
				return Err(e.into());
			}
			Ok(c) if c == 0 => {
				self.connected = false;
				return Err(ErrorKind::Generic("Connection closed".into()));
			}
			Ok(_) => {}
		}

		Ok(line)
	}

	pub fn write_line(&mut self, mut line: String) -> Result<(), ErrorKind> {
		line.push_str("\n");
		let bytes = line.into_bytes();
		match self.inner.write(&bytes) {
			Err(e) => {
				self.connected = false;
				Err(e.into())
			}
			Ok(c) if c == 0 => {
				self.connected = false;
				Err(ErrorKind::Generic("Connection closed".into()))
			}
			Ok(_) => Ok(()),
		}
	}
}

pub struct RpcClient {
	inner: LineStream,
}

impl RpcClient {
	pub fn new(address: String) -> Result<Self, ErrorKind> {
		let inner = LineStream::new(address).map_err(|_| ErrorKind::Rpc("Unable to connect"))?;
		Ok(Self { inner })
	}

	pub fn is_connected(&self) -> bool {
		self.inner.is_connected()
	}

	pub fn read(&mut self) -> Result<RpcResponse, ErrorKind> {
		let line = self
			.inner
			.read_line()
			.map_err(|_| ErrorKind::Rpc("Unable to read line"))?;
		let result: RpcResponse =
			serde_json::from_str(&line).map_err(|_| ErrorKind::Rpc("Unable to deserialize"))?;
		Ok(result)
	}

	pub fn write(&mut self, request: &RpcRequest) -> Result<(), ErrorKind> {
		let line =
			serde_json::to_string(request).map_err(|_| ErrorKind::Rpc("Unable to serialize"))?;
		self.inner
			.write_line(line)
			.map_err(|_| ErrorKind::Rpc("Unable to write line"))?;
		Ok(())
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcRequest {
	pub id: String,
	jsonrpc: String,
	method: String,
	params: Option<Value>,
}

impl RpcRequest {
	pub fn new<T: Serialize>(id: u32, method: &str, params: T) -> Result<Self, ErrorKind> {
		Ok(Self {
			id: format!("{}", id),
			jsonrpc: "2.0".into(),
			method: method.into(),
			params: Some(serde_json::to_value(params)?),
		})
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum RpcResponse {
	ResponseErr(RpcResponseErr),
	ResponseOk(RpcResponseOk),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponseOk {
	pub id: Option<String>,
	pub result: Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponseErr {
	pub id: Option<String>,
	pub error: Value,
}

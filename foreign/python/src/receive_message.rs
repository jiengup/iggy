// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use iggy::prelude::{
    HeaderKind, HeaderValue, IggyMessage as RustReceiveMessage,
    PollingStrategy as RustPollingStrategy,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pyclass_complex_enum, gen_stub_pymethods};

/// A Python class representing a received message.
/// This class wraps a Rust message, allowing for access to its payload and offset from Python.
#[pyclass]
#[gen_stub_pyclass]
pub struct ReceiveMessage {
    pub(crate) inner: RustReceiveMessage,
    pub(crate) partition_id: u32,
}

#[gen_stub_pymethods]
#[pymethods]
impl ReceiveMessage {
    /// Retrieves the payload of the received message.
    /// The payload is returned as a Python bytes object.
    pub fn payload<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        PyBytes::new(py, &self.inner.payload)
    }

    /// Retrieves the offset of the received message.
    /// The offset represents the position of the message within its topic.
    pub fn offset(&self) -> u64 {
        self.inner.header.offset
    }

    /// Retrieves the timestamp of the received message.
    /// The timestamp represents the time of the message within its topic.
    pub fn timestamp(&self) -> u64 {
        self.inner.header.timestamp
    }

    /// Retrieves the origin timestamp of the received message.
    /// The origin timestamp represents when the message was originally created.
    pub fn origin_timestamp(&self) -> u64 {
        self.inner.header.origin_timestamp
    }

    /// Retrieves the id of the received message.
    /// The id represents unique identifier of the message within its topic.
    pub fn id(&self) -> u128 {
        self.inner.header.id
    }

    /// Retrieves the checksum of the received message.
    /// The checksum represents the integrity of the message within its topic.
    pub fn checksum(&self) -> u64 {
        self.inner.header.checksum
    }

    /// Retrieves the length of the received message.
    /// The length represents the length of the payload.
    pub fn length(&self) -> u32 {
        self.inner.header.payload_length
    }

    /// Retrieves the partition this message belongs to.
    pub fn partition_id(&self) -> u32 {
        self.partition_id
    }

    /// Retrieves user headers attached to the received message.
    #[gen_stub(override_return_type(
        type_repr = "dict[str, str | bytes | bool | int | float] | None"
    ))]
    pub fn user_headers<'a>(&self, py: Python<'a>) -> PyResult<Option<Bound<'a, PyDict>>> {
        let Some(headers) = self
            .inner
            .user_headers_map()
            .map_err(|e| PyValueError::new_err(e.to_string()))?
        else {
            return Ok(None);
        };

        let result = PyDict::new(py);
        for (key, value) in headers {
            if key.kind() != HeaderKind::String {
                return Err(PyValueError::new_err(
                    "User header keys must be strings in the Python SDK",
                ));
            }
            let key = key
                .as_str()
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let value = rust_header_value_to_py(py, &value)?;
            result.set_item(key, value)?;
        }
        Ok(Some(result))
    }
}

fn rust_header_value_to_py<'a>(py: Python<'a>, value: &HeaderValue) -> PyResult<Bound<'a, PyAny>> {
    match value.kind() {
        HeaderKind::Raw => Ok(PyBytes::new(py, value.as_raw().map_err(to_value_error)?).into_any()),
        HeaderKind::String => Ok(value
            .as_str()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Bool => Ok(value
            .as_bool()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .to_owned()
            .into_any()),
        HeaderKind::Int8 => Ok(value
            .as_int8()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Int16 => Ok(value
            .as_int16()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Int32 => Ok(value
            .as_int32()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Int64 => Ok(value
            .as_int64()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Int128 => Ok(value
            .as_int128()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Uint8 => Ok(value
            .as_uint8()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Uint16 => Ok(value
            .as_uint16()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Uint32 => Ok(value
            .as_uint32()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Uint64 => Ok(value
            .as_uint64()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Uint128 => Ok(value
            .as_uint128()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Float32 => Ok(value
            .as_float32()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
        HeaderKind::Float64 => Ok(value
            .as_float64()
            .map_err(to_value_error)?
            .into_pyobject(py)?
            .into_any()),
    }
}

fn to_value_error(error: impl ToString) -> PyErr {
    PyValueError::new_err(error.to_string())
}

#[derive(Clone, Copy)]
#[gen_stub_pyclass_complex_enum]
#[pyclass(from_py_object)]
pub enum PollingStrategy {
    Offset { value: u64 },
    Timestamp { value: u64 },
    First {},
    Last {},
    Next {},
}

impl From<&PollingStrategy> for RustPollingStrategy {
    fn from(value: &PollingStrategy) -> Self {
        match value {
            PollingStrategy::Offset { value } => RustPollingStrategy::offset(value.to_owned()),
            PollingStrategy::Timestamp { value } => {
                RustPollingStrategy::timestamp(value.to_owned().into())
            }
            PollingStrategy::First {} => RustPollingStrategy::first(),
            PollingStrategy::Last {} => RustPollingStrategy::last(),
            PollingStrategy::Next {} => RustPollingStrategy::next(),
        }
    }
}

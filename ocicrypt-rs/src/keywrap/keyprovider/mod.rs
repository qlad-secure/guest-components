// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::{self, Debug};

use crate::config::{DecryptConfig, EncryptConfig, KeyProviderAttrs};
use crate::keywrap::KeyWrapper;
use crate::utils::{self, CommandExecuter};
use anyhow::{anyhow, bail, Result};
use base64::Engine;

pub mod mlkem;
pub use mlkem::get_mlkem_wrapper;

#[derive(Debug)]
enum OpKey {
    Wrap,
    Unwrap,
}

impl fmt::Display for OpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            OpKey::Wrap => write!(f, "keywrap"),
            OpKey::Unwrap => write!(f, "keyunwrap"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyWrapParams {
    ec: Option<EncryptConfig>,
    #[serde(rename = "optsdata")]
    opts_data: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyUnwrapParams {
    dc: Option<DecryptConfig>,
    annotation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyUnwrapResults {
    #[serde(rename = "optsdata")]
    opts_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyWrapResults {
    annotation: Vec<u8>,
}

/// KeyProviderKeyWrapProtocolInput defines the input to the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyProviderKeyWrapProtocolInput {
    /// op is either "keywrap" or "keyunwrap"
    op: String,
    /// keywrapparams encodes the arguments to key wrap if operation is set to wrap
    #[serde(rename = "keywrapparams")]
    key_wrap_params: KeyWrapParams,
    /// keyunwrapparams encodes the arguments to key unwrap if operation is set to unwrap
    #[serde(rename = "keyunwrapparams")]
    key_unwrap_params: KeyUnwrapParams,
}

/// KeyProviderKeyWrapProtocolOutput defines the output of the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Debug, Default)]
struct KeyProviderKeyWrapProtocolOutput {
    /// keywrapresults encodes the results to key wrap if operation is to keywrap
    #[serde(rename = "keywrapresults", skip_serializing_if = "Option::is_none")]
    key_wrap_results: Option<KeyWrapResults>,
    /// keyunwrapresults encodes the result to key unwrap if operation is to keyunwrap
    #[serde(rename = "keyunwrapresults", skip_serializing_if = "Option::is_none")]
    key_unwrap_results: Option<KeyUnwrapResults>,
}

impl KeyProviderKeyWrapProtocolOutput {
    #[cfg(feature = "keywrap-keyprovider-grpc")]
    async fn from_grpc(input: Vec<u8>, conn: &str, operation: OpKey) -> Result<Self> {
        let uri = conn.parse::<tonic::codegen::http::Uri>().unwrap();
        // create a channel ie connection to server
        let channel = tonic::transport::Channel::builder(uri)
            .connect()
            .await
            .map_err(|e| anyhow!("keyprovider: error while creating channel: {e:?}"))?;

        let mut client =
            crate::utils::grpc::keyprovider::key_provider_service_client::KeyProviderServiceClient::new(
                channel,
            );
        let msg = crate::utils::grpc::keyprovider::KeyProviderKeyWrapProtocolInput {
            key_provider_key_wrap_protocol_input: input,
        };
        let request = tonic::Request::new(msg);
        let grpc_output = match operation {
            OpKey::Wrap => client.wrap_key(request).await.map_err(|e| {
                anyhow!(
                    "keyprovider: error from grpc server for {} operation, {}",
                    OpKey::Wrap,
                    e
                )
            })?,

            OpKey::Unwrap => client.un_wrap_key(request).await.map_err(|e| {
                anyhow!(
                    "keyprovider: error from grpc server for {} operation, {}",
                    OpKey::Unwrap,
                    e
                )
            })?,
        };

        serde_json::from_slice(
            &grpc_output
                .into_inner()
                .key_provider_key_wrap_protocol_output,
        )
        .map_err(|_| {
            anyhow!(
                "Error while deserializing grpc output on {} operation",
                OpKey::Unwrap
            )
        })
    }

    #[cfg(feature = "keywrap-keyprovider-ttrpc")]
    fn from_ttrpc(input: Vec<u8>, conn: &str, operation: OpKey) -> Result<Self> {
        let c = ttrpc::Client::connect(conn)?;

        let kc = crate::utils::ttrpc::keyprovider_ttrpc::KeyProviderServiceClient::new(c);
        let kc1 = kc.clone();
        let mut req = crate::utils::ttrpc::keyprovider::KeyProviderKeyWrapProtocolInput::new();
        req.KeyProviderKeyWrapProtocolInput = input;

        let ttrpc_output = match operation {
            OpKey::Wrap => kc1
                .wrap_key(ttrpc::context::with_timeout(50 * 1000 * 1000 * 1000), &req)
                .map_err(|_| {
                    anyhow!(
                        "keyprovider: Error from ttrpc server for {:?} operation",
                        OpKey::Wrap.to_string()
                    )
                })?,

            OpKey::Unwrap => kc1
                .un_wrap_key(ttrpc::context::with_timeout(50 * 1000 * 1000 * 1000), &req)
                .map_err(|e| {
                    anyhow!(
                        "keyprovider: Error from ttrpc server for {:?} operation: {e:?}",
                        OpKey::Unwrap.to_string()
                    )
                })?,
        };

        serde_json::from_slice(&ttrpc_output.KeyProviderKeyWrapProtocolOutput).map_err(|_| {
            anyhow!(
                "Error while deserializing ttrpc output on {:?} operation",
                OpKey::Unwrap.to_string()
            )
        })
    }

    #[cfg(feature = "keywrap-keyprovider-cmd")]
    fn from_command(
        input: Vec<u8>,
        command: &crate::config::Command,
        runner: &dyn crate::utils::CommandExecuter,
    ) -> Result<Self> {
        let cmd_name = command.path.to_string();
        let default_args = vec![];
        let args = command.args.as_ref().unwrap_or(&default_args);
        let resp_bytes: Vec<u8> = runner
            .exec(cmd_name, args, input)
            .map_err(|e| anyhow!("keyprovider: error from command executor: {}", e))?;

        serde_json::from_slice(&resp_bytes)
            .map_err(|_| anyhow!("keyprovider: failed to deserialize message from binary executor"))
    }

    #[cfg(feature = "keywrap-keyprovider-native")]
    fn from_native(annotation: &str, dc_config: &DecryptConfig) -> Result<Self> {
        let kbc_kbs_pair = if let Some(list) = dc_config.param.get("attestation-agent") {
            list.first()
                .ok_or_else(|| anyhow!("keyprovider: empty kbc::kbs pair"))?
        } else {
            return Err(anyhow!("keyprovider: not supported attestation agent"));
        };
        let pair_str = String::from_utf8(kbc_kbs_pair.to_vec())?;
        let (kbc, kbs) = pair_str
            .split_once("::")
            .ok_or_else(|| anyhow!("keyprovider: invalid kbc::kbs pair"))?;
        let kbs = kbs.to_string();
        let kbc = kbc.to_string();
        let annotation = annotation.to_string();

        let handler = std::thread::spawn(move || {
            create_async_runtime()?.block_on(async {
                native::decrypt_image_layer_annotation(&kbs, &kbc, &annotation)
                    .await
                    .map_err(|e| format!("{e:?}"))
            })
        });

        match handler.join() {
            Ok(Ok(v)) => Ok(KeyProviderKeyWrapProtocolOutput {
                key_unwrap_results: Some(KeyUnwrapResults { opts_data: v }),
                ..Default::default()
            }),
            Ok(Err(e)) => Err(anyhow!("keyprovider: retrieve opts_data failed: {e:?}")),
            Err(e) => Err(anyhow!("keyprovider: retrieve opts_data failed: {e:?}")),
        }
    }
}

/// A KeyProvider keywrapper
#[derive(Debug)]
pub struct KeyProviderKeyWrapper {
    pub provider: String,
    pub attrs: KeyProviderAttrs,
    pub runner: Option<Box<dyn CommandExecuter>>,
}

impl KeyProviderKeyWrapper {
    /// Create a new instance of `KeyProviderKeyWrapper`.
    pub fn new(
        provider: String,
        mut attrs: KeyProviderAttrs,
        runner: Option<Box<dyn utils::CommandExecuter>>,
    ) -> Self {
        if let Some(grpc) = &attrs.grpc {
            if !grpc.starts_with("http://") && !grpc.starts_with("tcp://") {
                attrs.grpc = Some(format!("http://{grpc}"));
            }
        }

        KeyProviderKeyWrapper {
            provider,
            attrs,
            runner,
        }
    }

    fn wrap_key_cmd(&self, _input: Vec<u8>, _cmd: &crate::config::Command) -> Result<Vec<u8>> {
        if let Some(_runner) = self.runner.as_ref() {
            #[cfg(not(feature = "keywrap-keyprovider-cmd"))]
            {
                Err(anyhow!("keyprovider: no support of keyprovider-grpc"))
            }
            #[cfg(feature = "keywrap-keyprovider-cmd")]
            {
                let protocol_output = KeyProviderKeyWrapProtocolOutput::from_command(
                    _input, _cmd, _runner,
                )
                .map_err(|e| {
                    anyhow!(
                        "keyprovider: error from binary provider for {} operation: {e:?}",
                        OpKey::Wrap,
                    )
                })?;
                if let Some(result) = protocol_output.key_wrap_results {
                    Ok(result.annotation)
                } else {
                    Err(anyhow!("keyprovider: get NULL reply from provider"))
                }
            }
        } else {
            Err(anyhow!("keyprovider: runner for binary provider is NULL"))
        }
    }

    fn wrap_key_grpc(&self, _input: Vec<u8>, grpc: &str) -> Result<Vec<u8>> {
        #[cfg(not(feature = "keywrap-keyprovider-grpc"))]
        {
            Err(anyhow!(
                "keyprovider: no support of keyprovider-grpc, {}",
                grpc
            ))
        }
        #[cfg(feature = "keywrap-keyprovider-grpc")]
        {
            let grpc = grpc.to_string();
            let handler = std::thread::spawn(move || {
                create_async_runtime()?.block_on(async {
                    KeyProviderKeyWrapProtocolOutput::from_grpc(_input, &grpc, OpKey::Wrap)
                        .await
                        .map_err(|e| format!("{e:?}"))
                })
            });
            let protocol_output = match handler.join() {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    return Err(anyhow!(
                        "keyprovider: grpc provider failed to execute {} operation: {}",
                        OpKey::Wrap,
                        e
                    ));
                }
                Err(e) => {
                    return Err(anyhow!(
                        "keyprovider: grpc provider failed to execute {} operation: {e:?}",
                        OpKey::Wrap,
                    ));
                }
            };
            if let Some(result) = protocol_output.key_wrap_results {
                Ok(result.annotation)
            } else {
                Err(anyhow!("keyprovider: get NULL reply from provider"))
            }
        }
    }

    fn wrap_key_ttrpc(&self, _input: Vec<u8>, ttrpc: &str) -> Result<Vec<u8>> {
        #[cfg(not(feature = "keywrap-keyprovider-ttrpc"))]
        {
            Err(anyhow!(
                "keyprovider: no support of keyprovider-ttrpc, {}",
                ttrpc
            ))
        }
        #[cfg(feature = "keywrap-keyprovider-ttrpc")]
        {
            use anyhow::Context;

            let ttrpc = ttrpc.to_string();
            let protocol_output =
                KeyProviderKeyWrapProtocolOutput::from_ttrpc(_input, &ttrpc, OpKey::Wrap)
                    .context("keyprovider: ttrpc provider failed to execute Wrap")?;
            if let Some(result) = protocol_output.key_wrap_results {
                Ok(result.annotation)
            } else {
                Err(anyhow!("keyprovider: get NULL reply from provider"))
            }
        }
    }

    fn unwrap_key_cmd(
        &self,
        _input: Vec<u8>,
        _cmd: &crate::config::Command,
    ) -> Result<KeyProviderKeyWrapProtocolOutput> {
        if let Some(_runner) = self.runner.as_ref() {
            #[cfg(not(feature = "keywrap-keyprovider-cmd"))]
            return Err(anyhow!("keyprovider: no support of keyprovider-grpc"));
            #[cfg(feature = "keywrap-keyprovider-cmd")]
            {
                KeyProviderKeyWrapProtocolOutput::from_command(_input, _cmd, _runner).map_err(|e| {
                    anyhow!(
                        "keyprovider: error from binary provider for {} operation: {e:?}",
                        OpKey::Unwrap,
                    )
                })
            }
        } else {
            bail!("keyprovider: runner for binary provider is NULL");
        }
    }

    fn unwrap_key_grpc(
        &self,
        _input: Vec<u8>,
        grpc: &str,
    ) -> Result<KeyProviderKeyWrapProtocolOutput> {
        #[cfg(not(feature = "keywrap-keyprovider-grpc"))]
        return Err(anyhow!(
            "keyprovider: no support of keyprovider-grpc, {}",
            grpc
        ));
        #[cfg(feature = "keywrap-keyprovider-grpc")]
        {
            let grpc = grpc.to_string();
            let handler = std::thread::spawn(move || {
                create_async_runtime()?.block_on(async {
                    KeyProviderKeyWrapProtocolOutput::from_grpc(_input, &grpc, OpKey::Unwrap)
                        .await
                        .map_err(|e| {
                            format!(
                                "keyprovider: grpc provider failed to execute {} operation: {e:?}",
                                OpKey::Wrap,
                            )
                        })
                })
            });
            match handler.join() {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => bail!("failed to unwrap key by gRPC, {e:?}"),
                Err(e) => bail!("failed to unwrap key by gRPC, {e:?}"),
            }
        }
    }

    fn unwrap_key_ttrpc(
        &self,
        _input: Vec<u8>,
        ttrpc: &str,
    ) -> Result<KeyProviderKeyWrapProtocolOutput> {
        #[cfg(not(feature = "keywrap-keyprovider-ttrpc"))]
        return Err(anyhow!(
            "keyprovider: no support of keyprovider-ttrpc, {}",
            ttrpc
        ));
        #[cfg(feature = "keywrap-keyprovider-ttrpc")]
        {
            use anyhow::Context;
            let ttrpc = ttrpc.to_string();

            KeyProviderKeyWrapProtocolOutput::from_ttrpc(_input, &ttrpc, OpKey::Unwrap)
                .context("keyprovider: failed to unwrap key by ttrpc")
        }
    }

    fn unwrap_key_native(
        &self,
        _dc_config: &DecryptConfig,
        _json_string: &[u8],
    ) -> Result<KeyProviderKeyWrapProtocolOutput> {
        #[cfg(not(feature = "keywrap-keyprovider-native"))]
        return Err(anyhow!("keyprovider: no support of keyprovider-native"));
        #[cfg(feature = "keywrap-keyprovider-native")]
        {
            let content = String::from_utf8(_json_string.to_vec())?;
            KeyProviderKeyWrapProtocolOutput::from_native(&content, _dc_config).map_err(|e| {
                anyhow!(
                    "keyprovider: error from crate provider for {} operation: {e:?}",
                    OpKey::Unwrap,
                )
            })
        }
    }
}

impl KeyWrapper for KeyProviderKeyWrapper {
    /// WrapKeys calls appropriate binary-executable or grpc/ttrpc server for wrapping the session
    /// key for recipients and gets encrypted optsData, which describe the symmetric key used for
    /// encrypting the layer.
    fn wrap_keys(&self, enc_config: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        if !enc_config.param.contains_key(&self.provider) {
            return Err(anyhow!(
                "keyprovider: unknown provider {} for operation {}",
                &self.provider,
                OpKey::Wrap
            ));
        }

        let opts_data_str = String::from_utf8(opts_data.to_vec())
            .map_err(|_| anyhow!("keyprovider: can not convert option data to string"))?;
        let key_wrap_params = KeyWrapParams {
            ec: Some(enc_config.clone()),
            opts_data: Some(opts_data_str),
        };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OpKey::Wrap.to_string(),
            key_wrap_params,
            key_unwrap_params: KeyUnwrapParams::default(),
        };
        let _serialized_input = serde_json::to_vec(&input).map_err(|_| {
            anyhow!(
                "keyprovider: error while serializing input parameters for {} operation",
                OpKey::Wrap
            )
        })?;

        if let Some(_cmd) = &self.attrs.cmd {
            self.wrap_key_cmd(_serialized_input, _cmd)
        } else if let Some(grpc) = self.attrs.grpc.as_ref() {
            self.wrap_key_grpc(_serialized_input, grpc)
        } else if let Some(ttrpc) = self.attrs.ttrpc.as_ref() {
            self.wrap_key_ttrpc(_serialized_input, ttrpc)
        } else {
            Err(anyhow!(
                "keyprovider: invalid configuration, both grpc and runner are NULL"
            ))
        }
    }

    /// UnwrapKey calls appropriate binary-executable or grpc/ttrpc server for unwrapping the
    /// session key based on the protocol given in annotation for recipients and gets decrypted
    /// optsData, which describe the symmetric key used for decrypting the layer
    fn unwrap_keys(&self, dc_config: &DecryptConfig, json_string: &[u8]) -> Result<Vec<u8>> {
        let annotation_str = String::from_utf8(json_string.to_vec())
            .map_err(|_| anyhow!("keyprovider: can not convert json data to string"))?;
        let key_unwrap_params = KeyUnwrapParams {
            dc: Some(dc_config.clone()),
            annotation: Some(base64::engine::general_purpose::STANDARD.encode(annotation_str)),
        };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OpKey::Unwrap.to_string(),
            key_wrap_params: KeyWrapParams::default(),
            key_unwrap_params,
        };
        let _serialized_input = serde_json::to_vec(&input).map_err(|_| {
            anyhow!(
                "keyprovider: error while serializing input parameters for {} operation",
                OpKey::Unwrap
            )
        })?;

        let _protocol_output = if let Some(cmd) = self.attrs.cmd.as_ref() {
            self.unwrap_key_cmd(_serialized_input, cmd)?
        } else if let Some(grpc) = self.attrs.grpc.as_ref() {
            self.unwrap_key_grpc(_serialized_input, grpc)?
        } else if let Some(ttrpc) = self.attrs.ttrpc.as_ref() {
            self.unwrap_key_ttrpc(_serialized_input, ttrpc)?
        } else if let Some(_native) = self.attrs.native.as_ref() {
            self.unwrap_key_native(dc_config, json_string)?
        } else {
            return Err(anyhow!(
                "keyprovider: invalid configuration, both grpc and runner are NULL"
            ));
        };

        if let Some(result) = _protocol_output.key_unwrap_results {
            Ok(result.opts_data)
        } else {
            Err(anyhow!("keyprovider: get NULL reply from provider"))
        }
    }

    fn annotation_id(&self) -> String {
        format!(
            "org.opencontainers.image.enc.keys.provider.{}",
            self.provider
        )
    }

    fn probe(&self, _dc_param: &HashMap<String, Vec<Vec<u8>>>) -> bool {
        true
    }
}

#[cfg(any(
    feature = "keywrap-keyprovider-grpc",
    feature = "keywrap-keyprovider-native"
))]
fn create_async_runtime() -> std::result::Result<tokio::runtime::Runtime, String> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Err(e) => Err(format!(
            "keyprovider: failed to create async runtime, {e:?}"
        )),
        Ok(rt) => Ok(rt),
    }
}

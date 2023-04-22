//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use holo_northbound as northbound;
use holo_northbound::configuration::{CommitPhase, ConfigChange};
use holo_northbound::state::NodeAttributes;
use holo_northbound::{
    api as papi, CallbackKey, CallbackOp, NbDaemonSender, NbProviderReceiver,
};
use holo_utils::task::TimeoutTask;
use holo_utils::{Receiver, Sender, UnboundedReceiver};
use holo_yang::YANG_CTX;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, error, info, instrument, trace, warn};
use yang2::data::{
    Data, DataDiffFlags, DataFormat, DataPrinterFlags, DataTree,
    DataValidationFlags,
};
use yang2::schema::SchemaPathFormat;

use crate::config::Config;
use crate::northbound::client::{api as capi, gnmi, grpc};
use crate::northbound::{yang, Error, Result};

#[derive(Debug)]
pub struct Northbound {
    // YANG-modeled running configuration.
    running_config: Arc<DataTree>,
    // Callback keys from the data providers.
    callbacks: BTreeMap<CallbackKey, NbDaemonSender>,
    // List of data providers.
    providers: Vec<NbDaemonSender>,
    // Channel used to receive messages from the external clients.
    rx_clients: Receiver<capi::client::Request>,
    // Channel used to receive messages from the data providers.
    rx_providers: UnboundedReceiver<papi::provider::Notification>,
    // ID of the next configuration transaction.
    next_transaction_id: u32,
    // Confirmed commit information.
    confirmed_commit: ConfirmedCommit,
}

#[derive(Debug)]
pub struct ConfirmedCommit {
    // Channels used to send and receive timeout notifications.
    tx: Sender<()>,
    rx: Receiver<()>,
    // Rollback configuration.
    rollback_config: Option<DataTree>,
    // Confirmed commit timeout.
    timeout: Option<TimeoutTask>,
}

// ===== impl Northbound =====

impl Northbound {
    pub(crate) async fn init(config: &Config) -> Northbound {
        // Create global YANG context.
        yang::create_context(config);
        let yang_ctx = YANG_CTX.get().unwrap();

        // Create empty running configuration.
        let running_config = Arc::new(DataTree::new(yang_ctx));

        // Start client tasks (e.g. gRPC, gNMI).
        let rx_clients = start_clients(config);

        // Start provider tasks (e.g. interfaces, routing, etc).
        let (rx_providers, providers) = start_providers(config);

        // Load callbacks keys from data providers and check for missing
        // callbacks.
        let callbacks = load_callbacks(&providers).await;
        validate_callbacks(&callbacks);

        Northbound {
            running_config,
            callbacks,
            providers,
            rx_clients,
            rx_providers,
            next_transaction_id: 1,
            confirmed_commit: Default::default(),
        }
    }

    // Main event loop.
    #[instrument(skip_all, "northbound")]
    pub(crate) async fn run(mut self: Northbound) {
        loop {
            tokio::select! {
                Some(request) = self.rx_clients.recv() => {
                    self.process_client_msg(request).await;
                }
                Some(request) = self.rx_providers.recv() => {
                    self.process_provider_msg(request);
                }
                Some(_) = self.confirmed_commit.rx.recv() => {
                    self.process_confirmed_commit_timeout().await;
                }
                else => break,
            }
        }
    }

    // Processes a message received from an external client.
    async fn process_client_msg(&mut self, request: capi::client::Request) {
        debug!(%request, "received client request");
        trace!(?request, "received client request");

        match request {
            capi::client::Request::Get(request) => {
                let response = self
                    .process_client_get(request.data_type, request.path)
                    .await;
                let _ = request.responder.send(response);
            }
            capi::client::Request::Commit(request) => {
                let response = self
                    .process_client_commit(
                        request.operation,
                        request.config,
                        request.confirmed_timeout,
                    )
                    .await;
                if let Err(error) = &response {
                    warn!(%error, "commit failed");
                }
                let _ = request.responder.send(response);
            }
            capi::client::Request::Execute(request) => {
                let response = self.process_client_execute(request.data).await;
                if let Err(error) = &response {
                    warn!(%error, "execute failed");
                }
                let _ = request.responder.send(response);
            }
        }
    }

    // Processes a `Get` message received from an external client.
    async fn process_client_get(
        &self,
        data_type: capi::DataType,
        path: Option<String>,
    ) -> Result<capi::client::GetResponse> {
        let path = path.as_deref();
        let dtree = match data_type {
            capi::DataType::State => self.get_state(path).await?,
            capi::DataType::Configuration => self.get_configuration(path)?,
            capi::DataType::All => {
                let mut dtree_state = self.get_state(path).await?;
                let dtree_config = self.get_configuration(path)?;
                dtree_state
                    .merge(&dtree_config)
                    .map_err(Error::YangInternal)?;
                dtree_state
            }
        };

        Ok(capi::client::GetResponse { dtree })
    }

    // Processes a `Commit` message received from an external client.
    async fn process_client_commit(
        &mut self,
        operation: capi::CommitOperation,
        config: DataTree,
        confirmed_timeout: u32,
    ) -> Result<capi::client::CommitResponse> {
        // Handle different commit operations.
        let candidate = match operation {
            capi::CommitOperation::Merge => {
                let mut candidate = self
                    .running_config
                    .duplicate()
                    .map_err(Error::YangInternal)?;
                candidate.merge(&config).map_err(Error::YangInternal)?;
                candidate
            }
            capi::CommitOperation::Replace => config,
            capi::CommitOperation::Change => unimplemented!(),
        };

        // Create configuration transaction.
        let transaction_id = self
            .create_transaction(candidate, confirmed_timeout)
            .await?;
        Ok(capi::client::CommitResponse { transaction_id })
    }

    // Processes an `Execute` message received from an external client.
    async fn process_client_execute(
        &mut self,
        data: DataTree,
    ) -> Result<capi::client::ExecuteResponse> {
        let data = self.execute(data).await?;
        Ok(capi::client::ExecuteResponse { data })
    }

    // Processes a message received from a data provider.
    fn process_provider_msg(&mut self, request: papi::provider::Notification) {
        trace!(?request, "received client request");
        // TODO: relay request to the external clients (e.g. YANG notification).
    }

    // Processes a confirmed commit timeout.
    async fn process_confirmed_commit_timeout(&mut self) {
        info!("confirmed commit has timed out, rolling back to previous configuration");

        let rollback_config =
            self.confirmed_commit.rollback_config.take().unwrap();
        if let Err(error) = self.create_transaction(rollback_config, 0).await {
            error!(%error, "failed to rollback to previous configuration");
        }

        self.confirmed_commit.stop();
    }

    // Creates a configuration transaction using a two-phase commit protocol. In
    // case of success, the transaction ID is returned.
    //
    // A configuration transaction might fail if the candidate configuration
    // fails to be validated, or if one or more resources fail to be allocated.
    async fn create_transaction(
        &mut self,
        candidate: DataTree,
        confirmed_timeout: u32,
    ) -> Result<u32> {
        let candidate = Arc::new(candidate);

        // Compute diff between the running config and the candidate config.
        let diff = self
            .running_config
            .diff(&candidate, DataDiffFlags::DEFAULTS)
            .map_err(Error::YangInternal)?;

        // Check if the configuration has changed.
        if diff.iter().next().is_none() {
            // Check if this a confirmation commit.
            if self.confirmed_commit.timeout.is_some() {
                debug!("commit confirmation accepted");
                self.confirmed_commit.stop();
            }

            return Ok(self.next_transaction_id);
        }

        // Start confirmed commit timeout if necessary.
        if confirmed_timeout > 0 {
            let rollback_config = (*self.running_config).duplicate().unwrap();
            self.confirmed_commit
                .start(rollback_config, confirmed_timeout);
        }

        // Get transaction ID.
        let id = self.next_transaction_id;
        self.next_transaction_id += 1;

        // Get list of configuration changes.
        let changes = northbound::configuration::changes_from_diff(&diff);
        debug!(%id, "new transaction");
        trace!(
            "configuration changes: {}",
            diff.print_string(
                DataFormat::JSON,
                DataPrinterFlags::WITH_SIBLINGS
            )
            .unwrap()
            .unwrap_or_default()
        );

        // Phase 1: validate configuration and attempt to prepare resources for
        // the transaction.
        match self
            .commit_phase_notify(CommitPhase::Prepare, &candidate, &changes)
            .await
        {
            Ok(_) => {
                // Phase 2: apply the configuration changes.
                let _ = self
                    .commit_phase_notify(
                        CommitPhase::Apply,
                        &candidate,
                        &changes,
                    )
                    .await;

                // Update the running configuration.
                let running_config =
                    Arc::get_mut(&mut self.running_config).unwrap();
                running_config
                    .diff_apply(&diff)
                    .map_err(Error::YangInternal)?;
                running_config
                    .validate(DataValidationFlags::NO_STATE)
                    .map_err(Error::YangInternal)?;
                Ok(id)
            }
            Err(error) => {
                // Phase 2: abort the configuration changes.
                let _ = self
                    .commit_phase_notify(
                        CommitPhase::Abort,
                        &candidate,
                        &changes,
                    )
                    .await;
                Err(Error::TransactionPreparation(error))
            }
        }
    }

    // Notifies all data providers of the configuration changes associated to an
    // on-going transaction.
    async fn commit_phase_notify(
        &mut self,
        phase: CommitPhase,
        candidate: &Arc<DataTree>,
        changes: &[ConfigChange],
    ) -> std::result::Result<(), northbound::error::Error> {
        let mut handles = Vec::new();

        // Spawn one task per data provider.
        for daemon_tx in self.providers.iter() {
            // Batch all changes that should be sent to this provider.
            let changes = changes
                .iter()
                .filter(|(cb_key, _)| {
                    if let Some(tx) = self.callbacks.get(cb_key) {
                        tx.same_channel(daemon_tx)
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();

            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Commit(papi::daemon::CommitRequest {
                    phase,
                    old_config: self.running_config.clone(),
                    new_config: candidate.clone(),
                    changes,
                    responder: Some(responder_tx),
                });

            // Spawn task to send the request and receive the response.
            let daemon_tx = daemon_tx.clone();
            let handle = tokio::spawn(async move {
                daemon_tx.send(request).await.unwrap();
                responder_rx.await.unwrap()
            });
            handles.push(handle);
        }
        // Wait for all tasks to complete.
        for handle in handles {
            handle.await.unwrap()?;
        }

        Ok(())
    }

    // Gets a full or partial copy of the running configuration.
    fn get_configuration(&self, path: Option<&str>) -> Result<DataTree> {
        match path {
            Some(path) => self
                .running_config
                .find_path(path)
                .map_err(Error::YangInvalidPath)?
                .duplicate(true)
                .map_err(Error::YangInternal),
            None => {
                self.running_config.duplicate().map_err(Error::YangInternal)
            }
        }
    }

    // Gets dynamically generated operational data for the provided path. The
    // request might span multiple data providers.
    async fn get_state(&self, path: Option<&str>) -> Result<DataTree> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let mut dtree = DataTree::new(yang_ctx);

        for daemon_tx in self.providers.iter() {
            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Get(papi::daemon::GetRequest {
                    path: path.map(String::from),
                    attr_filter: Some(NodeAttributes::DEV),
                    responder: Some(responder_tx),
                });
            daemon_tx.send(request).await.unwrap();

            // Receive response.
            let response = responder_rx.await.unwrap().unwrap();

            // Combine all responses into a single data tree.
            dtree.merge(&response.data).map_err(Error::YangInternal)?;
        }

        Ok(dtree)
    }

    // Invoke a YANG RPC or Action.
    async fn execute(&self, data: DataTree) -> Result<DataTree> {
        let yang_ctx = YANG_CTX.get().unwrap();
        let mut dtree = DataTree::new(yang_ctx);

        for daemon_tx in self.providers.iter() {
            // Prepare request.
            let (responder_tx, responder_rx) = oneshot::channel();
            let request =
                papi::daemon::Request::Rpc(papi::daemon::RpcRequest {
                    data: data.duplicate().map_err(Error::YangInternal)?,
                    responder: Some(responder_tx),
                });
            daemon_tx.send(request).await.unwrap();

            // Receive response.
            let response = responder_rx.await.unwrap().unwrap();

            // Combine all responses into a single data tree.
            dtree.merge(&response.data).map_err(Error::YangInternal)?;
        }

        Ok(dtree)
    }
}

// ===== impl ConfirmedCommit =====

impl ConfirmedCommit {
    fn start(&mut self, rollback_config: DataTree, timeout: u32) {
        debug!(%timeout, "starting confirmed commit timeout");

        let timeout = self.timeout_task(timeout);

        self.rollback_config = Some(rollback_config);
        self.timeout = Some(timeout);
    }

    fn stop(&mut self) {
        self.rollback_config = None;
        self.timeout = None;
    }

    fn timeout_task(&self, timeout: u32) -> TimeoutTask {
        let tx = self.tx.clone();
        let timeout = Duration::from_secs(timeout as u64 * 60);
        TimeoutTask::new(timeout, move || async move {
            let _ = tx.send(()).await;
        })
    }
}

impl Default for ConfirmedCommit {
    fn default() -> ConfirmedCommit {
        let (tx, rx) = mpsc::channel(4);

        ConfirmedCommit {
            tx,
            rx,
            rollback_config: None,
            timeout: None,
        }
    }
}

// ===== helper functions =====

// Starts base data providers.
fn start_providers(
    config: &Config,
) -> (NbProviderReceiver, Vec<NbDaemonSender>) {
    let mut providers = Vec::new();
    let (provider_tx, provider_rx) = mpsc::unbounded_channel();
    let (ibus_tx, ibus_rx) = broadcast::channel(16);

    // Start holo-routing.
    let daemon_tx = holo_routing::start(
        provider_tx.clone(),
        ibus_tx.clone(),
        ibus_tx.subscribe(),
        config.event_recorder.clone(),
    );
    providers.push(daemon_tx);

    // Start holo-interface.
    let daemon_tx = holo_interface::start(
        provider_tx.clone(),
        ibus_tx.clone(),
        ibus_tx.subscribe(),
    );
    providers.push(daemon_tx);

    // Start holo-keychain.
    let daemon_tx = holo_keychain::start(provider_tx, ibus_tx, ibus_rx);
    providers.push(daemon_tx);

    (provider_rx, providers)
}

// Starts external clients.
fn start_clients(config: &Config) -> Receiver<capi::client::Request> {
    let (client_tx, daemon_rx) = mpsc::channel(4);

    // Spawn gRPC task.
    let grpc_config = &config.plugins.grpc;
    if grpc_config.enabled {
        grpc::start(grpc_config, client_tx.clone());
    }

    // Spawn gNMI task.
    let gnmi_config = &config.plugins.gnmi;
    if gnmi_config.enabled {
        gnmi::start(gnmi_config, client_tx);
    }

    daemon_rx
}

// Loads all YANG callback keys from the data providers.
async fn load_callbacks(
    providers: &[NbDaemonSender],
) -> BTreeMap<CallbackKey, NbDaemonSender> {
    let mut callbacks = BTreeMap::new();

    for provider_tx in providers.iter() {
        // Prepare request.
        let (responder_tx, responder_rx) = oneshot::channel();
        let request = papi::daemon::Request::GetCallbacks(
            papi::daemon::GetCallbacksRequest {
                responder: Some(responder_tx),
            },
        );
        provider_tx.send(request).await.unwrap();

        // Receive response.
        let provider_response = responder_rx.await.unwrap();

        // Validate and store callback key.
        for cb_key in provider_response.callbacks {
            validate_callback(&cb_key);
            callbacks.insert(cb_key, provider_tx.clone());
        }
    }

    callbacks
}

// Checks for missing YANG callbacks.
fn validate_callbacks(callbacks: &BTreeMap<CallbackKey, NbDaemonSender>) {
    let yang_ctx = YANG_CTX.get().unwrap();
    let mut errors: usize = 0;

    for snode in yang_ctx
        .traverse()
        .filter(|snode| snode.module().name() != "ietf-yang-schema-mount")
        .filter(|snode| snode.is_status_current())
    {
        for operation in [
            CallbackOp::Create,
            CallbackOp::Modify,
            CallbackOp::Delete,
            CallbackOp::Lookup,
            CallbackOp::Rpc,
            CallbackOp::GetIterate,
            CallbackOp::GetElement,
        ] {
            if operation.is_valid(&snode) {
                let path = snode.path(SchemaPathFormat::DATA);
                let cb_key = CallbackKey::new(path, operation);
                if callbacks.get(&cb_key).is_none() {
                    error!(?operation, path = %cb_key.path, "missing callback");
                    errors += 1;
                }
            }
        }
    }

    if errors > 0 {
        error!(%errors, "failed to validate northbound callbacks");
        std::process::exit(1);
    }
}

// Checks whether the callback key is valid.
fn validate_callback(callback: &CallbackKey) {
    let yang_ctx = YANG_CTX.get().unwrap();

    if let Ok(snode) = yang_ctx.find_path(&callback.path) {
        if !callback.operation.is_valid(&snode) {
            error!(xpath = %callback.path, operation = ?callback.operation,
                "invalid callback",
            );
            std::process::exit(1);
        }
    }
}
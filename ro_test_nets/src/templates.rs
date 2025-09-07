use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct TcpRequestConnectArgs {
    pub tcb: Vec<u8>, 
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub new_state: u32,
    pub rexmit_count: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpAccpetListenerRouteLookupFailureArgs {
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub status: u32,
    pub process_id: u32,
    pub compartment: u32,
    pub tcb: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpAcceptListenerInsertionFailureArgs {
    pub tcb: Vec<u8>,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub new_state: u32,
    pub rexmit_count: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpConnectTcbSkipRateLimitArgs {
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub path: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpAutoTuningBeginArgs {
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub buffer_size: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ndkpi_ReadArgs {
    pub ndk_qp: Vec<u8>,
    pub request_context: Vec<u8>,
    pub sge_address: Vec<u8>,
    pub sge_length: u32,
    pub sge_memory_region_token: u32,
    pub num_sge: i32,
    pub flags: u32,
    pub sge_index: i32,
    pub remote_address: Vec<u8>,
    pub remote_token: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpConnectionRundownArgs {
    pub tcb: Vec<u8>,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub state: u32,
    pub pid: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpipAoacFailFastArgs {
    pub request_type: u32,
    pub tcb_or_endpoint: Vec<u8>,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub status: u32,
    pub process_id: u32,
    pub interface_index: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteEndpointArgs {
    pub address_length: u32,
    pub remote_address: Vec<u8>,
    pub remote_port: u64,
    pub local_address: Vec<u8>,
    pub local_port: u16,
    pub partition_id: u64,
    pub num_entries: u64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpInspectConnectWithNameResContextArgs {
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub tcb: Vec<u8>,
    pub name_res_context: Vec<u8>,
    pub dns_name: String,
    pub status: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteEndpoint1466Args {
    pub address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address: Vec<u8>,
    pub partition_id: u64,
    pub num_entries: u64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpConnectionSummary1477Args {
    pub tcb: Vec<u8>,
    pub data_bytes_out: u64,
    pub data_bytes_in: u64,
    pub data_segments_out: u64,
    pub data_segments_in: u64,
    pub segments_out: u64,
    pub segments_in: u64,
    pub non_recov_da: u32,
    pub non_recov_da_episodes: u32,
    pub dup_acks_in: u32,
    pub bytes_retrans: u32,
    pub timeouts: u32,
    pub spurious_rto_detections: u32,
    pub fast_retran: u32,
    pub max_ssthresh: u32,
    pub max_ss_cwnd: u32,
    pub max_ca_cwnd: u32,
    pub snd_lim_trans_rwin: u32,
    pub snd_lim_time_rwin: u32,
    pub snd_lim_bytes_rwin: u64,
    pub snd_lim_trans_cwnd: u32,
    pub snd_lim_time_cwnd: u32,
    pub snd_lim_bytes_cwnd: u64,
    pub snd_lim_trans_snd: u32,
    pub snd_lim_time_r_snd: u32,
    pub snd_lim_bytes_r_snd: u64,
    pub connection_time_ms: u64,
    pub timestamps_enabled: u32,
    pub rtt_us: u32,
    pub min_rtt_us: u32,
    pub max_rtt_us: u32,
    pub syn_retrans: u32,
    pub congestion_algorithm: u32,
    pub state: u32,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub cwnd: u32,
    pub ss_thresh: u32,
    pub rcv_wnd: u32,
    pub rcv_buf: u32,
    pub snd_wnd: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpAccpetListenerRouteLookupFailureArgs_V1 {
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub status: u32,
    pub process_id: u32,
    pub compartment: u32,
    pub tcb: Vec<u8>,
    pub process_start_key :u64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpConnectionRundownArgs_V1 {
    pub tcb: Vec<u8>,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub state: u32,
    pub pid: u32,
    pub process_start_key: u64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TcpipAoacFailFastArgs_V1 {
    pub request_type: u32,
    pub tcb_or_endpoint: Vec<u8>,
    pub local_address_length: u32,
    pub local_address: Vec<u8>,
    pub remote_address_length: u32,
    pub remote_address: Vec<u8>,
    pub status: u32,
    pub process_id: u32,
    pub interface_index: u32,
    pub process_start_key: u64
}

/*
pub struct GeneralNetEvent {
    pub tcb: Option<Vec<u8>>,
    pub local_address_length: Option<u32>,
    pub local_address: Option<Vec<u8>>,
    pub remote_address_length: Option<u32>,
    pub remote_address: Option<Vec<u8>>,
    pub new_state: Option<u32>,
    pub rexmit_count: Option<u32>,
    pub status: Option<u32>,
    pub process_id: Option<u32>,
    pub compartment: Option<u32>,
    pub path: Option<Vec<u8>>,
    pub buffer_size: Option<u32>,
    pub ndk_qp: Option<Vec<u8>>,
    pub request_context: Option<Vec<u8>>,
    pub sge_address: Option<Vec<u8>>,
    pub sge_length: Option<u32>,
    pub sge_memory_region_token: Option<u32>,
    pub num_sge: Option<i32>,
    pub flags: Option<u32>,
    pub sge_index: Option<i32>,
    pub remote_token: Option<u32>,
    pub state: Option<u32>,
    pub pid: Option<u32>,
    pub request_type: Option<u32>,
    pub tcb_or_endpoint: Option<Vec<u8>>,
    pub interface_index: Option<u32>,
    pub address_length: Option<u32>,
    pub remote_port: Option<u64>,
    pub local_port: Option<u16>,
    pub partition_id: Option<u64>,
    pub num_entries: Option<u64>,
    pub name_res_context: Option<Vec<u8>>,
    pub dns_name: Option<String>,
    pub data_bytes_out: Option<u64>,
    pub data_bytes_in: Option<u64>,
    pub data_segments_out: Option<u64>,
    pub data_segments_in: Option<u64>,
    pub segments_out: Option<u64>,
    pub segments_in: Option<u64>,
    pub non_recov_da: Option<u32>,
    pub non_recov_da_episodes: Option<u32>,
    pub dup_acks_in: Option<u32>,
    pub bytes_retrans: Option<u32>,
    pub timeouts: Option<u32>,
    pub spurious_rto_detections: Option<u32>,
    pub fast_retran: Option<u32>,
    pub max_ssthresh: Option<u32>,
    pub max_ss_cwnd: Option<u32>,
    pub max_ca_cwnd: Option<u32>,
    pub snd_lim_trans_rwin: Option<u32>,
    pub snd_lim_time_rwin: Option<u32>,
    pub snd_lim_bytes_rwin: Option<u64>,
    pub snd_lim_trans_cwnd: Option<u32>,
    pub snd_lim_time_cwnd: Option<u32>,
    pub snd_lim_bytes_cwnd: Option<u64>,
    pub snd_lim_trans_snd: Option<u32>,
    pub snd_lim_time_r_snd: Option<u32>,
    pub snd_lim_bytes_r_snd: Option<u64>,
    pub connection_time_ms: Option<u64>,
    pub timestamps_enabled: Option<u32>,
    pub rtt_us: Option<u32>,
    pub min_rtt_us: Option<u32>,
    pub max_rtt_us: Option<u32>,
    pub syn_retrans: Option<u32>,
    pub congestion_algorithm: Option<u32>,
    pub cwnd: Option<u32>,
    pub ss_thresh: Option<u32>,
    pub rcv_wnd: Option<u32>,
    pub rcv_buf: Option<u32>,
    pub snd_wnd: Option<u32>,
    pub process_start_key: Option<u64>,
}
*/

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneralNetEvent {
    pub timestamp: String,
    pub event_id: u16,
    pub event_description: String,
    pub tcb: Option<Vec<u8>>,
    pub local_address_length: Option<u32>,
    pub local_address: Option<Vec<u8>>,
    pub remote_address_length: Option<u32>,
    pub remote_address: Option<Vec<u8>>,
    pub new_state: Option<u32>,
    pub rexmit_count: Option<u32>,
    pub status: Option<u32>,
    pub process_id: Option<u32>,
    pub compartment: Option<u32>,
    pub path: Option<Vec<u8>>,
    pub buffer_size: Option<u32>,
    pub ndk_qp: Option<Vec<u8>>,
    pub request_context: Option<Vec<u8>>,
    pub sge_address: Option<Vec<u8>>,
    pub sge_length: Option<u32>,
    pub sge_memory_region_token: Option<u32>,
    pub num_sge: Option<i32>,
    pub flags: Option<u32>,
    pub sge_index: Option<i32>,
    pub remote_token: Option<u32>,
    pub state: Option<u32>,
    pub pid: Option<u32>,
    pub request_type: Option<u32>,
    pub tcb_or_endpoint: Option<Vec<u8>>,
    pub interface_index: Option<u32>,
    pub address_length: Option<u32>,
    pub remote_port: Option<u64>,
    pub local_port: Option<u16>,
    pub partition_id: Option<u64>,
    pub num_entries: Option<u64>,
    pub name_res_context: Option<Vec<u8>>,
    pub dns_name: Option<String>,
    pub data_bytes_out: Option<u64>,
    pub data_bytes_in: Option<u64>,
    pub data_segments_out: Option<u64>,
    pub data_segments_in: Option<u64>,
    pub segments_out: Option<u64>,
    pub segments_in: Option<u64>,
    pub non_recov_da: Option<u32>,
    pub non_recov_da_episodes: Option<u32>,
    pub dup_acks_in: Option<u32>,
    pub bytes_retrans: Option<u32>,
    pub timeouts: Option<u32>,
    pub spurious_rto_detections: Option<u32>,
    pub fast_retran: Option<u32>,
    pub max_ssthresh: Option<u32>,
    pub max_ss_cwnd: Option<u32>,
    pub max_ca_cwnd: Option<u32>,
    pub snd_lim_trans_rwin: Option<u32>,
    pub snd_lim_time_rwin: Option<u32>,
    pub snd_lim_bytes_rwin: Option<u64>,
    pub snd_lim_trans_cwnd: Option<u32>,
    pub snd_lim_time_cwnd: Option<u32>,
    pub snd_lim_bytes_cwnd: Option<u64>,
    pub snd_lim_trans_snd: Option<u32>,
    pub snd_lim_time_r_snd: Option<u32>,
    pub snd_lim_bytes_r_snd: Option<u64>,
    pub connection_time_ms: Option<u64>,
    pub timestamps_enabled: Option<u32>,
    pub rtt_us: Option<u32>,
    pub min_rtt_us: Option<u32>,
    pub max_rtt_us: Option<u32>,
    pub syn_retrans: Option<u32>,
    pub congestion_algorithm: Option<u32>,
    pub cwnd: Option<u32>,
    pub ss_thresh: Option<u32>,
    pub rcv_wnd: Option<u32>,
    pub rcv_buf: Option<u32>,
    pub snd_wnd: Option<u32>,
    pub process_start_key: Option<u64>,
    pub local_address_ipv4: String,
    pub remote_address_ipv4: String
}

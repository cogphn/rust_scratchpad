use serde::{Deserialize, Serialize};






#[derive(Serialize, Deserialize, Debug)]
pub struct GeneralNetEvent {
    pub ts_str: String,
    pub event_id: u16,
    pub event_description: String,
    pub provider_name: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct DnsServerForInterface {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String, 

    pub interface: Option<String>,
    pub total_server_count: Option<u32>,
    pub index: Option<u32>,
    pub dynamic_address: Option<u8>,
    pub address_length: Option<u32>,
    pub address_ipv4: String 
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3006 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,

    pub query_name: Option<String>,
    pub query_type: Option<u32>,
    pub query_options: Option<u64>,
    pub server_list: Option<String>,
    pub is_network_query: Option<u32>, 
    pub network_query_index: Option<u32>,
    pub interface_index: Option<u32>,
    pub is_async_query: Option<u32>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3008 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,

    pub query_name: Option<String>,
    pub query_type: Option<u32>,
    pub query_options: Option<u64>,
    pub query_status: Option<u32>,
    pub query_results: Option<String>    
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3013 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,

    pub query_name: Option<String>,
    pub query_status: Option<u32>,

    pub query_results: Option<String>

}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3018 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,

    pub query_name : Option<String>,
    pub query_type : Option<u32>,
    pub query_options : Option<u64>,
    pub status: Option<u32>,
    pub query_results: Option<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3020 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,
    
    pub query_name : Option<String>,
    pub network_index: Option<u32>,
    pub interface_index: Option<u32>,
    pub status: Option<u32>,
    pub query_results: Option<String>
}



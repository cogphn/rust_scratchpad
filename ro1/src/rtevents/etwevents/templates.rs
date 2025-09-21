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
    pub ts_str: String,
    pub event_id: u16,
    pub event_desc: String, 
    pub provider_name: String,

    pub interface: Option<String>,
    pub total_server_count: Option<u32>,
    pub index: Option<u32>,
    pub dynamic_address: Option<u8>,
    pub address_length: Option<u32>,
    pub address_ipv4: String 
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3006 {
    pub ts_str: String,
    pub event_id: u16,
    pub event_desc: String,
    pub provider_name: String,

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
    pub ts_str: String,
    pub event_id: u16,
    pub event_desc: String,
    pub provider_name: String,

    pub query_name: Option<String>,
    pub query_type: Option<u32>,
    pub query_options: Option<u64>,
    pub query_status: Option<u32>,
    pub query_results: Option<String>    
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3013 {
    pub ts_str: String,
    pub event_id: u16,
    pub event_desc: String,
    pub provider_name: String,

    pub query_name: Option<String>,
    pub query_status: Option<u32>,

    pub query_results: Option<String>

}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns3018 {
    pub timestamp: String,
    pub event_id: u16,
    pub event_desc: String,
    pub provider_name: String,

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
    pub provider_name: String,
    
    pub query_name : Option<String>,
    pub network_index: Option<u32>,
    pub interface_index: Option<u32>,
    pub status: Option<u32>,
    pub query_results: Option<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericDnsEvent {
	pub ts_str: String,
	pub event_id: u16,
	pub event_desc: String,
    pub provider_name: String,
	pub location: Option<u32>,
	pub context: Option<u32>,
	pub interface: Option<String>,
	pub total_server_count: Option<u32>,
	pub index: Option<u32>,
	pub dynamic_address: Option<u8>,
	pub address_length: Option<u32>,
	pub address: Option<Vec<u8>>,
	pub error_code: Option<u32>,
	pub dns_suffix: Option<String>,
	pub ad_suffix: Option<String>,
	pub query_name: Option<String>,
	pub dns_address_length: Option<u32>,
	pub dns_address: Option<Vec<u8>>,
	pub key_name: Option<String>,
	pub dns_sec_validation_required: Option<u32>,
	pub dns_query_over_ip_sec: Option<u32>,
	pub dns_encryption: Option<u32>,
	pub direct_access_server_list: Option<String>,
	pub remote_ipsec: Option<u32>,
	pub remote_encryption: Option<u32>,
	pub proxy_type: Option<u32>,
	pub proxy_name: Option<String>,
	pub rule_name: Option<String>,
	pub response_question: Option<String>,
	pub generic_server_list: Option<String>,
	pub idn_config: Option<u32>,
	pub query_type: Option<u32>,
	pub query_options: Option<u64>,
	pub status: Option<u32>,
	pub server_list: Option<String>,
	pub is_network_query: Option<u32>,
	pub network_query_index: Option<u32>,
	pub interface_index: Option<u32>,
	pub is_async_query: Option<u32>,
	pub query_status: Option<u32>,
	pub query_results: Option<String>,
	pub is_parallel_network_query: Option<u32>,
	pub network_index: Option<u32>,
	pub interface_count: Option<u32>,
	pub adapter_name: Option<String>,
	pub local_address: Option<String>,
	pub dns_server_address: Option<String>,
	pub dns_server_ip_address: Option<String>,
	pub response_status: Option<u32>,
	pub host_name: Option<String>,
	pub adapter_suffix_name: Option<String>,
	pub dns_server_list: Option<String>,
	pub sent_update_server: Option<String>,
	pub ipaddress: Option<String>,
	pub warning_code: Option<u32>,
	pub next_state: Option<u8>,
	pub update_reason_code: Option<u32>,
	pub source_address: Option<u32>,
	pub source_port: Option<u32>,
	pub destination_address: Option<u32>,
	pub destination_port: Option<u32>,
	pub protocol: Option<u32>,
	pub reference_context: Option<u32>,
	pub if_guid: Option<Vec<u8>>,
	pub if_index: Option<u32>,
	pub if_luid: Option<u64>,
} 



#[derive(Serialize, Deserialize, Debug)]
pub struct GenericRegEvent {
	pub ts_str: String,
	pub event_id: u16,
	pub event_desc: String,
	pub provider_name: String,
	pub base_object: Option<Vec<u8>>,
	pub key_object: Option<Vec<u8>>,
	pub status: Option<u32>,
	pub disposition: Option<u32>,
	pub base_name: Option<String>,
	pub relative_name: Option<String>,
	pub key_name: Option<String>,
	pub info_class: Option<u32>,
	pub data_size: Option<u32>,
	pub captured_data_size: Option<u16>,
	pub captured_data: Option<Vec<u8>>,
	pub etype: Option<u32>,
	pub value_name: Option<String>,
	pub previous_data_type: Option<u32>,
	pub previous_data_size: Option<u32>,
	pub previous_data_captured_size: Option<u16>,
	pub previous_data: Option<Vec<u8>>,
	pub index: Option<u32>,
	pub entry_count: Option<u32>,
	pub hive_file_path: Option<String>,
	pub file_size: Option<u32>,
	pub total_entry_size: Option<u32>,
	pub bytes_recovered: Option<u32>,
	pub status_code: Option<Vec<u8>>,
	pub hive_mount_point: Option<String>,
	pub flush_flags: Option<Vec<u8>>,
	pub bytes_gathered: Option<u32>,
	pub writes_issued: Option<u32>,
	pub bytes_written: Option<u32>,
	pub source_file: Option<String>,
	pub flags: Option<Vec<u8>>,
	pub source_key_path: Option<String>
    
} 

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericFileEvent {
    pub ts_str: String,
	pub event_id: u16,
	pub event_desc: String,
	pub provider_name: String,

    pub irp: Option<Vec<u8>>,
    pub thread_id: Option<Vec<u8>>,
    pub file_object: Option<Vec<u8>>,
    pub file_key: Option<Vec<u8>>,
    pub extra_information: Option<Vec<u8>>,
    pub info_class: Option<u32>,
    pub file_path: Option<String>,
    pub issuing_thread_id: Option<Vec<u8>>,
    pub create_options: Option<u32>,
    pub create_attributes: Option<u32>,
    pub share_access: Option<u32>,
    pub file_name: Option<String>
}

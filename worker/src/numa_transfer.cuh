// Linux D10 comparison: this process's private pages and submitting thread only.
#if defined(__linux__) && defined(SYS_mbind) && defined(SYS_move_pages) && defined(SYS_get_mempolicy)
constexpr unsigned numa_nodes_limit=1024;
constexpr unsigned numa_word_bits=sizeof(unsigned long)*8;
constexpr unsigned numa_mask_words=numa_nodes_limit/numa_word_bits;

std::string numa_read_text(const std::string& path) {
  std::ifstream input(path);char text[16385]{};input.read(text,sizeof(text));const auto size=input.gcount();
  if(size<=0||size>=std::streamsize(sizeof(text)))throw Failure("unsupported","numa_topology_unavailable");
  return std::string(text,std::size_t(size));
}
struct ScopedAffinity {
  cpu_set_t original{};bool changed=false;
  ScopedAffinity(){if(sched_getaffinity(0,sizeof(original),&original)!=0)throw Failure("unsupported","numa_affinity_query_unavailable",errno);}
  void bind(int cpu){cpu_set_t selected;CPU_ZERO(&selected);CPU_SET(cpu,&selected);if(sched_setaffinity(0,sizeof(selected),&selected)!=0)throw Failure("unsupported","numa_affinity_control_unavailable",errno);changed=true;}
  ~ScopedAffinity(){if(changed)sched_setaffinity(0,sizeof(original),&original);}
};
struct NumaPages {
  void* data=MAP_FAILED;std::size_t bytes;bool registered=false;
  explicit NumaPages(std::size_t n):bytes(n){data=mmap(nullptr,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(data==MAP_FAILED)throw Failure("blocked","numa_owned_pages_allocation_failed",errno);}
  ~NumaPages(){if(registered)cudaHostUnregister(data);if(data!=MAP_FAILED)munmap(data,bytes);}
};
std::size_t verify_numa_pages(Result& result,void* data,std::size_t bytes,std::size_t page_bytes,int node) {
  const auto pages=bytes/page_bytes;constexpr std::size_t chunk=1024;
  std::vector<void*> pointers(std::min(chunk,pages));std::vector<int> statuses(pointers.size());
  for(std::size_t offset=0;offset<pages;offset+=pointers.size()) {
    result.budget(50);const auto count=std::min(pointers.size(),pages-offset);
    for(std::size_t i=0;i<count;++i)pointers[i]=static_cast<char*>(data)+(offset+i)*page_bytes;
    if(syscall(SYS_move_pages,0,count,pointers.data(),nullptr,statuses.data(),0)!=0)
      throw Failure("unsupported","numa_owned_page_location_query_unavailable",errno);
    for(std::size_t i=0;i<count;++i)if(statuses[i]!=node)throw Failure("blocked","numa_owned_pages_not_on_requested_node",statuses[i]);
  }
  return pages;
}

void numa_transfer(Result& result,std::size_t allowance) {
  char pci[32]{};cuda_check(cudaDeviceGetPCIBusId(pci,sizeof(pci),0),"numa_selected_pci_bus_id");
  const std::string bus(pci);
  if(bus.empty()||bus.size()>20||bus.find_first_not_of("0123456789abcdefABCDEF:.")!=std::string::npos)
    throw Failure("unsupported","numa_selected_pci_identity_unavailable");
  unsigned domain=0,pci_bus=0,slot=0,function=0;int consumed_bus=0;
  if(std::sscanf(bus.c_str(),"%x:%x:%x.%x%n",&domain,&pci_bus,&slot,&function,&consumed_bus)!=4||consumed_bus!=int(bus.size())||domain>65535||pci_bus>255||slot>31||function>7)
    throw Failure("unsupported","numa_selected_pci_identity_unavailable");
  char normalized_bus[32]{};std::snprintf(normalized_bus,sizeof(normalized_bus),"%04x:%02x:%02x.%x",domain,pci_bus,slot,function);
  int local=-1;
  try{std::size_t consumed=0;const auto value=numa_read_text("/sys/bus/pci/devices/"+std::string(normalized_bus)+"/numa_node");local=std::stoi(value,&consumed);if(value.find_first_not_of("\r\n",consumed)!=std::string::npos)local=-1;}catch(const Failure&){throw;}catch(...){throw Failure("unsupported","numa_gpu_local_node_unavailable");}
  if(local<0||local>=int(numa_nodes_limit))throw Failure("unsupported","numa_gpu_local_node_unavailable");
  unsigned long allowed[numa_mask_words]{};
  if(syscall(SYS_get_mempolicy,nullptr,allowed,numa_nodes_limit,nullptr,MPOL_F_MEMS_ALLOWED)!=0)
    throw Failure("unsupported","numa_allowed_memory_nodes_unavailable",errno);
  auto permitted=[&](unsigned node){return (allowed[node/numa_word_bits]&(1UL<<(node%numa_word_bits)))!=0;};
  if(!permitted(unsigned(local)))throw Failure("unsupported","numa_gpu_local_node_outside_allocation");
  int remote=-1;for(unsigned node=0;node<numa_nodes_limit;++node)if(int(node)!=local&&permitted(node)){remote=int(node);break;}
  if(remote<0)throw Failure("unsupported","numa_comparison_requires_two_allowed_memory_nodes");
  ScopedAffinity affinity;int cpu=-1;
  try{for(int candidate:gri::parse_cpu_list(numa_read_text("/sys/devices/system/node/node"+std::to_string(local)+"/cpulist"),CPU_SETSIZE))if(CPU_ISSET(candidate,&affinity.original)){cpu=candidate;break;}}catch(const Failure&){throw;}catch(...){throw Failure("unsupported","numa_local_cpu_topology_unavailable");}
  if(cpu<0)throw Failure("unsupported","numa_local_cpu_outside_allocation");
  affinity.bind(cpu);
  const long reported_page=sysconf(_SC_PAGESIZE);
  if(reported_page<=0||reported_page>long(MiB))throw Failure("unsupported","numa_page_size_unavailable");
  const auto page_bytes=std::size_t(reported_page);
  const auto bytes=std::min(allowance,std::size_t(result.args.tier=="standard"?256:64)*MiB)/page_bytes*page_bytes;
  if(bytes<page_bytes)throw Failure("blocked","numa_transfer_cap_too_small");
  DeviceBuffer device(bytes);
  result.conditions["direction"]="H2D";result.conditions["copy_method"]="cudaMemcpyAsync_registered_owned_pages";
  result.conditions["host_memory"]="mmap_private_anonymous_cudaHostRegister";
  result.conditions["transfer_bytes"]=bytes;result.conditions["timed_transfers_per_sample"]=4;result.conditions["warmup_transfers_per_node"]=2;
  result.conditions["traffic_accounting"]="one direction payload bytes";
  result.conditions["numa_cpu_affinity_controlled"]=true;result.conditions["numa_cpu_core"]=cpu;
  result.conditions["numa_local_node"]=local;result.conditions["numa_remote_node"]=remote;
  result.conditions["numa_locality_source"]="selected GPU PCI sysfs numa_node; kernel-reported";
  result.conditions["numa_policy"]="MPOL_BIND_owned_anonymous_pages";
  result.conditions["numa_placement_query"]="move_pages_query_only_all_pages_before_and_after_each_sample";
  result.conditions["numa_page_bytes"]=page_bytes;result.conditions["mixed_numa_placements"]=true;
  result.conditions["numa_node_order"]="local_then_remote";
  result.coverage["allocated_device_bytes"]=bytes;result.coverage["peak_pinned_host_bytes"]=bytes;
  result.coverage["host_bytes_per_placement"]=bytes;
  result.metric_name="numa_pinned_h2d";result.unit="GB/s";
  result.limitations.emplace_back("Controlled local/remote host-page H2D comparison holds the submitting CPU fixed. Kernel-reported GPU locality and queried own-page placement are not independent physical-topology attestation.");
  result.limitations.emplace_back("Local precedes remote, so temporal variation can affect the comparison. The pooled median is descriptive only; both node-specific medians and ratio are retained, without a calibrated NUMA penalty claim.");
  std::vector<Json> windows;std::vector<double> local_samples,remote_samples;
  const unsigned repetitions=result.args.tier=="standard"?10:5;
  for(const int node:{local,remote}) {
    result.budget(250);NumaPages host(bytes);unsigned long target[numa_mask_words]{};target[unsigned(node)/numa_word_bits]=1UL<<(unsigned(node)%numa_word_bits);
    if(syscall(SYS_mbind,host.data,bytes,MPOL_BIND,target,numa_nodes_limit,0)!=0)throw Failure("unsupported","numa_memory_policy_control_unavailable",errno);
    auto* words=static_cast<uint32_t*>(host.data);
    for(std::size_t i=0;i<bytes/4;++i)words[i]=gri::pattern(i,2,result.args.seed);
    verify_numa_pages(result,host.data,bytes,page_bytes,node);
    cuda_check(cudaHostRegister(host.data,bytes,cudaHostRegisterDefault),"numa_owned_pages_pin");host.registered=true;
    verify_numa_pages(result,host.data,bytes,page_bytes,node);
    auto operation=[&]{cuda_check(cudaMemcpyAsync(device.data,host.data,bytes,cudaMemcpyHostToDevice),"numa_h2d_copy");};
    auto warm=Clock::now();operation();operation();cuda_check(cudaDeviceSynchronize(),"numa_h2d_warmup");result.warmup_ms+=elapsed_ms(warm);
    for(unsigned repetition=0;repetition<repetitions;++repetition) {
      result.budget(100);if(sched_getcpu()!=cpu)throw Failure("blocked","numa_submitting_cpu_changed");
      const auto before=verify_numa_pages(result,host.data,bytes,page_bytes,node);
      cuda_check(cudaMemset(device.data,0,bytes),"numa_transfer_destination_clear");
      const auto timing=measure([&]{for(int i=0;i<4;++i)operation();});
      verify_device_words(result,device.data,bytes,2);
      const auto after=verify_numa_pages(result,host.data,bytes,page_bytes,node);
      if(sched_getcpu()!=cpu)throw Failure("blocked","numa_submitting_cpu_changed");
      const auto value=double(bytes*4)/(timing.first*1e6);result.add_sample(value,timing.first,timing.second);
      (node==local?local_samples:remote_samples).push_back(value);
      windows.push_back(Json::object({{"sample_index",result.samples.size()-1},{"node",node},{"local",node==local},{"cpu",cpu},{"bytes",bytes},{"value_gb_s",value},{"pages_verified_before",before},{"pages_verified_after",after},{"placement_verified",true}}));
      result.coverage["windows"]=Json::array(windows);
    }
  }
  result.conditions["numa_placement_verified"]=true;
  result.coverage["local_median_gb_s"]=gri::median(local_samples);result.coverage["remote_median_gb_s"]=gri::median(remote_samples);
  result.coverage["local_over_remote_ratio"]=gri::median(local_samples)/gri::median(remote_samples);
}
#else
void numa_transfer(Result&,std::size_t) {throw Failure("unsupported","controlled_numa_transfer_requires_linux_numa_apis");}
#endif

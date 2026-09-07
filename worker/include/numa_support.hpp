#pragma once
#include <string>
#include <vector>
#include <stdexcept>

namespace gri {
// Parse bounded kernel CPU-list notation; caller intersects its own affinity.
inline std::vector<int> parse_cpu_list(const std::string& text, int maximum=1024) {
  if(text.empty()||text.size()>16384||maximum<1||maximum>65536)throw std::invalid_argument("cpu list bound");
  std::vector<int> cpus;
  std::size_t position=0;
  auto number=[&]() {int n=0;const auto start=position;while(position<text.size()&&text[position]>='0'&&text[position]<='9'){n=n*10+(text[position++]-'0');if(n>=maximum)throw std::invalid_argument("cpu index bound");}if(position==start)throw std::invalid_argument("cpu number absent");return n;};
  while(position<text.size()) {
    const int first=number();int last=first;
    if(position<text.size()&&text[position]=='-'){++position;last=number();}
    if(last<first)throw std::invalid_argument("reversed cpu range");
    for(int cpu=first;cpu<=last;++cpu){if(cpus.size()>=std::size_t(maximum))throw std::invalid_argument("cpu list count");cpus.push_back(cpu);}
    if(position==text.size()||text[position]=='\n'){if(position+1<text.size())throw std::invalid_argument("cpu trailing data");break;}
    if(text[position++]!=','||position==text.size())throw std::invalid_argument("cpu delimiter");
  }
  return cpus;
}
}

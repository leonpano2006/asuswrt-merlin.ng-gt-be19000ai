/* Memory-only focused test: include the production generator, mock interfaces. */
#define main native_control_main
#define getifaddrs fixture_getifaddrs
#define freeifaddrs fixture_freeifaddrs
#include "native-control.c"
#undef main
#undef getifaddrs
#undef freeifaddrs

static struct ifaddrs interfaces[4];
static struct sockaddr_in addresses[3], masks[3];
static struct sockaddr_in6 address6, mask6;
static void reset_interfaces(void) {
 memset(interfaces,0,sizeof(interfaces));
 memset(addresses,0,sizeof(addresses));memset(masks,0,sizeof(masks));
 const char *ips[]={"192.168.100.15","172.16.1.15","203.0.113.15"};
 for(unsigned i=0;i<3;i++){
  addresses[i].sin_family=AF_INET;masks[i].sin_family=AF_INET;
  assert(inet_pton(AF_INET,ips[i],&addresses[i].sin_addr)==1);
  assert(inet_pton(AF_INET,"255.255.255.0",&masks[i].sin_addr)==1);
  interfaces[i].ifa_name=i==2?"eth0":"br0";interfaces[i].ifa_flags=IFF_UP;
  interfaces[i].ifa_addr=(struct sockaddr*)&addresses[i];
  interfaces[i].ifa_netmask=(struct sockaddr*)&masks[i];
  interfaces[i].ifa_next=&interfaces[i+1];
 }
 memset(&address6,0,sizeof(address6));memset(&mask6,0,sizeof(mask6));
 address6.sin6_family=AF_INET6;mask6.sin6_family=AF_INET6;
 assert(inet_pton(AF_INET6,"2001:db8:1::15",&address6.sin6_addr)==1);
 assert(inet_pton(AF_INET6,"ffff:ffff:ffff:ffff::",&mask6.sin6_addr)==1);
 interfaces[3].ifa_name="br0";interfaces[3].ifa_flags=IFF_UP;
 interfaces[3].ifa_addr=(struct sockaddr*)&address6;
 interfaces[3].ifa_netmask=(struct sockaddr*)&mask6;
}
int fixture_getifaddrs(struct ifaddrs **result){*result=interfaces;return 0;}
void fixture_freeifaddrs(struct ifaddrs *value){assert(value==interfaces);}
static int expected(char *out,size_t cap,unsigned password,unsigned forwarding,int vpn){
 return snprintf(out,cap,
  "# Generated from verified native LAN interface addresses.\n"
  "Port 22\nAddressFamily any\n"
  "ListenAddress 192.168.100.15:22\nListenAddress 172.16.1.15:22\n"
  "ListenAddress [2001:db8:1::15]:22\n"
  "AllowUsers MastermixStudios@192.168.100.0/24 MastermixStudios@172.16.1.0/24 MastermixStudios@2001:db8:1::/64%s\n"
  "PermitRootLogin no\nPasswordAuthentication %s\nPubkeyAuthentication yes\n"
  "KbdInteractiveAuthentication no\nPermitEmptyPasswords no\nUsePAM yes\n"
  "AuthorizedKeysFile /var/lib/leon-asus-ssh/authorized_keys .ssh/authorized_keys\n"
  "AllowTcpForwarding %s\nGatewayPorts no\nPermitTunnel no\nX11Forwarding no\n"
  "Subsystem sftp /usr/lib/openssh/sftp-server\n",
  vpn?" MastermixStudios@10.5.2.0/24":"",password?"yes":"no",forwarding?"yes":"no");
}
int main(void){
 struct leon_ssh_request request={.port=22};
 strcpy(request.lan_address,"192.168.100.15");
 char config[16384],golden[16384],base[16384];unsigned checks=0;
 for(unsigned password=0;password<2;password++)for(unsigned forwarding=0;forwarding<2;forwarding++){
  reset_interfaces();request.password_auth=password;request.forwarding=forwarding;
  assert(make_config(&request,config,sizeof(config))==0);
  assert(expected(golden,sizeof(golden),password,forwarding,1)>0);
  assert(!strcmp(config,golden));checks++;
 }
 reset_interfaces();strcpy(request.lan_address,"10.5.2.15");errno=0;
 assert(make_config(&request,config,sizeof(config))==-1&&errno==EADDRNOTAVAIL);checks++;
 reset_interfaces();strcpy(request.lan_address,"192.168.100.15");
 for(unsigned i=0;i<4;i++)if(!strcmp(interfaces[i].ifa_name,"br0"))interfaces[i].ifa_flags=0;
 errno=0;assert(make_config(&request,config,sizeof(config))==-1&&errno==EADDRNOTAVAIL);checks++;
 reset_interfaces();masks[0].sin_addr.s_addr=0;errno=0;
 assert(make_config(&request,config,sizeof(config))==-1&&errno==EINVAL);checks++;
 reset_interfaces();request.password_auth=0;request.forwarding=0;
 int base_length=expected(base,sizeof(base),0,0,0);assert(base_length>0);
 errno=0;assert(make_config(&request,config,(size_t)base_length+1)==-1&&errno==EOVERFLOW);checks++;
 printf("VPN_SSH_GENERATOR_PASS checks=%u lan_ipv4_ipv6_auth_listener_golden_and_fail_closed\n",checks);
 return 0;
}

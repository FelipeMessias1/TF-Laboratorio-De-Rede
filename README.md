# Trabalho-Final-Lab-Redes
Para executar o código colocar sudo python monitor.py Para ver interfaces disponíveis colocar ip addr Para testar IPV6 digitar algo como ping -c 4 ::1(executar o programa em um terminal e pingar em outro) Caso queira testar IPV6 com endereço de origem e destino diferentes, dá para adicionar esses endereços na interface: Exemplo: s sudo ip addr add fd00::AAAA/128 dev loudo ip addr add fd00::BBBB/128 dev lo
depois só dar o ping, ex: ping -c 4 -I fd00::AAAA fd00::BBBB

Para testar ICMP: – ping 8.8.8.8 (para IPv4) – ping6 2001:4860:4860::8888 (para IPv6) 
 DNS: – host www.example.com – dig google.com – dig @8.8.8.8 example.org 
 HTTP/HTTPS: – curl http://info.cern.ch 
 (para HTTP) – curl https://www.google.com 
  NTP: –  sudo apt install ntpdate
   sudo ntpdate pool.ntp.org
 DHCP: sudo apt install isc-dhcp-client
       sudo dhclient -r eth0     trocar eth0 pelo nome da interface escolhida
       sudo dhclient eth0
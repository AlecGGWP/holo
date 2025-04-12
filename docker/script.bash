echo "Début du tcpdump"
tcpdump -G 300 -W 1 -i any -w capture_test_%Y-%m-%d_%H-%M-%S.pcap >/dev/null 2>&1 &

echo "Début attente des 5 secondes"
sleep 5
echo "Fin de l'attente"

groupadd -r holo
useradd --system --shell /sbin/nologin --home-dir /var/run/holo/ -g holo holo
mkdir -p /var/run/holo
chown holo:holo /var/run/holo

./usr/local/sbin/holod /etc/holod.toml

echo "alias holo-cli-show='holo-cli -c \"show state\"'" >> /root/.bashrc
echo "alias ipr='ip -4 ro ; ip -6 ro ; ip -M ro'" >> /root/.bashrc

sleep 2 && holo-cli --file /etc/holo/holo.conf

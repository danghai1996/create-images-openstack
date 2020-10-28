# Hướng dẫn đóng image CentOS7 - Wordpress (LEMP) với QEMU Guest Agent + cloud-init

## Chú ý:
- Hướng dẫn này dành cho các image không sử dụng LVM
- Sử dụng công cụ virt-manager hoặc web-virt để kết nối tới console máy ảo
- OS cài đặt KVM là CentOS-7
- Phiên bản OpenStack sử dụng là Queens
- Hướng dẫn bao gồm 2 phần chính: thực hiện trên máy ảo cài OS và thực hiện trên KVM Host

## Thực hiện:
- Đóng image trên KVM
- Cấu hình ban đầu: 
    - RAM: 1 GB
    - Disk: 10 GB
    - CPU: 1

# Cài đặt CentOS-7
- Tiến hành cài đặt OS
- Sau khi cài đặt xong, ta tiến hành sang bước đóng image

## Xử lý trên KVM host
Chỉnh sửa file `.xml` của máy ảo, bổ sung chỉnh sửa channel trong (Thường thì CentOS mặc định đã cấu hình sẵn phần này) mục đích để máy host giao tiếp với máy ảo sử dụng `qemu-guest-agent`

![](..\images\centos7_wordpress_lemp\Screenshot_1.png)

```xml
<channel type='unix'>
      <source mode='bind' path='/var/lib/libvirt/qemu/channel/target/domain-242-haidd_Centos7_Wordpr/org.qemu.guest_agent.0'/>
      <target type='virtio' name='org.qemu.guest_agent.0' state='disconnected'/>
      <alias name='channel0'/>
      <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>
```

> ## Snapshot VM -> `os-begin`

# Cài đặt VM
## Phần 1: Chuẩn bị môi trường

### 1. Cấu hình và cài đặt các gói
Cài đặt `epel-release` và update
```
yum install epel-release -y
yum update -y
yum install -y wget
```

### 2. Disable firewalld, SElinux
```
systemctl disable firewalld
systemctl stop firewalld

sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/sysconfig/selinux
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
```

Reboot kiểm tra lại firewalld và SElinux

### 3. Cấu hình Network
Disable NetworkManager, sử dụng network service
```
systemctl disable NetworkManager
systemctl stop NetworkManager
systemctl enable network
systemctl start network
```

Disable IPv6:
```
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
```

Kiểm tra
```
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
```

Lưu ý: Kết quả ra `1` => Tắt thành công, `0` tức IPv6 vẫn bật

### 4. Cài đặt CMDlog
```
curl -Lso- https://raw.githubusercontent.com/nhanhoadocs/ghichep-cmdlog/master/cmdlog.sh | bash
```

### 5. Cấu hình SSH
```
sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/g' /etc/ssh/sshd_config 
sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/g' /etc/ssh/sshd_config 
systemctl restart sshd
```

### 6. Điều chỉnh timezone
Đổi timezone về `Asia/Ho_Chi_Minh`
```
timedatectl set-timezone Asia/Ho_Chi_Minh
```

### 7. Cài đặt chronyd
```
yum install chrony -y
sed -i 's|server 1.centos.pool.ntp.org iburst|server 103.101.161.201 iburst|g' /etc/chrony.conf
systemctl enable --now chronyd 
hwclock --systohc
```

> ## Snapshot `OS_env`

## Phần 2: Cài đặt wordpress (với LEMP)
### 1. Cài đặt Nginx
Tạo file repo:
```
vi /etc/yum.repos.d/nginx.repo
```
Nội dung
```
[nginx]
name=NginxRepo
baseurl=https://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=0
enabled=1
```

Cài đặt Nginx
```
yum install nginx -y
```

Kiểm tra phiên bản:
```
nginx -v
nginx version: nginx/1.18.0
```

Cài xong, tiến hành khởi động lại service:
```
systemctl start nginx
systemctl enable nginx
```

Check lại trạng thái hoạt động của service
```
systemctl status nginx
```

Kiểm tra bằng truy cập IP của VM

![](..\images\centos7_wordpress_lemp\Screenshot_2.png)

### 2. Cài đặt MariaDB
Mặc định, repo cài đặt MariaDB trên CentOS-7 là phiên bản 5.x. Vì vậy, để cài đặt bản mới cần chỉnh sửa repo cài MariaDB (phiên bản 10.5.6 - Stable)
```
vi /etc/yum.repos.d/MariaDB.repo
```
Nội dung
```
# MariaDB 10.5 CentOS repository list - created 2020-10-14 04:31 UTC
# http://downloads.mariadb.org/mariadb/repositories/
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.5/centos7-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
```

Cài đặt MariaDB:
```
yum install MariaDB-server MariaDB-client -y
```

Khởi động mariadb service:
```
systemctl start mariadb
systemctl enable mariadb
```

Cài đặt một số thông tin ban đầu:
```
mysql_secure_installation
```

![](..\images\centos7_wordpress_lemp\Screenshot_3.png)

Kiểm tra phiên bản:
```
mysql -V
mysql  Ver 15.1 Distrib 10.5.6-MariaDB, for Linux (x86_64) using readline 5.1
```

Disable `unix_socket authentication`: Thêm đoạn sau vào file `/etc/my.cnf`
```
[mariadb]
unix_socket=OFF
```

Restart service
```
systemctl restart mariadb
```

### 3. Cài đặt PHP
Cài đặt PHP 7.4
```
yum install -y epel-release yum-utils
yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum-config-manager --enable remi-php74
yum install -y php php-fpm php-common
yum install php-mysql php-gd php-xml php-mbstring php-opcache php-devel php-pear php-bcmath -y
```

Kiểm tra lại phiên bản PHP
```
php -v

PHP 7.4.11 (cli) (built: Sep 29 2020 10:17:06) ( NTS )
Copyright (c) The PHP Group
Zend Engine v3.4.0, Copyright (c) Zend Technologies
    with Zend OPcache v7.4.11, Copyright (c), by Zend Technologies
```

### 4. Cấu hình Nginx và PHP-FPM
Chỉnh sửa file:
```
vi /etc/nginx/conf.d/default.conf
```

Cấu hình nginx virtual hosts
```conf
server {
    listen   80;
    server_name  server_ip;

    # note that these lines are originally from the "location /" block
    root   /usr/share/nginx/html;
    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }

    location ~ .php$ {
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php-fpm/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
```
**Trong đó:** `server_name  <server_ip>;` -> `<server_ip>` : IP của server

Xác minh file cấu hình đúng:
```
nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Cấu hình PHP-FPM:
```
vi /etc/php-fpm.d/www.conf
```
Tìm và chỉnh sửa các mục:
- `user = apache` thành `user = nginx`
- `group = apache` thành `group = nginx`
- `listen.owner = nobody` thành `listen.owner = nginx`
- `listen.group = nobody` thành `listen.group = nginx`
- `;listen = 127.0.0.1:9000` thành `listen = /var/run/php-fpm/php-fpm.sock`

![](..\images\centos7_wordpress_lemp\Screenshot_4.png)

Start service php-fpm:
```
systemctl start php-fpm.service
systemctl enable php-fpm.service
```

Thêm đoạn sau vào file `/usr/share/nginx/html/info.php`
```
<?php
phpinfo();
?>
```

Truy cập 
```
<IP_server>/php.info
```

![](..\images\centos7_wordpress_lemp\Screenshot_5.png)

Xóa file test:
```
rm -f /usr/share/nginx/html/info.php
```

> ## Snapshot `lemp_stack`

### 5. Cài đặt wordpress
#### **Tạo cơ sở dữ liệu và tài khoản cho Wordpress**

Đăng nhập vào tài khoản root của database:
```
mysql -u root -p
```

Tạo Database cho Wordpress. Đặt tên db là: `wp_db`
```sql
CREATE DATABASE wp_db;
```

Tạo tài khoản riêng để quản lí DB. Tên tài khoản: `wp_user`, Mật khẩu: `nhanhoa2020`
```sql
CREATE USER wp_user@localhost IDENTIFIED BY 'nhanhoa2020';
```

Bây giờ ta sẽ cấp quyền quản lí cơ sở dữ liệu cho user mới tạo:
```sql
GRANT ALL PRIVILEGES ON *.* TO wp_user@localhost IDENTIFIED BY 'nhanhoa2020';
```

Sau đó xác thực lại những thay đổi về quyền và thoát giao diện mariadb
```
FLUSH PRIVILEGES;

exit
```

Tải xuống WordPress phiên bản mới nhất: 
```
wget https://wordpress.org/latest.tar.gz
```

Giải nén file `latest.tar.gz`
```
tar xvfz latest.tar.gz
```

Copy các file trong thư mục wordpress tới đường dẫn `/usr/share/nginx/html/`
```
cp -Rvf /root/wordpress/* /usr/share/nginx/html
```

#### **Cấu hình wordpress**
Tạo file cấu hình từ file mẫu:
```
cp /usr/share/nginx/html/wp-config-sample.php /usr/share/nginx/html/wp-config.php
```

Chỉnh sửa file cấu hình `wp-config.php`. Chỉnh lại tên database, username, password đã đặt ở trên. 
```
vi /var/www/html/wp-config.php
```
- `db_name`: `wp_db`,
- `username`: `wp_user`
- `pass`: `nhanhoa2020`

![](..\images\centos7_wordpress_lemp\Screenshot_6.png)

Xóa file wordpress giải nén đã tải về:
```
rm -rf /root/latest.tar.gz /root/wordpress/
```

#### **Phân quyền**
```
chown -R nginx:nginx /usr/share/nginx/html/*
chown -R root:root /usr/share/nginx/html/wp-config.php
```

### 6. Cấu hình thêm
#### Tăng giới hạn dung lượng upload file
Chỉnh sửa file 
```
vi /etc/php.ini
```
Sửa các mục sau:
```conf
upload_max_filesize = 20M
post_max_size = 22M
```

#### Tạo file lưu thông tin mysql
```
vi /root/info.txt
```
Nội dung:
```
MySQL:
- root/nhanhoa2020
- wp_user/nhanhoa2020
```

> ## Snapshot `WP-LEMP`

## Phần 3: Cấu hình tối ưu các stack LEMP
### 1. Tunning OS
Chỉnh sửa file `/etc/sysctl.conf`
Thêm các cấu hình dưới vào file:
```yaml
### GENERAL SYSTEM SECURITY OPTIONS ###
###

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

#Allow for more PIDs
kernel.pid_max = 65535

# The contents of /proc/<pid>/maps and smaps files are only visible to
# readers that are allowed to ptrace() the process
#kernel.maps_protect = 1

#Enable ExecShield protection
#kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Controls the maximum size of a message, in bytes
kernel.msgmnb = 65535

# Controls the default maxmimum size of a mesage queue
kernel.msgmax = 65535

# Restrict core dumps
fs.suid_dumpable = 0

# Hide exposed kernel pointers
kernel.kptr_restrict = 1

###
### IMPROVE SYSTEM MEMORY MANAGEMENT ###
###

# Increase size of file handles and inode cache
 fs.file-max = 597900
 vm.max_map_count = 597900

# Do less swapping
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# specifies the minimum virtual address that a process is allowed to mmap
vm.mmap_min_addr = 4096

# 50% overcommitment of available memory
vm.overcommit_ratio = 50
vm.overcommit_memory = 0

# Set maximum amount of memory allocated to shm to 256MB
kernel.shmmax = 268435456
kernel.shmall = 268435456

# Keep at least 64MB of free RAM space available
vm.min_free_kbytes = 65535

###
### GENERAL NETWORK SECURITY OPTIONS ###
###

#Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 65536

# Disables packet forwarding
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Disables IP source routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 7

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Don't relay bootp
net.ipv4.conf.all.bootp_relay = 0

# Don't proxy arp for anyone
net.ipv4.conf.all.proxy_arp = 0

# Turn on the tcp_timestamps, accurate timestamp make TCP congestion control algorithms work better
net.ipv4.tcp_timestamps = 1

# Don't ignore directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Enable ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Allowed local port range
net.ipv4.ip_local_port_range = 1024 65535

# Enable a fix for RFC1337 - time-wait assassination hazards in TCP
net.ipv4.tcp_rfc1337 = 1



###
### TUNING NETWORK PERFORMANCE ###
###

# For high-bandwidth low-latency networks, use 'bbr' congestion control (kernel > 4.9)
# Only enabled in bionic (at least v4.15)
# Do a 'sudo modprobe tcp_bbr' first
net.ipv4.tcp_notsent_lowat = 16384

# For servers with tcp-heavy workloads, enable 'fq' queue management scheduler (kernel > 3.12)
net.core.default_qdisc = fq

# Turn on the tcp_window_scaling
net.ipv4.tcp_window_scaling = 1

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# Increase number of incoming connections
net.core.somaxconn = 32768

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 16384
net.core.dev_weight = 64

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# When mem allocated by TCP exceeds “pressure”, kernel will put pressure on TCP memory
net.ipv4.tcp_mem=8388608 8388608 8388608

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 6000000

# try to reuse time-wait connections, but don't recycle them (recycle can break clients behind NAT)
#net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1

# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_orphan_retries = 0

# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391)
net.ipv4.ipfrag_low_thresh = 196608
net.ipv6.ip6frag_low_thresh = 196608
net.ipv4.ipfrag_high_thresh = 262144
net.ipv6.ip6frag_high_thresh = 262144


# don't cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase size of RPC datagram queue length
net.unix.max_dgram_qlen = 50

# Don't allow the arp table to become bigger than this
net.ipv4.neigh.default.gc_thresh3 = 2048

# Tell the gc when to become aggressive with arp table cleaning.
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
net.ipv4.neigh.default.gc_thresh2 = 1024

# Adjust where the gc will leave arp table alone - set to 32.
net.ipv4.neigh.default.gc_thresh1 = 32

# Adjust to arp table gc to clean-up more often
net.ipv4.neigh.default.gc_interval = 30

# Increase TCP queue length
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3

# How many times to retry killing an alive TCP connection
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_retries1 = 3

# Avoid falling back to slow start after a connection goes idle
# keeps our cwnd large with the keep alive connections (kernel > 3.6)
net.ipv4.tcp_slow_start_after_idle = 0

# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
net.ipv4.tcp_fastopen = 3

# This will enusre that immediatly subsequent connections use the new values
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1


###
### CUSTOM ###
###

fs.nr_open=12000000
net.ipv4.tcp_sack=1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_challenge_ack_limit = 999999999
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
# End
```

Thêm vào cuối file: `/etc/security/limits.conf`
```
root	-	nofile	1048576
*	    -	nofile	597900
```

Kiểm tra:
```
sysctl -p
```

### 2. Tunning Nginx
Tạo thư mục:
```
mkdir -p /lib/systemd/system/nginx.service.d
```
Tạo file:
```
vi /lib/systemd/system/nginx.service.d/worker_files_limit.conf
```
Nội dung
```
[Service]
LimitNOFILE=100000
```
Restart service:
```
systemctl daemon-reload
systemctl restart nginx
```

Backups file cấu hình nginx
```
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
```

Ta sẽ chỉnh lại file cấu hình Nginx: `/etc/nginx/nginx.conf`.
```
vi /etc/nginx/nginx.conf
```
```
user  nginx;
worker_processes  auto;
worker_rlimit_nofile 100000;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  20000;
    multi_accept on;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    reset_timedout_connection on;

    send_timeout 30;
    keepalive_timeout 30;
    keepalive_requests 100000;

    client_body_buffer_size 32k;
    client_max_body_size 100m;
    client_body_timeout 30;
    client_header_timeout 30;

    open_file_cache_valid 3m;
    open_file_cache max=30000 inactive=1m;

    types_hash_max_size 2048;
    server_names_hash_max_size 2048;

    ##
    # Gzip Settings
    ##

    gzip on;
    gzip_disable "msie6";

    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types application/atom+xml application/javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/svg+xml image/x-icon text/css text/plain text/x-component text/xml text/javascript;

    include /etc/nginx/conf.d/*.conf;
}
```

Kiểm tra lại một số thông số quan trọng:
```
cat /etc/nginx/nginx.conf | grep -E 'worker_rlimit_nofile|client_max_body_size|open_file_cache|fastcgi_cache_path'

worker_rlimit_nofile 100000;
    client_max_body_size 100m;
    open_file_cache_valid 3m;
    open_file_cache max=30000 inactive=1m;
```

```
cat /lib/systemd/system/nginx.service.d/worker_files_limit.conf
[Service]
LimitNOFILE=100000
```

```
ps --ppid $(cat /var/run/nginx.pid) -o %p|sed '1d'|xargs -I{} cat /proc/{}/limits|grep open.files

Max open files            100000               100000               files
```

### 3. Tunning MariaDB
#### **Bật query cache mariadb:**
Kiểm tra xem query cache có được hỗ trợ không ?
```
MariaDB [(none)]> show variables like 'have_query_cache';
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| have_query_cache | YES   |
+------------------+-------+
```

Kiểm tra các biến của Query cache:
```
MariaDB [(none)]> show variables like 'query_cache_%' ;
+------------------------------+---------+
| Variable_name                | Value   |
+------------------------------+---------+
| query_cache_limit            | 1048576 |
| query_cache_min_res_unit     | 4096    |
| query_cache_size             | 1048576 |
| query_cache_strip_comments   | OFF     |
| query_cache_type             | OFF     |
| query_cache_wlock_invalidate | OFF     |
+------------------------------+---------+
```

Cấu hình query cache:

Sửa file `/etc/my.cnf`:
```
[mysqld]
query_cache_type =1
query_cache_limit = 128K
query_cache_size = 64M
```

Restart service:
```
systemctl restart mariadb
```

Truy cập Mariadb, kiểm tra lại các giá trị biến query cache:
```
mysql -uroot -p

MariaDB [(none)]> show variables like 'query_cache_%' ;
+------------------------------+----------+
| Variable_name                | Value    |
+------------------------------+----------+
| query_cache_limit            | 131072   |
| query_cache_min_res_unit     | 4096     |
| query_cache_size             | 67108864 |
| query_cache_strip_comments   | OFF      |
| query_cache_type             | ON       |
| query_cache_wlock_invalidate | OFF      |
+------------------------------+----------+
```

Kiểm chứng theo [tài liệu](https://www.digitalocean.com/community/tutorials/how-to-optimize-mysql-with-query-cache-on-ubuntu-18-04).


### 4. Tunning PHP
Ta sẽ thực hiện cấu hình `php-opcache`

Để bật tính năng opcache của php, truy cập file `/etc/php.d/10-opcache.ini` và thay đổi các giá trị dưới đây:
```
vi /etc/php.d/10-opcache.ini
```
```conf
opcache.enable=1
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=192
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=50000
```

Chỉnh sửa file:
```
vi /etc/php-fpm.d/www.conf
```
Chỉnh sửa các mục:
```conf
[www]
user = nginx
group = nginx
listen = /var/run/php-fpm/php-fpm.sock
listen.owner = nginx
listen.group = nginx
listen.allowed_clients = 127.0.0.1
pm = dynamic
pm.max_children = 30
pm.start_servers = 10
pm.min_spare_servers = 10
pm.max_spare_servers = 20
pm.max_requests = 1000
pm.status_path = /status
ping.path = /ping
slowlog = /var/log/php-fpm/www-slow.log
request_terminate_timeout = 300
php_admin_value[error_log] = /var/log/php-fpm/www-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = files
php_value[session.save_path]    = /var/lib/php/session
php_value[soap.wsdl_cache_dir]  = /var/lib/php/wsdlcache
```

Restart php-fpm
```
systemctl restart php-fpm.service
```

### 5. Vô hiệu hóa `xmlrpc.php`
Ta sẽ chỉnh chặn trong cấu hình ngix:
```
vi /etc/nginx/conf.d/default.conf
```

Thêm block sau trong block `server{}`
```
server {
    ...
    location = /xmlrpc.php {
        deny all;
    }
}
```

File `/etc/nginx/conf.d/default.conf`
```nginx
server {
    listen   80;
    server_name  10.10.30.170;

    # note that these lines are originally from the "location /" block
    root   /usr/share/nginx/html;
    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }

    location ~ .php$ {
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php-fpm/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location = /xmlrpc.php {
        deny all;
    }
}
```

Kiểm tra và restart service:
```
nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful

systemctl restart nginx
```

Kiểm tra: Truy cập đường dẫn:
```
<IP_server>/xmlrpc.php
```
Thấy kết quả như hình là ok:

![](..\images\centos7_wordpress_lemp\Screenshot_7.png)

> ## Snapshot: Tunning_wp

## Phần 4: Cài đặt cấu hình các thành phần đóng image
- Tạo file `/root/info.txt` lưu thông tin db: 
    ```
    MySQL:
    - root/nhanhoa2020
    - wp_user/nhanhoa2020
    ```

- Cài đặt acpid nhằm cho phép hypervisor có thể reboot hoặc shutdown instance.
    ```
    yum install acpid -y
    systemctl enable acpid
    ```

- Cài đặt qemu guest agent, kích hoạt và khởi động qemu-guest-agent service
    ```
    yum install -y qemu-guest-agent
    systemctl enable qemu-guest-agent.service
    systemctl start qemu-guest-agent.service
    ```

- Cài đặt cloud-init và cloud-utils:
    ```
    yum install -y cloud-init cloud-utils
    ```
    Để máy ảo trên OpenStack có thể nhận được Cloud-init cần thay đổi cấu hình mặc định bằng cách sửa đổi file `/etc/cloud/cloud.cfg`.
    ```
    sed -i 's/disable_root: 1/disable_root: 0/g' /etc/cloud/cloud.cfg
    sed -i 's/ssh_pwauth:   0/ssh_pwauth:   1/g' /etc/cloud/cloud.cfg
    sed -i 's/name: centos/name: root/g' /etc/cloud/cloud.cfg
    ```

**Lưu ý:**

- Để sử sụng qemu-agent, phiên bản selinux phải > 3.12
    ```
    rpm -qa | grep -i selinux-policy
    ```
- Để có thể thay đổi password máy ảo thì phiên bản qemu-guest-agent phải >= 2.5.0
    ```
    qemu-ga --version
    ```

- Cấu hình console
    - Để sử dụng nova console-log, bạn cần thay đổi option cho `GRUB_CMDLINE_LINUX` và lưu lại
    ```
    sed -i 's/GRUB_CMDLINE_LINUX="crashkernel=auto rhgb quiet"/GRUB_CMDLINE_LINUX="crashkernel=auto console=tty0 console=ttyS0,115200n8"/g' /etc/default/grub

    grub2-mkconfig -o /boot/grub2/grub.cfg
    ```

- Disable Default routing
    ```
    echo "NOZEROCONF=yes" >> /etc/sysconfig/network
    ```

- Để sau khi boot máy ảo, có thể nhận đủ các NIC gắn vào:
    ```
    cat << EOF >> /etc/rc.local
    for iface in \$(ip -o link | cut -d: -f2 | tr -d ' ' | grep ^eth)
    do
    test -f /etc/sysconfig/network-scripts/ifcfg-\$iface
    if [ \$? -ne 0 ]
    then
        touch /etc/sysconfig/network-scripts/ifcfg-\$iface
        echo -e "DEVICE=\$iface\nBOOTPROTO=dhcp\nONBOOT=yes" > /etc/sysconfig/network-scripts/ifcfg-\$iface
        ifup \$iface
    fi
    done
    EOF
    ```

    Thêm quyền thực thi cho file `/etc/rc.local`
    ```
    chmod +x /etc/rc.local 
    ```

- Xóa file hostname
    ```
    rm -f /etc/hostname
    ```

- Clean all
    ```
    yum clean all

    rm -f /var/log/wtmp /var/log/btmp

    rm -f /root/.bash_history

    > /var/log/cmdlog.log

    history -c
    ```

> ## Tắt VM -> Snapshot: Final

## Phần 5: Xử lý image trên KVM host
###  Sử dụng lệnh virt-sysprep để xóa toàn bộ các thông tin máy ảo
```
virt-sysprep -d haidd_Centos7_Wordpress
```

### Tối ưu kích thước image:
```
virt-sparsify --compress --convert qcow2 /var/lib/libvirt/images/haidd_Centos7_Wordpress.qcow2 CentOS7-WP-LEMP.qcow2
```

### Upload image lên glance và sử dụng
```
glance image-create --container-format bare --visibility=public \
--name CentOS7-Wordpress-LEMP --disk-format raw \
--file /root/Haidd-images/CentOS7-WP-LEMP.raw --visibility=public \
--property os_type=linux \
--property hw_qemu_guest_agent=yes \
--property vps_image_user=root \
--property vps_image_type=CentOS \
--property vps_image_app=true \
--min-disk 10 --min-ram 1024 --progress
```

## Cloud-init:
Script
```bash
#!/bin/bash
# LEMP-WP
# NhanHoa Cloud Team 

# Input from cloud-init
new_passwd_1=$1
new_passwd_2=$2
ip_server=$(hostname -I | awk '{print $1}')

# Get info mysql_root_passwd and wp_user_passwd password
old_passwd_1=$(cat /root/info.txt | grep root | cut -d '/' -f2)
old_passwd_2=$(cat /root/info.txt | grep wp_user | cut -d '/' -f2)

# Change IP virtual host
sed -Ei "s|server_ip|$ip_server|g" /etc/nginx/conf.d/default.conf

# Change password
mysqladmin --user=root --password=$old_passwd_1 password $new_passwd_1
mysqladmin --user=wp_user --password=$old_passwd_2 password $new_passwd_2

# Save info.txt
sed -Ei "s|root\/$old_passwd_1|root\/$new_passwd_1|g" /root/info.txt
sed -Ei "s|wp_user\/$old_passwd_2|wp_user\/$new_passwd_2|g" /root/info.txt
# Save to setting wp-config.php
sed -Ei "s|'$old_passwd_2'|'$new_passwd_2'|g" /usr/share/nginx/html/wp-config.php

# Delete info.txt
rm -f /root/info.txt
```

Cloud-init sau khi đã mã hóa script
```yaml
#cloud-config
password: '{vps_password}'
chpasswd: { expire: False }
ssh_pwauth: True
write_files:
- encoding: gzip
  content: !!binary |
    H4sIAKXxmF8AA32SQU/jMBCF7/kVsxApcHCt5p4TIKgEqNIicVkpMrGTWCS2sSctK8p/XzubVA4qnGJPMt+89ybnv+iLVPSFuTY5h/ubhy153vrTY8vUnWZw1emBw5NgPSS+vFFmQKit7qEKb4hUEhMl9qVhzu15uS7SdXzPizRPpCmdsDthi/Si1Q4V6wWQDRyA7V8h+zBWKoR0/ZldhiG3AkGqWkP/1711pdUaJxwwxWFvysHj5tL40JYnuuORiouKIdDQSwNrhe/o5zVWGAhFf668E8IhoxmQOr+M+/Mf+ycBJxBe/JUPrhGw2cJOWhxYB8Fx4gQHciPhzB3+R1FKc0iPwRyaM6ACK6oaqd5ppVW94pSLmg0drsI1Yh8dj/kw3ksFhARJxWiNkPmLIo1DOTZCGm/sBGZ2+A0pP03Kg8bfbCdgTiy2HaT9oQtBcy1WMyaxiD2GTMKWnDwqx3JOoCZ9qMEJRKkav0wS4pXNyrQmHpUtRmT+HrOzET44S13LrJj21mLf0SXRj7wWncAoFNv7v+Wrsn/bTgMbiQMAAA==
  path: /opt/wp-lemp.sh
  permissions: '0755'
runcmd:
  - bash /opt/wp-lemp.sh {vps_mysql_password} {db_wp_password}
  - rm -f /opt/wp-lemp.sh
```
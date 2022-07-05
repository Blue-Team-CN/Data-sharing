# CobaltStrike破解及特征去除

隐藏方法主要有以下几种:

- 默认端口修改
- 流量特征混淆
  - 服务端证书修改
  - 上线证书修改
  - CloudFlare证书申请
- dns_idle
- ip/域名隐藏
  - CDN
    - Cloudflare CDN配置
    - Profile配置
    - Listener配置
- 域前置
- 反向代理
  - Malleable C2 profile配置
  - Nginx配置
  - 防火墙配置
- Cloudflare Workers隐藏域名
- 云函数隐匿真实IP
- Heroku代理隐匿真实IP
- Beacon Staging特征

## 0x00 java环境安装

ubuntu安装部署

[ORACLE官网下载JDK地址](https://www.oracle.com/java/technologies/javase-jdk8-downloads.html)

```bash
# 解压文件并移动至/opt目录下
sudo tar -xzvf jdk-8u91-linux-x64.tar.gz -C /opt
# 设置环境变量，修改全局配置文件
sudo vim ~/.bashrc
# 添加以下内容
#set oracle jdk environment 
export JAVA_HOME=/opt/jdk1.8.0_333 
export JRE_HOME=${JAVA_HOME}/jre 
export CLASSPATH=.:${JAVA_HOME}/lib:${JRE_HOME}/lib 
export PATH=${JAVA_HOME}/bin:$PATH
# 配置文件生效
source /etc/profile
# 验证安装是否成功
java -version #显示java版本
javac #有提示
```

注意，在ubuntu环境下，如果使用`apt install`命令安装过相关java环境，切记要先卸载。

## 0x01 CS下载、破解与汉化

官方包下载地址：<https://github.com/k8gege/Aggressor/releases/download/cs/CobaltStrike_4.4_000.jar>

官方hash验证地址：<https://verify.cobaltstrike.com/>

dogcs下载地址：<https://github.com/TryHello/DogCs4.4/releases/tag/dog>

破解与汉化CSAgent.zip下载地址：<https://github.com/Twi1ight/CSAgent/>

破解及汉化步骤：

```yml
下载CSAgent.zip解压，将原版cobaltstrike.jar放到解压目录中，确保CSAgent.jar、resources文件夹、scripts文件夹和cobaltstrike.jar处于同级目录

替换CSAgent.properties文件中的sleeved.decryption.key的值为官方解密key，目前内置的key为4.5版本，各个版本的官方解密key：
- 4.0 1be5be52c6255c33558e8a1cb667cb06
- 4.1 80e32a742060b884419ba0c171c9aa76
- 4.2 b20d487addd4713418f2d5a3ae02a7a0
- 4.3 3a4425490f389aeec312bdd758ad2b99
- 4.4 5e98194a01c6b48fa582a6a9fcbb92d6
- 4.5 f38eb3d1a335b252b58bc2acde81b542
正常使用teamserver和cobaltstrike脚本启动即可，用法与以前无任何差别，windows使用cobaltstrike.bat启动
对于仅想使用破解功能的朋友，只需删除resources文件夹和scripts文件夹即可去除汉化
```

## 0x02 CS启动与连接

本文以dogcs为例子。Windows服务端启动：

```powershell
#下载带jdk的版本,然后在当前目录下执行
jdk-11.0.15.1\bin\java.exe -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=4488 -Dcobaltstrike.server_bindto=0.0.0.0 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword=Microsoft -server -XX:+AggressiveHeap -XX:+UseParallelGC -classpath ./dogcs.jar -Duser.language=en server.TeamServer 192.168.0.105 demo
#如果没有证书cobaltstrike.store文件，使用以下命令生成证书文件
keytool -keystore ./cobaltstrike.store -storepass Microsoft -keypass Microsoft -genkey -keyalg RSA -alias cobaltstrike -dname "CN=*.microsoft.com, OU=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US"
```

客户端启动`./cobaltstrike`

## 0x03 C2隐藏

在真实的红蓝对抗中，隐藏C2是很有必要的。本文重点在于本章节。

### 1.端口修改

cobalt strike服务端默认50050端口，修改也很简单。只需要编辑teamserver文件，将50050修改为想要更改的端口即可。或者启动时指定server_port

```yml
# start the team server.
java -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=4488 -Dcobaltstrike.server_bindto=0.0.0.0 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword=Microsoft -server -XX:+AggressiveHeap -XX:+UseParallelGC -classpath ./dogcs.jar -Duser.language=en server.TeamServer $*
```

### 2.流量特征混淆

#### 2.1 服务端证书修改

查看keytool -list -v -keystore cobaltstrike.store证书情况，输入默认密码123456回车，可以看到所有者、发布者中Cobalt Strike相关字样。

使用keytool生成新的证书。

```yml
keytool -keystore ./cobaltstrike.store -storepass Microsoft -keypass Microsoft -genkey -keyalg RSA -alias cobaltstrike -dname "CN=*.microsoft.com, OU=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US"
```

```yml
keytool是一个Java数据证书的管理工具，使用如下：

    -keytool -keystore cobaltstrike.store -storepass 密码

    -keypass 密码

    -genkey -keyalg RSA

    -alias google.com -dname "CN=(名字与姓氏),

    OU=(组织单位名称), O=(组织名称),

    L=(城市或区域名称),

    ST=(州或省份名称),

    C=(单位的两字母国家代码)。
```

#### 2.2 上线证书修改

如果想要修改这个证书，需要修改Malleable C2 profile。

Self-signed Certificates with SSL Beacon 和 Valid SSL Certificates with SSL Beacon

这两个都是用来修改https上线使用的证书的。

- Self-signed Certificates with SSL Beacon 这里是自己设定的自签名证书。
- Valid SSL Certificates with SSL Beacon这里是叫我们使用有效的证书。

我们可以使用之前修改过的cobaltstrike.store，也可以使用从其他地方弄过来的证书

我们可以在启动CobaltStrike的时候，指定一个profile文件，然后在文件中配置上线时使用的证书文件即可修改上线时默认的证书。

这里以jquery-c2.4.2.profile为例：

```yml
https-certificate { ## Option 1) Trusted and Signed Certificate ## Use keytool to create a Java Keystore file. ## Refer to https://www.cobaltstrike.com/help-malleable-c2#validssl ## or https://github.com/killswitch-GUI/CobaltStrike-ToolKit/blob/master/HTTPsC2DoneRight.sh ## Option 2) Create your own Self-Signed Certificate ## Use keytool to import your own self signed certificates #set keystore "/pathtokeystore"; #set password "password"; ## Option 3) Cobalt Strike Self-Signed Certificate set C "US"; set CN "jquery.com"; set O "jQuery"; set OU "Certificate Authority"; set validity "365"; }
```

自定义生成证书修改Option 3下面的选项即可，

使用前面服务端生成的cobaltstrike.store或者 自己申请的真实证书，注释掉Option 3，使用Option 2即可

```yml
set keystore "/pathtokeystore.store";  #密钥库文件路径
set password "password";         #密钥库密码
```

#### 2.3 CloudFlare证书申请

如果接入了Cloudflare CDN，可以直接使用Cloudflare提供的证书，或者使用letsencrypt这样的免费证书。

```yml
SSL/TLS --> 源服务器
```

使用默认配置生成证书和秘钥后，复制粘贴到你的服务器上，这里选择的文件名server.pem和server.key。

```yml
# xxx.xxx.com 为申请的域名 openssl pkcs12 -export -in server.pem -inkey server.key -out xxx.xxx.com.p12 -name xxx.xxx.com -passout pass:123456
```

```yml
keytool -importkeystore -deststorepass 123456 -destkeypass 123456 -destkeystore xxx.xxx.com.store -srckeystore xxx.xxx.com.p12 -srcstoretype PKCS12 -srcstorepass 123456 -alias xxx.xxx.com
```

在生成keystore文件后将该文件放在CS的根目录下，务必确保keystore文件名与密码和https-certificate中设置的一致。

```yml
./c2lint jquery-c2.4.3.profile
// 检查一下是否可用
```

### 3.dns_idle

0.0.0.0是Cobalt Strike DNS Beacon特征可设置Malleable C2进行修改 输入set dns_idle “8.8.8.8”;

### 4.ip/域名隐藏

#### 4.1 CDN

让cdn转发合法的http或者https流量来达到隐藏的目的。

[反溯源-cs和msf域名上线](https://xz.aliyun.com/t/5728)
[利用CDN隐藏C2地址](https://www.cnblogs.com/websecyw/p/11239733.html)
[使用CDN隐藏c2流量](http://blog.sern.site:8000/2020/08/03/%E4%BD%BF%E7%94%A8CDN%E9%9A%90%E8%97%8Fc2%E6%B5%81%E9%87%8F/)

- 配置了cdn
- 拥有一个公网域名
- 配置cdn的A记录解析使其能解析到C2的ip
- 将公网域名填写到cs listener的host处并填写可用的端口
- 可达到的效果：受害主机上只会有跟cdn的ip通信的流量，不会有跟真实C2通信的流量，可以保护C2的ip，但是域名还是会暴露。

技术实现重点：

```yml
一个不备案的域名，否则这个方式毫无用处
这种技术对http与https没有强制要求，都可以使用，而域前置技术要求是https
```

可以去Freenom申请一个免费的域名，有了域名后可以直接接入Cloudflare

接入后更改NS，按照Cloudflare的指示将域名的NS设置成Cloudflare的即可，这里不再赘述。

接入后配置一个DNS的A记录，解析到VPS的IP，后续上线用。

##### Cloudflare CDN配置

https配置

Cloudflare默认的TLS配置为灵活，由于之前使用了Cloudflare给原服务器发的证书，我们可以改成完全（严格）提高安全性。

禁用缓存

在这个Profile jquery-c2.4.2.profile中，我们请求的URI是以.js结尾的，Cloudflare作为一个CDN肯定要去缓存它，

但这样的话请求就无法到达我们的CS服务器，自然也就无法上线了。

添加Cloudflare规则 ，不代理js请求。
url匹配：

```yml
如果URL匹配：
xxx.xxx.com/*js

则设置为：
缓存级别   绕过
```

##### Profile配置

我们需要更改Profile中的响应头配置,不然可能会出现能上线但是无法回显命令的情况。

```yml
header "Content-Type" "application/javascript; charset=utf-8"; 修改为： header "Content-Type" "application/*; charset=utf-8";
```

即可正常执行命令回显。

```yml
./teamserver your_ip your_pass jquery-c2.4.3.profile
```

##### Listener配置

添加一个HTTPS监听器

填入三次你的域名，其他的默认就好。

在确保域名解析正确的情况下，此时HTTPS BEACON已经可以上线了

这里需要注意的是免费版的Cloudflare对代理的端口有限制。我们只能成如下端口：

```yml
http：80、8080、8880、2052、2082、2086、2095
https：443、2053、2083、2087、2096、8443
```

以上针对的是https的beacon，http的话在DNS中加一个二级域名并使用该二级域名上线即可。
不用额外再弄一个profile，因为http的beacon只看域名。

### 5.域前置

Domain Fronting，中文名域前置，是一种用于隐藏真实C2服务器IP且同时能伪装为与高信誉域名通信的技术，多用于木马受控端和控制端之间的隐蔽通信。

[域前置技术实践](https://www.anquanke.com/post/id/195011)
[域前置技术原理与在CS上的实现](https://blog.csdn.net/qq_41874930/article/details/107742843)
[域前置攻击复现|域前置水太深，偷学六娃来隐身](https://www.freebuf.com/articles/network/276159.html)
[暗度陈仓:基于国内某云的DomainFronting技术实践](https://www.anquanke.com/post/id/195011)

### 6.反向代理

受害者上只会有与重定向机器之间的流量，不会有与真实c2服务器的流量，重定向服务器会将非beacon的请求重定向到一些高信誉域名上，达到迷惑的目的。

[利用CDN、域前置、重定向三种技术隐藏C2的区别](https://blog.csdn.net/qq_41874930/article/details/109008708)

#### 6.1 Malleable C2 profile配置

以jquery-c2.4.2.profile为列 :

http全局配置中开启转发否则获取不到出网IP

```yml
http-config { set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type"; header "Server" "Apache"; header "Keep-Alive" "timeout=10, max=100"; header "Connection" "Keep-Alive"; # Use this option if your teamserver is behind a redirector set trust_x_forwarded_for "true"; ##如果您的团队服务器位于重定向器后面，请使用此选项 }
```

设置UA，可以结合UA特征过滤

```yml
set useragent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
```

#### 6.2 Nginx配置

可以使用脚本生成

<https://github.com/threatexpress/cs2modrewrite>

```yml
python3 ./cs2nginx.py -i havex.profile -c https://127.0.0.1:8443 -r https://www.baidu.com -H cdn.xxxx.club -i 为CS使用的profile模板文件 -c 为后端CS绑定的端口，这个会在后面CS的配置中有所体现 -r 为不合要求的访问302重定向去的位置，这里填了百度 -H 为你的域名，这里就是你配的那个
```

在配置完后，需要配置ssl证书

```yml
##################### # SSL Configuration ##################### listen 443 ssl; listen [::]:443 ssl; ssl on; ssl_certificate /root/tool/CS/https/server.pem; # 改这个 ssl_certificate_key /root/tool/CS/https/server.key; # 改这个 ssl_session_cache shared:le_nginx_SSL:1m; # managed by Certbot ssl_session_timeout 1440m; # managed by Certbot ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # managed by Certbot ssl_prefer_server_ciphers on; # managed by Certbot
```

同时的话还可以定制化处理location块，使得只有指定URL才能访问，保证了不会被扫到。

以User-Agent来过滤流量

```yml
location ~ ^(/jquery-3\.3\.1\.slim\.min\.js|/jquery-3\.3\.2\.min\.js|/jquery-3\.3\.1\.min\.js|/jquery-3\.3\.2\.slim\.min\.js)$ { if ($http_user_agent != "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko") { return 302 $REDIRECT_DOMAIN$request_uri; } # 把流量转到CS 监听的 HTTP port(bind) 端口上 # proxy_pass $C2_SERVER; proxy_pass https://192.168.30.10:8080; # If you want to pass the C2 server's "Server" header through then uncomment this line # proxy_pass_header Server; expires off; proxy_redirect off; proxy_set_header Host $host; # 配置nginx 转发源ip proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Real-IP $remote_addr; }
```

#### 6.3 配置防火墙

如果cs服务器和配置反向代理的Nginx的服务器是同一台，CS的listener监听的地址是0.0.0.0，

别人依旧可以直接访问我们CS监听的端口而分析出beacon信息，我们应该配置成只能让反向代理套件访问。

以iptables为例：

```yml
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 8443 -j ACCEPT iptables -A INPUT -p tcp --dport 8443 -j DROP
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 8880 -j ACCEPT iptables -A INPUT -p tcp --dport 8880 -j DROP
```

### 7. Cloudflare Workers隐藏域名

这个有点类似域前置，使用Cloudflare Workers可以隐藏我们的真实域名。

添加Works，申请好子域后创建服务，点击快速编辑, 复制如下脚本粘贴：

```yml
 let upstream = 'https://cdn.xxxx.club' # 这里写你的域名 
 addEventListener('fetch', event => { 
    event.respondWith(fetchAndApply(event.request));
    }) 
    async function fetchAndApply(request) { 
        const ipAddress = request.headers.get('cf-connecting-ip') || ''; 
        let requestURL = new URL(request.url); 
        let upstreamURL = new URL(upstream); 
        requestURL.protocol = upstreamURL.protocol; 
        requestURL.host = upstreamURL.host; 
        requestURL.pathname = upstreamURL.pathname + requestURL.pathname; 

        let new_request_headers = new Headers(request.headers); 
        new_request_headers.set("X-Forwarded-For", ipAddress); 
        let fetchedResponse = await fetch( 
            new Request(requestURL, { 
                method: request.method, 
                headers: new_request_headers, 
                body: request.body 
            }) 
        ); 
        let modifiedResponseHeaders = new Headers(fetchedResponse.headers); 
        modifiedResponseHeaders.delete('set-cookie');
        return new Response( 
            fetchedResponse.body, 
            { 
                headers: modifiedResponseHeaders, 
                status: fetchedResponse.status, 
                statusText: fetchedResponse.statusText 
            } 
        ); 
    }
```

之后使用右侧的域名替换CS中https beacon的三个域名即可

### 8.云函数隐匿真实IP

云函数，顾名思义就是在云上跑的一个函数，运行服务器由服务商提供，自带CDN效果。
那我们可以运行一个函数来转发我们的流量，就可以隐藏自己的真实IP。

参考：

[C2使用云函数进行隐藏和加速](https://mp.weixin.qq.com/s/gfBE-HaUCgQw8L0QByqTDA)
[为你的C2隐藏与加速](https://mp.weixin.qq.com/s/6nBrRJHFFpCw4N90n8aURA)

### 9.Heroku代理隐匿真实IP

参考：
[红队攻防基础建设—C2 IP隐匿技术 - 安全客，安全资讯平台](https://www.anquanke.com/post/id/238142#h2-7)

### 10.Beacon Staging特征

Beacon Staging Server就是分阶段模式中，提供shellcode等功能扩展存储的Stage服务器。

Beacon Staging Server的作用是为了防止Payload过大或者适应不同的攻击场景，可以分阶段进行payload投递。

首先通过投递一个被称为stager的小巧的payload，然后去Beacon staging server下载体积较大更复杂的stage，并且访问stage的URL通过checksum8进行校验。

由Windows Execute模块生成的就是Stager。

stager上线逻辑：

```yml
——>运行stager——>自动生成并访问符合checksum8校验的URI进行远程下载stage——>上线
```

X60的Quake主动测绘已经有了通过beacon查找C2。

具体参考<https://www.anquanke.com/post/id/224535>

nmap也可以扫出来

```yml
nmap [ip][port] --script=grab_beacon_config.nse
```

Beacon Staging特征修改方法。

- 修改源码加密的密钥 , 参考：[Bypass_cobaltstrike_beacon_config)scan](https://cloud.tencent.com/developer/article/1764340)
- 限制端口访问，让一般的扫描器扫不了出开，

这里我们可以参考上文：用nginx做反向代理，结合profile文件通过ua过滤流量；Cobalt Strike结合Nginx做反向代理

## 0x04 参考推荐

[CobaltStrike4.4汉化破解及特征去除](https://bewhale.github.io/posts/50202.html#toc-heading-25)

[Cobaltstrike去除特征](https://blog.csdn.net/shuteer_xu/article/details/110508415)

[hvv利器cs4.4修改去特征狗狗版(美化ui,去除特征,自带bypass核晶截图等..)](https://www.t00ls.com/viewthread.php?tid=66233&extra=&highlight=4.4&page=1)

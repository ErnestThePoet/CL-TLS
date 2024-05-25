# CL-TLS
## 基于ASCON的轻量级认证与传输平台设计与实现【我的毕业设计】

## 介绍
在工业互联网等环境中，终端设备计算资源有限、终端设备拓扑变化复杂，为了满足传输安全的需要，在[TLSv1.3](https://datatracker.ietf.org/doc/html/rfc8446)协议的基础之上，设计了轻量级的CL-TLS协议。CL-TLS协议简化了报文结构，引入了轻量级的ASCON-128A加密算法和ASCON-HashA哈希算法，同时使用无证书公钥密码体制(CLPKC)取代PKI机制进行身份认证。

## CL-TLS协议要点

### 应用层协议
使用CL-TLS协议的系统运行时，需要使用到如下应用层协议：
- KGC协议  

在本实现中，CL-TLS以MQTT代理服务器的形式运行，使用了下列应用层协议：
- MQTT协议
- CONNCTL协议  

KGC协议和CONNCTL协议的详细作用将在后面说明。

### CL-TLS握手流程
```
       Client                                        Server

Key  ^
Exch | ClientHello
     v                      -------->
                                                            ^ Key
                                               ServerHello  | Exch
                                                            v
                                                            ^  Server
                                       {PublicKeyRequest*}  |  Params
                                                            v
                                               {PublicKey}  ^
                                         {PublicKeyVerify}  | Auth
                            <--------           {Finished}  v
     ^ {PublicKey*}
Auth | {PublicKeyVerify*}
     v {Finished}           -------->
       [Application Data]   <------->  [Application Data]

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.
```

### 身份认证方式
CL-TLS使用基于CLPKC的方案进行身份认证。每个设备均拥有自己的身份ID和公私钥对，其中设备公私钥对由设备自身和KGC共同生成，使用KGC的私钥和设备ID即可验证设备公钥是否属于该设备。

#### 设备注册流程
- 新服务端设备注册流程
  1. 设备选取 $Seed_A\gets\\{0,1\\}^{256}$ ；
  2. 设备生成部分秘钥 $(PK_A,SK_A):=Ed25519GenKeypair(Seed_A)$ ；
  3. 设备将自身身份 $ID$ 和 $PK_A$ 发送给KGC；
  4. KGC选取 $Seed_B\gets\\{0,1\\}^{256}$ ；
  5. KGC生成部分秘钥 $(PK_B,SK_B):=Ed25519GenKeypair(Seed_B)$ ；
  6. KGC计算 $S:=Sign_{SK_{KGC}}(ID||PK_A||PK_B)$ ；
  7. KGC将 $(PK_B,SK_B,S)$ 发回设备；
  8. 设备保存公钥 $PK:=PK_A||PK_B||S$ ，私钥 $SK:=SK_A||SK_B$ 

- 新客户端设备注册流程
  1. 设备选取 $Seed_A\gets\\{0,1\\}^{256}$ ；
  2. 设备生成部分秘钥 $(PK_A,SK_A):=Ed25519GenKeypair(Seed_A)$ ；
  3. 设备将自身身份 $ID$ 和 $PK_A$ 发送给KGC；
  4. 设备将自身所属的所有服务端的身份集合 $ID_S$ 发送给KGC；
  5. KGC选取 $Seed_B\gets\\{0,1\\}^{256}$ ；
  6. KGC生成部分秘钥 $(PK_B,SK_B):=Ed25519GenKeypair(Seed_B)$ ；
  7. KGC计算 $S:=Sign_{SK_{KGC}}(ID||PK_A||PK_B)$ ；
  8. KGC通知 $ID_S$ 中的每一个服务端，添加 $ID$ 到其允许来访的身份列表中；
  9. KGC将 $(PK_B,SK_B,S)$ 发回设备；
  10. 设备保存公钥 $PK:=PK_A||PK_B||S$ ，私钥 $SK:=SK_A||SK_B$ 

特别地，当整个系统从零开始部署时，KGC的公私钥对通过以下流程生成：
- KGC公私钥对初始化生成流程
  1. KGC选取 $Seed_A\gets\\{0,1\\}^{256}$ ；
  2. KGC生成部分秘钥 $(PK_A,SK_A):=Ed25519GenKeypair(Seed_A)$ ；
  3. KGC选取 $Seed_B\gets\\{0,1\\}^{256}$ ；
  4. KGC生成部分秘钥 $(PK_B,SK_B):=Ed25519GenKeypair(Seed_B)$ ；
  5. KGC计算 $S:=Sign_{SK_A||SK_B}(ID||PK_A||PK_B)$ 
  6. KGC保存公钥 $PK:=PK_A||PK_B||S$ ，私钥 $SK:=SK_A||SK_B$ 

#### 签名和验签算法
-  $Sign_{SK_A||SK_B}(m)$ ： $S_1:=Ed25519Sign_{SK_A}(m),S_2:=Ed25519Sign_{SK_B}(m),输出S:=S_1||S_2$ 
-  $Vrfy_{PK_A||PK_B}(m,S_1||S_2)$ ： $输出Ed25519Vrfy_{PK_A}(m,S_1)\wedge Ed25519Vrfy_{SK_B}(m,S_2)$ 

#### 访问控制
除了KGC以外，每个服务端都维护一个允许对自己进行访问的设备ID列表。属于某个服务器的客户端在进行注册时，KGC将会通知该服务器添加新客户端的设备ID到自己的允许访问列表中。  
`ClientHello`消息中包含客户端的ID，服务端可以在收到后立即进行检查。

#### 身份验证
客户端和服务端在`PublicKey`消息中发送自己的公钥 $PK$ ，对方收到后通过计算 $Vrfy_{PK_{KGC}}(ID||PK_A||PK_B,S)$ 来验证公钥属于具有该 $ID$ 的设备。  
客户端和服务端在`PublicKeyVerify`消息中发送使用自己的私钥 $SK$ 签名的通信数据摘要 $S_{traffic}:=Sign_{SK}(Hash(traffic))$ ，对方收到后通过计算 $Vrfy_{PK}(Hash(traffic),S_{traffic})$ 来确定对方为公钥的持有者。  
除了新设备向KGC注册时不需要发送`PublicKey`和`PublicKeyVerify`以外，其余所有情况下连接握手时都需要验证双方身份。

### 错误处理
在整个通信过程中，如果任意一方出现错误，则向对方发送一个`Error Stop Notify`报文，其中包含错误代码，然后关闭TCP连接。对方收到后，可对错误进行展示和记录，然后终止会话。

## 代理服务器工作模式
在本实现中，CL-TLS以代理服务器的方式工作，传输MQTT应用层协议。
### 编译产物
- `cltls_client`：CL-TLS客户端代理服务器
- `cltls_server`：CL-TLS服务端程序，可以代理服务器模式运行或以KGC模式运行
- `cltls_misc_mqtt_client`：演示用的简单MQTT客户端程序
- `cltls_misc_mqtt_server`：演示用的简单MQTT服务端程序
- `cltls_misc_initializer`：KGC公私钥对生成程序

### 模块结构
```
                                      --------------------
                                      |    KGC Device    |
                                      |                  |
                                      |  --------------  |
                               -------+->|            |<-+-------
                               |      |  | KGC Server |  |      |
                               |   ---+--|            |--+---   |
                               |   |  |  --------------  |  |   |
                               |   |  |   IDk PKk SKk    |  |   |
                               |   |  --------------------  |   |
                               |   |                        |   |
 ------------------------------+---+---------     ----------+---+-----------------------------
 | Client Device               |   |        |     |         |   |              Server Device |
 |                             |   v        |     |         v   |                            |
 |  ---------------      -----------------  |     |  -----------------      ---------------  |
 |  |             |----->|               |--+-----+->|               |----->|             |  |
 |  | MQTT Client |      | CL-TLS Client |  |     |  | CL-TLS Server |      | MQTT Server |  |
 |  |             |<-----|               |<-+-----+--|               |<-----|             |  |
 |  ---------------      -----------------  |     |  -----------------      ---------------  |
 |                          IDc PKc SKc     |     |  IDs PKs SKs PermittedIDs                |
 --------------------------------------------     --------------------------------------------
```

### 工作流程
下面说明一个最简系统的工作流程，该系统由一个KGC设备、一个客户端设备和一个服务端设备组成。

- KGC设备
  - IP地址：`192.168.7.60`
  - ID：`ECECECECECECECEC`
  - 目录结构（除可执行文件外，均为空文件）：
```
cltls
|---kgc
|   |---cltls_server
|   |---config.conf
|   |---permitted_ids.txt
|
|---common
|   |---idip.txt
|
|---cltls_misc_initializer
```

- 客户端设备
  - IP地址：`192.168.7.120`
  - ID：`AA00000000000001`
  - 目录结构（除可执行文件外，均为空文件）：
```
cltls
|---client
|   |---cltls_client
|   |---config.conf
|   |---bs.txt
|
|---common
|   |---idip.txt
|   |---kgc_pubkey.key
|
|---cltls_misc_mqtt_client
```

- 服务端设备
  - IP地址：`192.168.7.180`
  - ID：`BB00000000000001`
  - 目录结构（除可执行文件外，均为空文件）：
```
cltls
|---server
|   |---cltls_server
|   |---config.conf
|   |---permitted_ids.txt
|
|---common
|   |---idip.txt
|   |---kgc_pubkey.key
|
|---cltls_misc_mqtt_server
```

#### 初始化
在从零部署CL-TLS应用环境时，首先使用的`cltls_misc_initializer`程序为KGC生成公私钥对。在KGC设备的`cltls`目录内，执行`./cltls_misc_initializer kgc`，即可生成KGC公私钥对文件`pubkey.key`和`privkey.key`并把它们存储在`kgc`子目录中。同时，将`pubkey.key`分发到所有其他设备的`cltls/common`目录中，命名为`kgc_pubkey.key`。  
类似DNS系统，CL-TLS代理服务器使用一个本地维护的数据库文件来存储从设备ID到设备IP地址的映射关系。在每个设备的`cltls/common`目录内，都新建一个`idip.txt`，内容为：
```
ECECECECECECECEC 192.168.7.60
AA00000000000001 192.168.7.120
BB00000000000001 192.168.7.180
```
虽然在本示例中客户端设备不会被其他设备主动连接，但仍然将其ID/IP映射加入到数据库中，为以后在设备上同时运行服务端的可能做好准备。

#### 启动KGC
编辑KGC服务器的配置文件`cltls/kgc/config.conf`：
```
IDENTITY=ECECECECECECECEC
PUBLIC_KEY=pubkey.key
PRIVATE_KEY=privkey.key
KGC_PUBLIC_KEY=pubkey.key
IDIP_DATABASE=../common/idip.txt
PERMITTED_IDS_DATABASE=permitted_ids.txt
SOCKET_BLOCK_SIZE=2097152
```
注意KGC在握手阶段不检查客户端ID，允许所有客户端建立连接，其`permitted_ids.txt`内容为空。  
保存配置后，进入`cltls/kgc`目录，执行`./cltls_server -m KGC`即可运行KGC。

#### 注册并启动服务端设备
编辑服务端的配置文件`cltls/server/config.conf`：
```
IDENTITY=BB00000000000001
PUBLIC_KEY=pubkey.key
PRIVATE_KEY=privkey.key
KGC_PUBLIC_KEY=../common/kgc_pubkey.key
IDIP_DATABASE=../common/idip.txt
PERMITTED_IDS_DATABASE=permitted_ids.txt
SOCKET_BLOCK_SIZE=2097152
```
保存配置后，进入`cltls/server`目录，执行`./cltls_server -r`即可完成注册，此时服务端得到的公私钥对已经被存储在了配置文件里指定的文件中。  
首先启动服务器设备上的MQTT服务端程序。回到`cltls`目录，执行`./cltls_misc_mqtt_server 22601`。  
然后进入`cltls/server`，启动CL-TLS服务端：`./cltls_server -m PROXY -p 22600 --fwd-ip 127.0.0.1 --fwd-port 22601`  
CL-TLS服务端还支持的可选选项是：
- `-l, --log=<str>`：日志打印级别，可为`ERROR|WARN|INFO`之一，默认为`INFO`；
- `--cipher=<str>`：优先使用的密码学算法套件，可为`ASCON128A_ASCONHASHA|ASCON128A_SHA256|AES128GCM_ASCONHASHA|AES128GCM_SHA256`之一，默认为`ASCON128A_ASCONHASHA`。服务端设备可以通过此选项选择在自身平台上性能或资源占用最佳的算法套件；
- `-c, --config=<str>`：配置文件路径，默认为`config.conf`；
- `-t, --timing`：是否打印握手和MQTT代理转发耗时，默认不打印。

#### 注册并启动客户端设备
编辑客户端的配置文件`cltls/client/config.conf`：
```
IDENTITY=AA00000000000001
PUBLIC_KEY=pubkey.key
PRIVATE_KEY=privkey.key
KGC_PUBLIC_KEY=../common/kgc_pubkey.key
IDIP_DATABASE=../common/idip.txt
SOCKET_BLOCK_SIZE=2097152
```
保存配置后，再编辑客户端所属的服务器ID及其代理服务器端口号列表文件`cltls/client/bs.txt`：
```
BB00000000000001 22600
```
此文件中服务端的代理服务器端口号仅用于注册阶段KGC向服务器发起连接。  
进入`cltls/client`目录，执行`./cltls_client -r --bs bs.txt`即可完成注册，此时客户端得到的公私钥对已经被存储在了配置文件里指定的文件中，所属的服务端也将本客户端的ID加入到了允许来访的ID列表中。  
然后即可启动CL-TLS客户端：`./cltls_client -p 23600`  
回到`cltls`目录，启动MQTT客户端程序：`./cltls_misc_mqtt_client 127.0.0.1 23600`  
CL-TLS客户端还支持的可选选项是：
- `-l, --log=<str>`：日志打印级别，可为`ERROR|WARN|INFO`之一，默认为`INFO`；
- `-c, --config=<str>`：配置文件路径，默认为`config.conf`；
- `-t, --timing`：是否打印握手和MQTT代理转发耗时，默认不打印。

#### 进行安全通信
在MQTT客户端内，输入`CONN BB00000000000001 22600`并回车。MQTT客户端会给CL-TLS客户端发送一个`CONNCTL`协议的`Connect Request`消息，CL-TLS客户端会在ID/IP表中查找到服务器IP后与CL-TLS服务端建立TCP连接并进行握手，完成后CL-TLS服务端会与本地MQTT服务端建立连接。上述流程均成功后，CL-TLS服务端会发回`CONNCTL`协议的`Connect Response`消息，状态代码为成功。CL-TLS客户端收到后，会向MQTT客户端发送一个`CONNCTL`协议的`Connect Response`消息，状态代码为成功。然后即可开始在MQTT客户端内传输数据了。  
输入`PUBLISH 32`并回车，客户端将发出一个载荷大小为32字节的MQTT PUBLISH消息并打印载荷内容。收到服务端的MQTT PUBLISH响应后，消息载荷也会被打印出来。可以对比服务端所打印的载荷内容，验证消息被正确传输。  
然后再输入`PUBLISH 268435455`并回车，将发送一个载荷大小为`256MB-1`的MQTT PUBLISH消息，这也是单个MQTT消息能承载的最大载荷大小，将会打印消息首尾16字节的数据。CL-TLS客户端和服务端配置文件中的`SOCKET_BLOCK_SIZE`选项指定了套接字收发时的最大块长度，超过此长度的消息将被分成多块收发，以控制收发双方用于套接字收发的缓冲区大小。  
最后，输入`DISCONNECT`并回车，整个会话将结束。

#### 使用MQTT GUI程序进行安全通信
[CLTLS-MQTT-GUI](https://github.com/ErnestThePoet/CLTLS-MQTT-GUI)是配套CL-TLS代理服务器的MQTT GUI演示程序，可以可视化地进行MQTT数据的安全传输。使用方法请见该仓库内的README。

## 使用到的开源项目
- [ascon/ascon-c](https://github.com/ascon/ascon-c)
- [boringssl/boringssl](https://boringssl.googlesource.com/boringssl)
- [cofyc/argparse](https://github.com/cofyc/argparse)
- [glouw/ctl](https://github.com/glouw/ctl)

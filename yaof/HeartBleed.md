# <center>openssl心脏出血漏洞分析文档</center> #
### <center>版本\<1.0\></center> ###
## 修订历史记录 ##
|日期|版本|说明|作者|
|---|---|---|----|
|2016/07/18|\<1.0\>|openssl心脏出血漏洞分析文档|姚飞|
|2016/07/22|\<1.0\>|文档改进|姚飞|
## 目录 ##
1.&emsp;&emsp;简介<br>&emsp;&emsp;1.1&emsp;&emsp;目的<br>&emsp;&emsp;1.2&emsp;&emsp;范围

# <center>协议分析文档</center> #
## 1.&emsp;简介 ##
### 1.1&emsp;目的 ###
&emsp;&emsp;&emsp;描述和分析openssl心脏出血漏洞的具体流程，数据包结构及检测方法
### 1.2&emsp;范围 ###
&emsp;&emsp;&emsp;应用SSL协议进行加密且协议中含有心跳扩展机制的数据
### 1.3&emsp;定义、首字母缩写词和缩略语 ###
&emsp;&emsp;&emsp;略。
### 1.4&emsp;参考资料 ###
&emsp;&emsp;&emsp;[Openssl "心血" 漏洞分析](http://www.freebuf.com/articles/web/31553.html "http://www.freebuf.com/articles/web/31553.html").<br />
&emsp;&emsp;&emsp;[Ubuntu下Apache https安装和配置](http://blog.csdn.net/newjueqi/article/details/9789659 "http://blog.csdn.net/newjueqi/article/details/9789659").<br />
&emsp;&emsp;&emsp;[Openssl漏洞POC学习](http://blog.csdn.net/youfuchen/article/details/23279547 "http://blog.csdn.net/youfuchen/article/details/23279547").<br />
### 1.5&emsp;概述 ###
&emsp;&emsp;&emsp;OpenSSL在实现TLS和DTLS的心跳处理逻辑时，存在编码缺陷。OpenSSL的心跳处理逻辑没有检测心跳包中的长度字段是否和后续的数据字段相符合，攻击者可以利用这一点，构造异常的数据包，来获取心跳数据所在的内存区域的后续数据。这些数据中可能包含了证书私钥，用户名，用户密码，用户邮箱等敏感信息。该漏洞允许攻击者从内存中读取多达64KB的数据。
### 1.6&emsp;解码方法 ###
&emsp;&emsp;&emsp;对base64编码进行解码,在python27命令行下：<br>&emsp;&emsp;&emsp;<code>import base64</code><br>&emsp;&emsp;&emsp;<code>base64.b64decode(‘’)</code>

## 2.&emsp;协议简介 ##
### 2.1&emsp;协议分析范围 ###
&emsp;&emsp;&emsp;对应用TLS/DTLS的心跳处理机制的安全传输协议进行分析。
### 2.2&emsp;定义（术语、名词解释） ###
&emsp;&emsp;&emsp;客户端：进行心脏出血攻击的计算机<br>
&emsp;&emsp;&emsp;服务端：存在心脏出血漏洞OpenSSL版本的Ubuntu虚拟机服务器
## 3.&emsp;协议交互流程 ##
&emsp;&emsp;&emsp;客户端发送一段心跳包中的长度字段和后续的数字字段不相符合的Request请求包，服务器端对客户端进行响应返回一定长度的隐秘信息。
## 4.&emsp;数据包格式 ##
&emsp;&emsp;&emsp;
SSL(Secure Socket Layer 安全套接层)及其继任者传输层安全（Transport Layer Security，TLS）是为网络通信提供安全及数据完整性的一种安全协议。TLS和SSL在传输层对网络连接进行加密。所以通过SSL或TLS协议加密后的数据包再通过wireshark软件进行对数据包的抓取时，抓取到的数据也是经过加密处理的数据。<br>
&emsp;&emsp;&emsp;DTLS(Datagram Transport Layer Security)数据包传输层安全协议。TLS不能用来保证UDP上传输的数据的安全，因此Datagram TLS试图在现存的TLS协议架构上提出扩展，使之支持UDP，即成为TLS的一个支持数据报传输的版本。DTLS1.0基于TLS1.1，DTLS1.2基于TLS1.2<br>
&emsp;&emsp;&emsp;心脏出血漏洞主要通过攻击者模拟向服务器端发送自己编写的Heartbeat心跳数据包，主要是HeartbeatMessage的长度与payload的length进行匹配，若payload_lenght长度大于HeartbeatMes sage的length，则会在服务器返回的response响应包中产生数据溢出，造成有用数据泄露。

**TLS数据包格式**

|心跳包字段|长度|说明
|------|---|---|
|ContentType|1byte|心跳包类型，IANA组织把type编号定义为24（0x18）|
|ProtocolVersion|2bytes|TLS的版本号，目前主要包括含有心跳扩展的TLS版本：TLSv1.0，TLSv1.1，TLSv1.2|
|length|2bytes|HeartbeatMessage的长度|
|HeartbeatMessageType|1byte|Heartbeat类型 01表示heartbeat_request 02表示heartbeat_response|
|payload_length|2bytes|payload长度|
|payload|payload_length个bytes|payload的具体内容|
|padding|>=16bytes|padding填充，最少为16个字节|

**DTLS数据包格式**

|心跳包字段|长度|说明
|---------|---|---|
|ContentType|1byte|心跳包类型，IANA组织把type编号定义为24（0x18）|
|ProtocolVersion|2bytes|DTLS的版本号，DTLS1.0基于TLS1.1，DTLS1.2基于TLS1.2|
|epoch|2bytes|为一个计数器，每一个加密状态改变时加一。主要用来区分在一个多次重新协商的情况，多个记录包文可能会具有相同的序列号，因此再用这个域来区分，接收者可以用来区分不同的包。epoch初始值为0，每发送一个changeCipherSpec消息后加一|
|sequence_number|6bytes|记录层的序列号，在每一个ChangeCipherSpec消息发送之后，sequence_number都设置为0|
|length|2bytes|HeartbeatMessage的长度|
|HeartbeatMessageType|1byte|Heartbeat类型 01表示heartbeat_request 02表示heartbeat_response|
|payload_length|2bytes|payload长度|
|payload|payload_length个bytes|payload的具体内容|
|padding|>=16bytes|padding填充，最少为16个字节|

### 4.1&emsp;探测数据包 ###
&emsp;&emsp;&emsp;心脏出血漏洞必须在含有心跳扩展和漏洞没有被修复的版本中存在，目前存在OpenSSL心血漏洞的OpenSSL版本有OpenSSL1.0.1，1.0.1a，1.0.1b，1.0.1c，1.0.1d，1.0.1e，1.0.1f，Beta 1 of OpenSSL1.0.2等。具体流程如下：

* 搭建含有OpenSSL心脏出血漏洞靶机环境（具体靶机搭建操作详情请看文档：heartbleed靶机环境搭建）
* 搭建拥有数据交互的https网站（Apache+MySQL+PHP5+HTTPS）
* 心脏出血漏洞主要存在于OpenSSL的心跳机制里，判断OpenSSL有没有开启心跳扩展，并开启心跳扩展机制。
* 在客户端对虚拟机中搭建的靶场页面进行访问，同时在客户端中通过POC程序对靶场进行攻击
* 通过wireshark对攻击的请求包和响应包进行捕获

#### 4.1.1 请求包 ####
<br>
**TLS数据包(Hex)**
>![Alt text](/heartbleed_request.png)
><font color=red>**18 03 02 00 03 01 40 00**</font>
<br>

**分析**
<br>
>由于SSL记录协议位于某个可靠的传输协议（例如TCP）上面由于数据通过SSL加密处理后显示乱码，我们通过wireshark抓取的数据包主要通过16进制显示，所以像heartbeat_Request的数据包主要分为四部分：（1）数据包帧头部分（在数据包中占14个字节）<br>
>（2）IPv4网络层部分（数据包中占20字节）<br>
>（3）TCP传输层部分（数据包中占20字节）<br>
>图片中方框标注的部分即为通过SSL加密的心跳数据包部分：<br>
>Content Type：Heartbeat 24(<font color=red>0x18</font>)<br>Version：TLS1.1(<font color=red>0x0302</font>)<br>Length：3(<font color=red>0x0003</font>)<br>HeartbeatMessage:<br>Type:Request(<font color=red>0x01</font>)<br>payload Length:16384(<font color=red>0x4000</font>)<br>payload<br>padding and HMAC<br>
>payload和padding都为空，利用漏洞将后面内存中的数据dump下来
#### 4.1.2 响应包 ####
<br>
**TLS数据包（Hex）**
![Alt text](/heartbleed_response.png)
<br>
><font color=red>**18 03 02 40 00 02 40 00**</font> d8 03 02 53 43 5b 90 9d  ...@..@....SC[..<br>9b 72 0b bc 0c bc 2b 92 a8 48 97 cf bd 39 04 cc  .r....+..H...9..<br>16 0a 85 03 90 9f 77 04 33 d4 de 00 00 66 c0 14  ......w.3....f..<br>c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f  ...".!.9.8......<br>c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16  ...5............<br>00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e  ................<br>00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04  .3.2.....E.D....<br>00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05  ./...A..........<br>00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06  ................<br>00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02  .......I........<br>00 0a 00 34 00 32 00 0e 00 0d 00 19 00 0b 00 0c  ...4.2..........<br>00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07  ................<br>00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02  ................<br>00 03 00 0f 00 10 00 11 00 23 00 00 00 0f 00 01  .........#......<br>01 6b 87 3c 2a f7 db 30 ef 5c d2 68 0f 8b c6 10  .k.<\*..0.\.h....<br>37 2e 33 36 0d 0a 41 63 63 65 70 74 3a 20 74 65  7.36..Accept: te<br>78 74 2f 68 74 6d 6c 2c 61 70 70 6c 69 63 61 74  xt/html,applicat<br>69 6f 6e 2f 78 68 74 6d 6c 2b 78 6d 6c 2c 61 70  ion/xhtml+xml,ap<br>70 6c 69 63 61 74 69 6f 6e 2f 78 6d 6c 3b 71 3d  plication/xml;q=<br>30 2e 39 2c 69 6d 61 67 65 2f 77 65 62 70 2c 2a  0.9,image/webp,*<br>2f 2a 3b 71 3d 30 2e 38 0d 0a 52 65 66 65 72 65  /\*;q=0.8..Refere<br>72 3a 20 68 74 74 70 73 3a 2f 2f 31 39 32 2e 31  r: https://192.1<br>36 38 2e 31 39 37 2e 31 32 38 2f 63 68 65 63 6b  68.197.128/check<br>2e 70 68 70 3f 6e 61 6d 65 3d 79 61 6f 66 65 69  .php?name=yaofei<br>26 70 61 73 73 77 6f 72 64 3d 31 32 33 34 35 36  &password=123456<br>0d 0a 41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e  ..Accept-Encodin<br>67 3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65  g: gzip, deflate<br>2c 20 73 64 63 68 2c 20 62 72 0d 0a 41 63 63 65  , sdch, br..Acce<br>70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d  pt-Language: zh-<br>43 4e 2c 7a 68 3b 71 3d 30 2e 38 0d 0a 0d 0a 9d  CN,zh;q=0.8.....<br>47 d4 f2 b4 2e dc 63 f7 4c 28 bb 43 71 41 ca 00  G.....c.L(.CqA..<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................<br>

**分析**
<br>
>(上图中为通过wireshark抓取的heartbeat_Response数据包的模块化展示，同样数据包分为帧头部分，IPv4网络层部分，TCP传输层部分以及SSL返回的数据部分)<br>
>图下数据为返回的心跳数据包详情展示，由于数据长度为16384个字节太长不好显示这边只截取一部分数据进行展示<br>
><font color=red>**18 03 02 40 00 02 40 00**</font>为响应包数据特征：<br>
>0x18表示SSL数据包类型为心跳包<br>
>0x0302表示TLS的版本号：Version（TLSv1.1）<br>
>0x4000表示返回的数据包长度（16384）<br>
>0x02表示返回的心跳消息类型（Response）<br>
>0x4000表示返回的payload_length(16384)<br>
>剩余的数据即为通过心脏出血漏洞从内存中dump下来的数据（payload和padding）
>由于请求包（Request）中的长度为0x0003（3）但是要返回的payload_length为0x4000（16384），所以响应包（Response）返回的数据长度为0x4000（16384）即漏洞攻击成功。
</blockquote>
## 5.&emsp;特征总结 ##
&emsp;&emsp;&emsp;OpenSSL心脏出血漏洞(heartbleed)的产生主要由于OpenSSL的心跳处理逻辑没有检测心跳包中的长度字段是否和后续字段相吻合导致攻击者构造异常数据包，来直接获取心跳数据所在的内存区域的后续数据。主要特征有：

* heartbleed漏洞主要存在于有心跳机制的OpenSSL协议中。
* IANA组织把开启心跳扩展机制的SSL数据包type类型定义为24（0x18）。
* heartbleed漏洞主要存在于TLS和DTLS两种协议中，在含有heartbleed漏洞的OpenSSL协议中需要开启心跳扩展机制（beartbeat），而含有心跳扩展机制的TLS版本主要包含在TLSv1.0（0x0301），TLSv1.1（0x0302），TLSv1.2（0x0303）三种版本中。
* heartbleed漏洞攻击主要由于攻击者构造异常的心跳数据包，即心跳包中的长度字段与后续的数据字段不相符合，来获取心跳数据所在的内存区域的后续数据。

&emsp;&emsp;&emsp;综上所述我们可以通过对线网中的数据首先进行判断是否为含有OpenSSL的数据包，同时通过对数据包中的type类型判断数据包是否为心跳数据包，然后对TLS的版本进行匹配找到相应的含有心跳扩展机制的心跳数据包，最后通过对心跳包中的数据实际长度与长度字段定义的值比较，如果实际长度小于定义的长度则该数据包即为含有heartbleed漏洞的数据包。
## 6.&emsp;含有SSL加密的协议 ##
|协议|默认端口|说明
|-----|----|----|
|SMTPS|465|(SMTP-over-SSL)协议发送邮件协议|
|HTTPS|443|安全套接字层超文本传输协议|
|NNTPS|563|通过安全套接字层的网络新闻传输协议|
|LDAPS|636|通过安全套接字层的轻型目录访问协议|
|ftps|990|通过ssl加密的ftp协议|
|IMAPS|993|邮件接收协议|
|POP3S|995|邮件接收协议|
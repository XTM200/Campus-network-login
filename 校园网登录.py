import requests,bs4,time,hashlib,hmac,base64,math,re
from urllib import parse

ur1='http://10.10.10.3/v2/srun_portal_message?'
ur2='http://10.10.10.3/cgi-bin/rad_user_info?'
ur3='http://10.10.10.3/v1/srun_portal_log?'
ur4='http://10.10.10.3/cgi-bin/get_challenge?'
ur5='http://10.10.10.3/cgi-bin/srun_portal?'
ur6='http://10.10.10.3/v1/srun_portal_detect'

cs={
     'enc':'srun_bx1',
     'ac_id':'1',
     'ip':'',
     'n':'200',
     'Type':'1',
     'username':'账号名',
     'password':'密码',
     'token':'',
     }

header={
     'Accept':'*/*',
     'Accept-Encoding':'gzip, deflate',
     'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
     'Connection':'keep-alive',
     'Cookie':'网页登录的Cookie',#不一定是必须
     'Host':'10.10.10.3',
     'Referer':'http://10.10.10.3/srun_portal_pc?ac_id=1&theme=pro',
     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.26',
     'X-Requested-With':'XMLHttpRequest'
     }


error='not_online_error'
a1=0
while error == 'not_online_error' and a1<3:
     code=99
     a2=0
     while code!='0' and a2<3:
         #第一个请求
         param=ur1+'per-page=100'
         html=requests.get(param,header)
         print(html)
         html=bs4.BeautifulSoup(html.text,'html.parser')
         code=re.search('"code":(.*?),',html.text).group(1)
         print(html)
         a2=a2+1
     a1=a1+1
     #第二个请求//获取ip
     headers=header
     headers['Accept']='text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01'

     data2={
         'callback':'',
         '_':''
            }
     data2['callback']='jQuery112406965263917347384_'+str(int(time.time()*1000))
     data2['_']=int(time.time()*1000)
     #字典连接
     def zdcl(url,data):
         datc=''
         for key,value in data.items():
             date=str(key) + '='  + str(value)
             datc=datc+'&'+date
             datc=datc.strip('&')
         data=url + datc
         return data
     param=zdcl(ur2,data2)

     html=requests.get(param,headers)
     print(html)
     html=bs4.BeautifulSoup(html.text,'html.parser')
     print(html)
     cs['ip']=re.search('"online_ip":"(.*?)"',html.text).group(1)
     error=re.search('"error":"(.*?)"',html.text).group(1)
     if error=='not_online_error':
         sign='sign_error'
         a3=0
         while sign =='sign_error'and a3<3:
             a3=a3+1
             #第三个请求

             data3='username'+'='+cs['username']
             param=ur3+data3

             html=requests.get(param,header)
             print(html)
             html=bs4.BeautifulSoup(html.text,'html.parser')
             print(html)
             #第四个请求//获取token值

             data4={
                 'callback':data2['callback'],
                 'username':cs['username'],
                 'ip':cs['ip'],
                 '_':data2['_']+1
                 }
             param=zdcl(ur4,data4)
             html=requests.get(param,header)
             print(html)
             html=bs4.BeautifulSoup(html.text,'html.parser')
             print(html)
             cs['token']=re.search('"challenge":"(.*?)"',html.text).group(1)
             #sign=re.search('"error":"(.*?)"',html.text).group(1)
             #第五个请求

             #MD5加密
             def MD5(cs):
                 token=cs['token']
                 password=cs['password']
                 return hmac.new(token.encode(),password.encode(),hashlib.md5).hexdigest()
             cs['hmd5']=MD5(cs)
             #参数i
             def gjencodecs(cs):
                 info={}
                 info['username']=cs['username']
                 info['password']=cs['password']
                 info['ip']=cs['ip']
                 info['acid']=cs['ac_id']
                 info['enc_ver']=cs['enc']
                 i=re.sub("'",'"',str(info))
                 i=re.sub(" ",'',i)
                 return i
             #函数encode   函数名get_xencode
             def force(msg):
                 ret = []
                 for w in msg:
                     ret.append(ord(w))
                 return bytes(ret)
             def ordat(msg, idx):
                 if len(msg) > idx:
                     return ord(msg[idx])
                 return 0
             def sencode(msg, key):
                 l = len(msg)
                 pwd = []
                 for i in range(0, l, 4):
                     pwd.append(
                         ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
                         | ordat(msg, i + 3) << 24)
                 if key:
                      pwd.append(l)
                 return pwd
             def lencode(msg, key):
                 l = len(msg)
                 ll = (l - 1) << 2
                 if key:
                     m = msg[l - 1]
                     if m < ll - 3 or m > ll:
                         return
                     ll = m
                 for i in range(0, l):
                     msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                         msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
                 if key:
                     return "".join(msg)[0:ll]
                 return "".join(msg)
             def get_xencode(msg, key):
                 if msg == "":
                     return ""
                 pwd = sencode(msg, True)
                 pwdk = sencode(key, False)
                 if len(pwdk) < 4:
                     pwdk = pwdk + [0] * (4 - len(pwdk))
                 n = len(pwd) - 1
                 z = pwd[n]
                 y = pwd[0]
                 c = 0x86014019 | 0x183639A0
                 m = 0
                 e = 0
                 p = 0
                 q = math.floor(6 + 52 / (n + 1))
                 d = 0
                 while 0 < q:
                     d = d + c & (0x8CE0D9BF | 0x731F2640)
                     e = d >> 2 & 3
                     p = 0
                     while p < n:
                         y = pwd[p + 1]
                         m = z >> 5 ^ y << 2
                         m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                         m = m + (pwdk[(p & 3) ^ e] ^ z)
                         pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                         z = pwd[p]
                         p = p + 1
                     y = pwd[0]
                     m = z >> 5 ^ y << 2
                     m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                     m = m + (pwdk[(p & 3) ^ e] ^ z)
                     pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
                     z = pwd[n]
                     q = q - 1
                 return lencode(pwd, False)
             token=cs['token']
             print(cs)
             info=gjencodecs(cs)
             f=get_xencode(info,token)
             #base64转码
             _PADCHAR = "="
             _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
             def _getbyte(s, i):
                 x = ord(s[i]);
                 if (x > 255):
                     print("INVALID_CHARACTER_ERR: DOM Exception 5")
                     exit(0)
                 return x
             def get_base64(s):
                 i=0
                 b10=0
                 x = []
                 imax = len(s) - len(s) % 3-1;
                 if len(s) == 0:
                     return s
                 for i in range(0,imax,3):
                     b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2);
                     x.append(_ALPHA[(b10 >> 18)]);
                     x.append(_ALPHA[((b10 >> 12) & 63)]);
                     x.append(_ALPHA[((b10 >> 6) & 63)]);
                     x.append(_ALPHA[(b10 & 63)])
                 i=imax
                 if len(s) - imax ==1:
                     b10 = _getbyte(s, i) << 16;
                     x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR);
                 else:
                     b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
                     x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR);
                 return "".join(x)
             i='{SRBX1}'+get_base64(f)[0:144]
             cs['i']=i
             #字符连接
             def zflj(cs):
                  a = cs['token']
                  a = a + cs['username']
                  a += cs['token'] + cs['hmd5']
                  a += cs['token'] + cs['ac_id']
                  a += cs['token'] + cs['ip']
                  a += cs['token'] + cs['n']
                  a += cs['token'] + cs['Type']
                  a += cs['token'] + cs['i']
                  return a
             zflj=zflj(cs)
             def chksum(a):
                  a=a.encode()
                  return hashlib.sha1(a).hexdigest()
             chksum=chksum(zflj)
             data5={
                  'callback':data4['callback'],
                  'action':'login',
                  'username':header['username'],
                  'password':parse.quote('{MD5}'+cs['hmd5']),
                  'os':'Windows+10',
                  'name':'Windows',
                  'double_stack':'0',
                  'chksum':chksum,
                  'info':parse.quote(i).replace('/','%2F'),
                  'ac_id':'1',
                  'ip':cs['ip'],
                  'n':'200',
                  'type':'1',
                  '_':data4['_']+1
                  }

             param=zdcl(ur5,data5)
             html=requests.get(param,headers)
             print(html)
             html=bs4.BeautifulSoup(html.text,'html.parser')
             print(html)
             sign=re.search('"error":"(.*?)"',html.text).group(1)

     #第八个请求
     param=ur6

     html=requests.get(param,header)
     print(html)
     html=bs4.BeautifulSoup(html.text,'html.parser')
     print(html)





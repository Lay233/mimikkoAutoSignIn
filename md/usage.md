```
usage: mimikko.py [-h] [-u ID] [-p password] [-a Token] [-e code] [-r resign] [-s SCKEY] [-d token] [-c secret] [-i CompanyId] [-x Secret] [-w AgentId]

兽耳助手自动签到 使用说明：

optional arguments:
  -h, --help    show this help message and exit
  -u ID         登录账号(邮箱或手机号)
  -p password   登录密码
  -a Token      AUTHORIZATION验证，抓包获取
  -e code       助手代码
  -r resign     补签最近1~7天
  -s SCKEY      server酱推送密钥
  -d token      钉钉机器人token
  -c secret     钉钉机器人安全设置加签的secret
  -i CompanyId  企业微信推送CompanyId
  -x Secret     企业微信推送Secret
  -w AgentId    企业微信推送AgentId

请从 登录账号(-u)和密码(-p) 或 AUTHORIZATION验证(-a) 中选择一种登录方式
```
# -*- coding: UTF-8 -*-
"""
 * @author  cyb233
 * @date  2021/1/9
"""
import sys
import time
import requests
import re
import json
import argparse
import hashlib
import hmac
import base64
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    parser = argparse.ArgumentParser(description='请从 登录账号(-u)和密码(-p) 或 AUTHORIZATION验证(-a) 中选择一种登录方式')

    parser.add_argument('-u', default=False, metavar='ID', help='登录账号(邮箱或手机号)')
    parser.add_argument('-p', default=False, metavar='password', help='登录密码')
    parser.add_argument('-a', default=False, metavar='Token', help='AUTHORIZATION验证，抓包获取')
    parser.add_argument('-e', default='momona', metavar='code', help='助手代码，选择助手')
    parser.add_argument('-r', default=False, metavar='resign', type=int, help='补签最近x天，可选数字1~7')
    parser.add_argument('-s', default=False, metavar='sckey', help='server酱推送密钥')
    parser.add_argument('-d', default=False, metavar='token', help='钉钉机器人token')
    parser.add_argument('-c', default=False, metavar='secret', help='钉钉机器人安全设置加签的secret')
    parser.add_argument('-i', default=False, metavar='CompanyId', help='企业微信推送CompanyId')
    parser.add_argument('-x', default=False, metavar='Secret', help='企业微信推送Secret')
    parser.add_argument('-w', default=False, metavar='AgentId', help='企业微信推送AgentId')

    args =  parser.parse_args()

    print('正在获取secret参数')
    user_id = args.u
    user_password = args.p
    Authorization = args.a
    Energy_code = args.e
    resign = args.r
    if resign > 7:
        resign = 7
    elif resign < 1:
        resign = False
    SCKEY = args.s
    DDTOKEN = args.d
    if DDTOKEN and DDTOKEN.find('access_token=') != -1:
        DDTOKEN = DDTOKEN[DDTOKEN.find('access_token=')+13:]
    DDSECRET = args.c
    wxAgentId = args.i
    wxSecret = args.x
    wxCompanyId = args.w
    
    if user_id:
        user_id = user_id.strip()
        print('user_id 存在')
    if user_password:
        user_password = user_password.strip()
        print('user_password 存在')
    if Authorization:
        Authorization = Authorization.strip()
        print('Authorization 存在')
    if not Authorization and not (user_id and user_password):
        sys.exit('获取参数错误：请在Secret中保存 登录ID和密码 或 Authorization ！！！')
    if Energy_code:
        Energy_code = Energy_code.strip()
        print('Energy_code 存在')
    if resign:
        print('resign 存在')
    if SCKEY:
        SCKEY = SCKEY.strip()
        print('SCKEY 存在')
    if DDTOKEN:
        DDTOKEN = DDTOKEN.strip()
        print('DDTOKEN 存在')
    if DDSECRET:
        DDSECRET = DDSECRET.strip()
        print('DDSECRET 存在')
    if wxAgentId:
        wxAgentId = wxAgentId.strip()
        print('wxAgentId 存在')
    if wxSecret:
        wxSecret = wxSecret.strip()
        print('wxSecret 存在')
    if wxCompanyId:
        wxCompanyId = wxCompanyId.strip()
        print('wxCompanyId 存在')
    print('获取参数结束')
except Exception as es:
    print('获取参数错误：', es)
    sys.exit(1)

login_path = 'https://api1.mimikko.cn/client/user/LoginWithPayload' # 登录(post)
is_sign = 'https://api1.mimikko.cn/client/user/GetUserSignedInformation' # 今天是否签到
history_path = 'https://api1.mimikko.cn/client/dailysignin/log/30/0' # 签到历史
can_resign = 'https://api1.mimikko.cn/client/love/getcanresigntimes' # 补签卡数量
defeat_set = 'https://api1.mimikko.cn/client/Servant/SetDefaultServant' # 设置默认助手
resign_path = 'https://api1.mimikko.cn/client/love/resign?servantId=' # 补签(post)
sign_path = 'https://api1.mimikko.cn/client/RewardRuleInfo/SignAndSignInformationV3' # 签到
energy_info_path = 'https://api1.mimikko.cn/client/love/GetUserServantInstance' # 获取助手状态
energy_reward_path = 'https://api1.mimikko.cn/client/love/ExchangeReward' # 兑换助手能量
vip_info = 'https://api1.mimikko.cn/client/user/GetUserVipInfo' # 获取会员状态
vip_roll = 'https://api1.mimikko.cn/client/roll/RollReward' # 会员抽奖(post)
sc_api = 'https://sc.ftqq.com/' #Server酱推送
sct_api = 'https://sctapi.ftqq.com/' #Server酱推送Turbo版
ding_api = 'https://oapi.dingtalk.com/robot/send?' # 钉钉推送
app_Version = '3.1.6'
app_id = 'wjB7LOP2sYkaMGLC'
servant_name = {
    'nonona':'诺诺纳',
    'momona':'梦梦奈',
    'ariana':'爱莉安娜',
    'miruku':'米璐库',
    'nemuri':'奈姆利',
    'ruri':'琉璃',
    'alpha0':'阿尔法零',
    'miruku2':'米露可',
    'ulrica':'优莉卡',
    'giwa':'羲和',
    'maya':'摩耶'
}
# 登录post
def loginRequest_post(url, app_id, app_Version, params):
    params_post = params
    headers_post = {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'AppID': app_id,
        'Version': app_Version,
        'Content-Type': 'application/json',
        'Host': 'api1.mimikko.cn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.1',
    }
    try:
        with requests.post(url, headers=headers_post, data=params_post, verify=False, timeout=300) as resp:
            res = resp.json()
            return res
    except Exception as exl:
        print(exl)
# get请求
def apiRequest_get(url, app_id, app_Version, Authorization, params):
    params_get = params
    headers_get = {
        'Cache-Control': 'Cache-Control:public,no-cache',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'Mozilla/5.0(Linux;Android6.0.1;MuMu Build/V417IR;wv)AppleWebKit/537.36(KHTML,like Gecko)Version/4.0 Chrome/52.0.2743.100MobileSafari / 537.36',
        'AppID': app_id,
        'Version': app_Version,
        'Authorization': Authorization,
        'Connection': 'Keep-Alive',
        'Host': 'api1.mimikko.cn'
    }
    try:
        with requests.get(url, headers=headers_get, params=params_get, verify=False, timeout=300) as resp:
            res = resp.json()
            return res
    except Exception as exg:
        print(exg)
# post请求
def apiRequest_post(url, app_id, app_Version, Authorization, params):
    params_post = params
    headers_post = {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'AppID': app_id,
        'Version': app_Version,
        'Authorization': Authorization,
        'Content-Type': 'application/json',
        'Host': 'api1.mimikko.cn',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'okhttp/3.12.1',
    }
    try:
        with requests.post(url, headers=headers_post, data=params_post, verify=False, timeout=300) as resp:
            res = resp.json()
            return res
    except Exception as exp:
        print(exp)
# 时间格式化
def timeStamp2time(timeStamp):
    timeArray = time.localtime(timeStamp)
    firstStyleTime = time.strftime('%Y-%m-%d', timeArray)
    secondStyleTime = time.strftime('%Y年%m月%d日 %H:%M:%S', timeArray)
    return firstStyleTime, secondStyleTime
# 钉钉post
def ddpost(ding_api, DDTOKEN, DDSECRET, title_post, post_text):
    timestamp = str(round(time.time() * 1000))
    secret_enc = DDSECRET.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, DDSECRET)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    headers_post = {
        'Content-Type': 'application/json; charset=UTF-8',
    }
    url = f'{ding_api}access_token={DDTOKEN}&timestamp={timestamp}&sign={sign}'
    post_info = {
        "msgtype": "text",
        "text": {
            "content": f'{title_post}\n\n{post_text}'
        }
    }
    post_info = json.dumps(post_info)
    try:
        post_data = requests.post(url, headers=headers_post, data=post_info, timeout=300)
        if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
            return post_data.json()["errcode"]
        else:
            return post_data.text
    except Exception as exp:
        print(exp)
# server酱post
def scpost(sc_api, SCKEY, title_post, post_text):
    headers_post = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    post_info = {'text': title_post, 'desp': post_text}
    url = f'{sc_api}{SCKEY}.send'
    try:
        post_data = requests.post(url, headers=headers_post, data=post_info, timeout=300)
        if 'errno' in post_data.json() and post_data.json()["errno"] == 0:
            return post_data.json()["errno"]
        else:
            return post_data.text
    except Exception as exp:
        print(exp)
# 企业微信推送
def send2wechat(AgentId, Secret, CompanyId, message):
    """
    # 此段修改自https://www.jianshu.com/p/99f706f1e943
    :param AgentId: 应用ID
    :param Secret: 应用Secret
    :param CompanyId: 企业ID
    """
    # 通行密钥
    ACCESS_TOKEN = None
    try:
        # 通过企业ID和应用Secret获取本地通行密钥
        r = requests.get(f'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CompanyId}&corpsecret={Secret}', timeout=300).json()
        ACCESS_TOKEN = r["access_token"]
    except Exception as exp:
        print('wxtoken', f'{exp}\n{r})
    # print(ACCESS_TOKEN)
    # 要发送的信息格式
    data = {
        "touser": "@all",
        "msgtype": "text",
        "agentid": f"{AgentId}",
        "text": {"content": f"{message}"}
    }
    # 字典转成json，不然会报错
    data = json.dumps(data)
    try:
        if ACCESS_TOKEN:
            # 发送消息
            post_data = requests.post(f'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={ACCESS_TOKEN}', data=data, timeout=300)
            # print(post_data.json())
            if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                return post_data.json()["errcode"]
            else:
                return post_data.text
        else:
            return 'ACCESS_TOKEN获取失败，发送未成功'
    except Exception as exp:
        print('wxpost', exp)

def mimikko():
    global Authorization
    #登录
    print('开始登录')
    if user_id and user_password:
        print("使用 ID密码 登录")
        user_password_sha = hashlib.sha256(user_password.encode('utf-8')).hexdigest()
        login_data = loginRequest_post(login_path, app_id, app_Version, f'{{"password":"{user_password_sha}", "id":"{user_id}"}}')
        if login_data and login_data.get('body'):
            Authorization = login_data['body']['Token']
            print("登录成功！")
        else:
            if SCKEY:
                print("登录错误，正在推送到Server酱")
                post_data = scpost(sc_api, SCKEY, "兽耳助手签到登录错误", "兽耳助手登录错误，请访问GitHub检查")
                print('server酱 errcode:', post_data)
            if DDTOKEN and DDSECRET:
                print("登录错误，正在推送到钉钉")
                post_data = ddpost(ding_api, DDTOKEN, DDSECRET, "兽耳助手签到登录错误", "兽耳助手登录错误，请访问GitHub检查")
                print('钉钉 errcode:', post_data)
            if wxAgentId and wxSecret and wxCompanyId:
                print("登录错误，正在推送到企业微信")
                post_data = send2wechat(wxAgentId, wxSecret, wxCompanyId, "兽耳助手签到登录错误\n\n兽耳助手登录错误，请访问GitHub检查")
                print('企业微信 errcode:', post_data)
            sys.exit('兽耳助手登录错误！！！')
    else:
        if Authorization:
            print("使用 Authorization 验证")
        else:
            if SCKEY:
                print("登录错误，正在推送到server酱")
                post_data = scpost(sc_api, SCKEY, "兽耳助手签到登录错误", "登录错误，未找到 Authorization ，请访问GitHub检查")
                print('server酱 errcode:', post_data)
            if DDTOKEN and DDSECRET:
                post_data = ddpost(ding_api, DDTOKEN, DDSECRET, "兽耳助手签到登录错误", "登录错误，未找到 Authorization ，请访问GitHub检查")
                print('钉钉 errcode:', post_data)
            if wxAgentId and wxSecret and wxCompanyId:
                print("登录错误，正在推送到企业微信")
                post_data = send2wechat(wxAgentId, wxSecret, wxCompanyId, "兽耳助手签到登录错误\n\n登录错误，未找到 Authorization ，请访问GitHub检查")
                print('企业微信 errcode:', post_data)
            sys.exit('请在Secret中保存 登录ID和密码 或 Authorization ！！！')
    #设置默认助手
    print('设置默认助手')
    defeat_data = apiRequest_get(f'{defeat_set}?code={Energy_code}', app_id, app_Version, Authorization, "")
    #执行前的好感度
    original_energy_data = apiRequest_get(f'{energy_info_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
    if original_energy_data and original_energy_data.get('body'):
        original_energy_post = str(original_energy_data['body']['Favorability'])
    else:
        energy_reward_post = "*"
    #签到历史
    sign_history = apiRequest_get(history_path, app_id, app_Version, Authorization, "")
    #补签
    if resign:
        print("正在尝试补签")
        #补签前的补签卡
        cansign_before = apiRequest_get(can_resign, app_id, app_Version, Authorization, "")
        if cansign_before and cansign_before.get('body'):
            cansign_before_time = cansign_before['body']['Value']
        else:
            cansign_before_time = False
        print(cansign_before_time)
        for i in [1, 2, 3, 4, 5, 6, 7]:
            if not i>resign:
                print('round ', str(i))
                resign_time = int(time.time())-86400*i
                r_date, r_time = timeStamp2time(resign_time)
                resign_data = apiRequest_post(resign_path, app_id, app_Version, Authorization, f'["{r_date}T15:59:59+0800"]')
                print(resign_data)
            else:
                break
        #补签后的补签卡
        cansign_after = apiRequest_get(can_resign, app_id, app_Version, Authorization, "")
        if cansign_after and cansign_after.get('body'):
            cansign_after_time = cansign_after['body']['Value']
        else:
            cansign_after_time = False
        print(cansign_after_time)
        #使用的补签卡
        if cansign_before_time and cansign_after_time:
            times_resigned = cansign_after_time-cansign_before_time
        else:
            times_resigned = False
    else:
        times_resigned = False
    #签到
    print('正在尝试签到')
    sign_data = apiRequest_get(sign_path, app_id, app_Version, Authorization, "")
    if sign_data and sign_data.get('body'):
        sign_info = apiRequest_get(is_sign, app_id, app_Version, Authorization, "")
        if sign_data['body']['GetExp']:
            if times_resigned:
                sign_result_post =f'''补签成功{str(times_resigned)}/{str(resign)}天\n签到成功：{str(sign_info['body']['ContinuousSignDays'])}天\n好感度：{str(sign_data['body']['Reward'])}\n硬币：{str(sign_data['body']['GetCoin'])}\n经验值：{str(sign_data['body']['GetExp'])}\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
            else:
                sign_result_post = f'''签到成功：{str(sign_info['body']['ContinuousSignDays'])}天\n好感度：{str(sign_data['body']['Reward'])}\n硬币：{str(sign_data['body']['GetCoin'])}\n经验值：{str(sign_data['body']['GetExp'])}\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
            title_ahead = f'''兽耳助手签到{str(sign_info['body']['ContinuousSignDays'])}'''
        else:
            sign_result_post = f'''今日已签到：{str(sign_info['body']['ContinuousSignDays'])}天\n签到卡片：{sign_data['body']['Description']}{sign_data['body']['Name']}\n{sign_data['body']['PictureUrl']}'''
            title_ahead = f'''兽耳助手签到{str(sign_info['body']['ContinuousSignDays'])}'''
    else:
        sign_result_post = '签到失败'
        title_ahead = '兽耳助手签到'
    #VIP抽奖
    print('正在尝试VIP抽奖')
    vip_info_data = apiRequest_get(vip_info, app_id, app_Version, Authorization, "")
    if vip_info_data and vip_info_data.get('body'):
        if vip_info_data['body']['rollNum'] > 0:
            vip_roll_data = apiRequest_post(vip_roll, app_id, app_Version, Authorization, "")
            vip_roll_post = f'''VIP抽奖成功：{vip_roll_data['body']['Value']['description']}'''
        else:
            vip_roll_data = "抽奖次数不足"
            if vip_info_data['body']['isValid']:
                vip_roll_post = "今天已经抽过奖了"
            else:
                vip_roll_post = "VIP抽奖失败：您还不是VIP"
    else:
        vip_roll_data = "抽奖次数不足"
        vip_roll_post = "VIP抽奖失败"
    #能量兑换好感度
    print('正在尝试兑换能量')
    energy_info_data = apiRequest_get(f'{energy_info_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
    if energy_info_data and energy_info_data.get('body'):
        if energy_info_data['body']['Energy'] > 0:
            energy_reward_data = apiRequest_get(f'{energy_reward_path}?code={Energy_code}', app_id, app_Version, Authorization, "")
            title_post = f'''{title_ahead}{servant_name[energy_reward_data['body']['code']]}好感度{str(energy_reward_data['body']['Favorability'])}'''
            gethgd = int(energy_reward_data['body']['Favorability'])-int(original_energy_post)
            energy_reward_post = f'''能量值：{str(energy_info_data['body']['Energy'])}/{str(energy_info_data['body']['MaxEnergy'])}\n好感度兑换成功\n助手：{servant_name[energy_reward_data['body']['code']]} LV{str(energy_reward_data['body']['Level'])} +{gethgd}({original_energy_post}→{str(energy_reward_data['body']['Favorability'])}/{str(energy_info_data['body']['MaxFavorability'])})'''
        else:
            energy_reward_data = "您的能量值不足，无法兑换"
            title_post = f'''{title_ahead}{servant_name[energy_info_data['body']['code']]}好感度{str(energy_info_data['body']['Favorability'])}'''
            gethgd = int(energy_info_data['body']['Favorability'])-int(original_energy_post)
            energy_reward_post = f'''能量值：{str(energy_info_data['body']['Energy'])}/{str(energy_info_data['body']['MaxEnergy'])}\n好感度兑换失败：当前没有能量\n助手：{servant_name[energy_info_data['body']['code']]} LV{str(energy_info_data['body']['Level'])} +{gethgd}({original_energy_post}→{str(energy_info_data['body']['Favorability'])}/{str(energy_info_data['body']['MaxFavorability'])})'''
    else:
        energy_reward_data = "您的能量值不足，无法兑换"
        title_post = title_ahead
        energy_reward_post = "能量兑换失败"
    return sign_data, vip_info_data, vip_roll_data, energy_info_data, energy_reward_data, sign_info, sign_history, sign_result_post, title_post, vip_roll_post, energy_reward_post

try:
    sign_data, vip_info_data, vip_roll_data, energy_info_data, energy_reward_data, sign_info, sign_history, sign_result_post, title_post, vip_roll_post, energy_reward_post = mimikko()
    varErr = True
    varErrText = ''
    for i in ['sign_data', 'vip_info_data', 'vip_roll_data', 'energy_info_data', 'energy_reward_data', 'sign_info', 'sign_history', 'sign_result_post', 'title_post', 'vip_roll_post', 'energy_reward_post']:
        if not i in locals():
            varErr = False
            print('mimikko 函数返回值', i, '缺失')
            varErrText = f'{varErrText},{i}'
    if varErr:
        now_date, now_time = timeStamp2time(time.time()+28800)
        #print(time.time())
        # # sign_data
        print('sign_data', sign_data)
        # # roll info
        print('vip_roll_data', vip_roll_data)
        # # Energy info
        print('energy_info_data', energy_info_data)
        # # Energy reward
        print(energy_reward_data)
        # # sign_info
        # # sign_history
        print(sign_history)
        print(f'\n\n现在是：{now_time}\n{sign_result_post}\n{vip_roll_post}\n{energy_reward_post}\n')
    else:
        varErrText = f'函数返回值 {varErrText[1:]} 缺失'
except Exception as em:
    varErr = False
    varErrText = f'Error: {em}'
    print('mimikko', em)

try:
    # print(len(sys.argv))
    if SCKEY:
        # print("有SCKEY")
        if varErr:
            print("运行成功，正在推送到Server酱")
            post_text = re.sub('\\n', '  \n', f'现在是：{now_time}\n{sign_result_post}\n{vip_roll_post}\n{energy_reward_post}')
            post_data = scpost(sc_api, SCKEY, title_post, post_text)
            print('server酱 errcode:', post_data)
        else:
            print("运行失败，正在推送到Server酱")
            post_data = scpost(sc_api, SCKEY, "兽耳助手签到数据异常", f'兽耳助手签到数据异常，请访问GitHub检查：{varErrText}')
            print('server酱 errcode:', post_data)
        if post_data == 0:
            rs1 = False
        else:
            rs1 = True
    else:
        if varErr:
            print("运行成功，且没有SCKEY，Server酱未推送")
        else:
            print(f"运行失败：\n兽耳助手签到数据异常，请访问GitHub检查：{varErrText}，且没有SCKEY，Server酱未推送")
        rs1 = False
except Exception as es:
    rs1 = True
    if SCKEY:
        print("数据异常，正在推送到Server酱")
        post_data = scpost(sc_api, SCKEY, "兽耳助手签到数据异常", f"兽耳助手签到数据异常，请访问GitHub检查：{es}")
        print('server酱 errcode:', post_data)
    else:
        print("数据异常，且没有SCKEY，Server酱未推送")
    print('sc', es)
try:
    # print(len(sys.argv))
    if DDTOKEN and DDSECRET:
        #print("有DDTOKEN和DDSECRET")
        if varErr:
            print("运行成功，正在推送到钉钉")
            post_text = re.sub('\\n', '  \n', f'现在是：{now_time}\n{sign_result_post}\n{vip_roll_post}\n{energy_reward_post}')
            post_data = ddpost(ding_api, DDTOKEN, DDSECRET, title_post, post_text)
            print('钉钉 errcode:', post_data)
        else:
            print("运行失败，正在推送到钉钉")
            post_data = ddpost(ding_api, DDTOKEN, DDSECRET, "兽耳助手签到数据异常", f"兽耳助手签到数据异常，请访问GitHub检查：{varErrText}")
            print('钉钉 errcode:', post_data)
        if post_data == 0:
            rs2 = False
        else:
            rs2 = True
    else:
        if varErr:
            print("运行成功，且没有DDTOKEN或DDSECRET，钉钉未推送")
        else:
            print(f"运行失败：\n兽耳助手签到数据异常，请访问GitHub检查：{varErrText}，且没有DDTOKEN或DDSECRET，钉钉未推送")
        rs2 = False
except Exception as ed:
    rs2 = True
    if DDTOKEN and DDSECRET:
        print("数据异常，正在推送到钉钉")
        post_data = ddpost(ding_api, DDTOKEN, DDSECRET, "兽耳助手签到数据异常", f"兽耳助手签到数据异常，请访问GitHub检查：{ed}")
        print('钉钉 errcode:', post_data)
    else:
        print("数据异常，且没有DDTOKEN或DDSECRET，钉钉未推送")
    print('dd', ed)
try:
    # print(len(sys.argv))
    if wxAgentId and wxSecret and wxCompanyId:
        #print("有wxAgentId, wxSecret和wxCompanyId")
        if varErr:
            print("运行成功，正在推送到企业微信")
            post_text = re.sub('\\n', '  \n', f'现在是：{now_time}\n{sign_result_post}\n{vip_roll_post}\n{energy_reward_post}')
            post_data = send2wechat(wxAgentId, wxSecret, wxCompanyId, f'{title_post}\n\n{post_text}')
            print('企业微信 errcode:', post_data)
        else:
            print("运行失败，正在推送到企业微信")
            post_data = send2wechat(wxAgentId, wxSecret, wxCompanyId, f'兽耳助手签到数据异常\n\n兽耳助手签到数据异常，请访问GitHub检查：{varErrText}')
            print('企业微信 errcode:', post_data)
        if post_data == 0:
            rs3 = False
        else:
            rs3 = True
    else:
        if varErr:
            print("运行成功，且没有wxAgentId, wxSecret或wxCompanyId，企业微信未推送")
        else:
            print(f"运行失败：\n兽耳助手签到数据异常，请访问GitHub检查：{varErrText}，且没有wxAgentId, wxSecret或wxCompanyId，企业微信未推送")
        rs3 = False
except Exception as ew:
    rs3 = True
    if wxAgentId and wxSecret and wxCompanyId:
        print("数据异常，正在推送到企业微信")
        post_data = send2wechat(wxAgentId, wxSecret, wxCompanyId, f"兽耳助手签到数据异常\n\n兽耳助手签到数据异常，请访问GitHub检查：{ew}")
        print('企业微信 errcode:', post_data)
    else:
        print("数据异常，且没有wxAgentId, wxSecret或wxCompanyId，企业微信未推送")
    print('wx', ew)
if rs1 or rs2 or rs3:
    sys.exit('推送异常，请检查')

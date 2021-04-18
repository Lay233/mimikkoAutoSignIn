# -*- coding: UTF-8 -*-
"""
 * @author  cyb233
 * @date  2021/4/18
"""
import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def mimikko_login(url, app_id, app_Version, params):  # 登录post
    headers = {
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
        with requests.post(url, headers=headers, data=params, timeout=300) as resp:
            # logging.debug(resp.text)  # 请务必谨慎开启，因为包含 Authorization 参数！！！
            res = resp.json()
            return res
    except Exception as exl:
        logging.error(exl, exc_info=True)
        return False


def mimikko_get(url, app_id, app_Version, Authorization, params):  # get请求
    headers = {
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
        with requests.get(url, headers=headers, params=params, timeout=300) as resp:
            logging.debug(resp.text)
            res = resp.json()
            return res
    except Exception as exg:
        logging.error(exg, exc_info=True)
        return False


def mimikko_post(url, app_id, app_Version, Authorization, params):  # post请求
    headers = {
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
        with requests.post(url, headers=headers, data=params, timeout=300) as resp:
            logging.debug(resp.text)
            res = resp.json()
            return res
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return False


def timeStamp1time(timeStamp):  # 时间格式化1
    timeArray = time.localtime(timeStamp)
    StyleTime = time.strftime('%Y-%m-%d', timeArray)
    return StyleTime


def timeStamp2time(timeStamp):  # 时间格式化2
    timeArray = time.localtime(timeStamp)
    StyleTime = time.strftime('%Y年%m月%d日 %H:%M:%S', timeArray)
    return StyleTime


def ddpost(DDTOKEN, DDSECRET, title_post, post_text):  # 钉钉推送
    timestamp = str(round(time.time() * 1000))
    secret_enc = DDSECRET.encode('utf-8')
    string_to_sign = f'{timestamp}\n{DDSECRET}'
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc,
                         digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    headers_post = {
        'Content-Type': 'application/json; charset=UTF-8',
    }
    url = f'https://oapi.dingtalk.com/robot/send?access_token={DDTOKEN}&timestamp={timestamp}&sign={sign}'
    post_info = {
        "msgtype": "text",
        "text": {
            "content": f'{title_post}\n\n{post_text}'
        }
    }
    post_info = json.dumps(post_info)
    try:
        with requests.post(url, headers=headers_post, data=post_info, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                return post_data.json()["errcode"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def scpost(SCKEY, title_post, post_text):  # server酱推送
    headers_post = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    post_info = {'text': title_post, 'desp': post_text}
    url = f'https://sc.ftqq.com/{SCKEY}.send'
    try:
        with requests.post(url, headers=headers_post, data=post_info, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'errno' in post_data.json() and post_data.json()["errno"] == 0:
                return post_data.json()["errno"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def send2wechat(wxAgentId, wxSecret, wxCompanyId, title_post, post_text):  # 企业微信推送
    """
    # 此段修改自https://www.jianshu.com/p/99f706f1e943
    :param AgentId: 应用ID
    :param Secret: 应用Secret
    :param CompanyId: 企业ID
    """
    # 通行密钥
    ACCESS_TOKEN = None
    ATurl = f'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={wxCompanyId}&corpsecret={wxSecret}'
    try:
        # 通过企业ID和应用Secret获取本地通行密钥
        with requests.get(ATurl, timeout=300) as r:
            logging.debug(r.text)
            r = r.json()
            ACCESS_TOKEN = r["access_token"]
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp
    # logging.debug(ACCESS_TOKEN)  # 注意账号安全
    # 要发送的信息格式
    data = {
        "touser": "@all",
        "msgtype": "text",
        "agentid": f"{wxAgentId}",
        "text": {"content": f'{title_post}\n\n{post_text}'}
    }
    # 字典转成json，不然会报错
    data = json.dumps(data)
    url = f'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={ACCESS_TOKEN}'
    try:
        if ACCESS_TOKEN:
            # 发送消息
            with requests.post(url, data=data, timeout=300) as post_data:
                logging.debug(post_data.text)
                if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                    return post_data.json()["errcode"]
                else:
                    return post_data.text
        else:
            return 'ACCESS_TOKEN获取失败，未发送'
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def dcpost(dcwebhook, title_post, post_text):  # Discord推送
    url = dcwebhook
    headers = {"Content-Type": "application/json"}
    data = {"content": f'{title_post}\n\n{post_text}'}
    try:
        # 发送消息
        with requests.post(url, headers=headers, data=data, timeout=300) as post_data:
            logging.debug(post_data.text)
            if 'errcode' in post_data.json() and post_data.json()["errcode"] == 0:
                return post_data.json()["errcode"]
            else:
                return post_data.text
    except Exception as exp:
        logging.error(exp, exc_info=True)
        return exp


def AllPush(DDTOKEN, DDSECRET, wxAgentId, wxSecret, wxCompanyId, SCKEY, dcwebhook, title_post, post_text):  # 全推送
    dddata = scdata = wxdata = dcdata = False
    if SCKEY:
        logging.info("正在推送到Server酱")
        scdata = scpost(SCKEY, title_post, post_text)  # server酱推送
    else:
        logging.info('SCKEY不存在')
    if DDTOKEN and DDSECRET:
        logging.info("正在推送到钉钉")
        dddata = ddpost(DDTOKEN, DDSECRET, title_post, post_text)  # 钉钉推送
    else:
        logging.info('DDTOKEN或DDSECRET不存在')
    if wxAgentId and wxSecret and wxCompanyId:
        logging.info("正在推送到企业微信")
        wxdata = send2wechat(wxAgentId, wxSecret, wxCompanyId,
                             title_post, post_text)  # 企业微信推送
    else:
        logging.info('wxAgentId, wxSecret或wxCompanyId不存在')
    if dcwebhook:
        logging.info("正在推送到Discord")
        dcdata = dcpost(dcwebhook, title_post, post_text)  # Discord推送
    else:
        logging.info('dcappid或dckey不存在')
    return dddata, scdata, wxdata, dcdata

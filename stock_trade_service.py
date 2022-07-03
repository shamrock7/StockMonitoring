#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author shen.charles@hotmail.com
import base64
import json
import logging
import time
import random
import sys

import requests
import urllib
import urllib3
from lxml import etree
import redis
# from PIL import Image
# from io import BytesIO

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s]\t[%(levelname)s]\t%(filename)s:%(lineno)s:%(funcName)s\t%(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)

baidu_api_key = ""
baidu_secret_key = ""
baidu_endpoint = "https://aip.baidubce.com"


class AuthenticationException(Exception):
    def __init__(self):
        super().__init__('Authentication Failed!')


class StockTradeService(object):
    def __init__(self, *, uid: str, password: str):
        self.uid = uid
        self.__rds = None
        self.password = password
        self.sess = requests.session()
        self.validate_key = ''

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def init_rds(self, addr: str, port: int, password: str):
        if self.__rds is not None:
            return

        if addr.__len__() == 0:
            addr = "127.0.0.1"
        if port <= 0:
            port = 6379

        self.__rds = redis.StrictRedis(host=addr, port=port, password=password)

    def get_baidu_access_token(self):
        """
        :return {
            "session_secret": "012183f25a46d1ec7e491fd1c3e85a4a",
            "refresh_token": "25.a137077f3033c88ff035262269a39f9b.315360000.1971616795.282335-26553195",
            "scope": "ai_custom_dc_captcha_detection public brain_all_scope ...",
            "session_key": "9mzdCSM/B/z1q+BiwcydMyKhq0fqFmkmvaVrYOPko4Jh2yKwxd5sUok274EWqekM1jmGNz/1w6B8Ap8HpPPY3CahOvXicg==",
            "expires_in": 2592000,
            "access_token": "24.256d01027176cc20abc4717841a20479.2592000.1658848795.282335-26553195"
        }
        """
        if self.__rds is None:
            data = self.__get_baidu_access_token()
            if data is not None:
                return json.loads(data)
        data = self.__rds.get("baidu_access_token")
        return json.loads(data)

    def __get_baidu_access_token(self):
        """
        :return {
            "session_secret": "012183f25a46d1ec7e491fd1c3e85a4a",
            "refresh_token": "25.a137077f3033c88ff035262269a39f9b.315360000.1971616795.282335-26553195",
            "scope": "ai_custom_dc_captcha_detection public brain_all_scope ...",
            "session_key": "9mzdCSM/B/z1q+BiwcydMyKhq0fqFmkmvaVrYOPko4Jh2yKwxd5sUok274EWqekM1jmGNz/1w6B8Ap8HpPPY3CahOvXicg==",
            "expires_in": 2592000,
            "access_token": "24.256d01027176cc20abc4717841a20479.2592000.1658848795.282335-26553195"
        }
        """

        url = "{}/oauth/2.0/token?".format(baidu_endpoint)

        params = {
            "grant_type": "client_credentials",
            "client_id": baidu_api_key,
            "client_secret": baidu_secret_key,
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json,  text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6,ja;q=0.5",
            "DNT": "1",
            "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        response = requests.post(url=url, data=params, headers=headers, verify=False)

        if response.status_code != 200:
            logging.error(response.text)
            return
        result = json.loads(response.content)

        self.__rds.set(name="baidu_access_token", value=response.content, ex=result["expires_in"])
        return result

    def recognize_captcha_with_content(self, content: str):
        """
        :param content image's base64 data string
        """
        token_info = self.get_baidu_access_token()

        url = "{}/rpc/2.0/ai_custom/v1/detection/dc_captcha_detection?access_token={}".format(baidu_endpoint,
                                                                                              token_info[
                                                                                                  "access_token"])
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json,  text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,zh-TW;q=0.6,ja;q=0.5",
            "DNT": "1",
            "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        data = {
            "image": content,
        }
        response = requests.post(url=url, json=data, headers=headers)

        resp = json.loads(response.content)

        resp["results"] = sorted(resp["results"], key=lambda x: x["location"]["top"] * x["location"]["top"] +
                                                                x["location"]["left"] * x["location"]["left"],
                                 reverse=False)

        result = ""
        for item in resp["results"]:
            result += item["name"]
        return result

    def get_identify_code(self):
        rand_number = random.random() - 0.00000000000000009
        url = 'https://jy.xzsec.com/Login/YZM?randNum={rand_number}'.format(rand_number=rand_number)
        headers = {
            'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Host': 'jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
        }
        response = self.sess.get(url, headers=headers, verify=False)

        img_b64 = base64.b64encode(response.content).decode("utf8")
        return rand_number, self.recognize_captcha_with_content(img_b64)
        # image = Image.open(BytesIO(response.content))
        # image.show()
        # identify_code = input('输入验证码: ')
        # return rand_number, identify_code

    def authentication(self):
        url = 'https://jy.xzsec.com/Login/Authentication?validatekey='
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '112',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Origin': 'https://jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        rand_number, identify_code = self.get_identify_code()
        data = {
            'userId': self.uid,
            'password': self.password,
            'randNumber': rand_number,
            'identifyCode': identify_code,
            'duration': 1800,
            'authCode': '',
            'type': 'Z'
        }
        response = self.sess.post(url, data=data, headers=headers, verify=False)
        if response.status_code == 200:
            r_json = response.json()
            if r_json['Status'] == 0:
                self.validate_key = self.get_validate_key()
                result = True
            else:
                result = False
        else:
            result = False
        return result

    def get_validate_key(self):
        url = 'https://jy.xzsec.com/Trade/Buy'
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Host': 'jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
        }
        response = self.sess.get(url, headers=headers, verify=False)
        html = etree.HTML(response.text)
        em_validate_key = html.xpath('//input[@id="em_validatekey"]')[0].get('value')
        return em_validate_key

    def get_stock_list(self):
        url = 'https://jy.xzsec.com/Search/GetStockList?validatekey={}'.format(self.validate_key)
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '14',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Origin': 'https://jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/Trade/Buy',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        data = {
            'qqhs': 1000,
            'dwc': ''
        }
        response = self.sess.post(url, data=data, headers=headers, verify=False)
        r_json = response.json()
        stock_list = r_json['Data']
        return stock_list

    def submit_trade(self, zqdm, price, amount, trade_type, zqmc, gddm):
        url = 'https://jy.xzsec.com/Trade/SubmitTrade?validatekey={}'.format(self.validate_key)
        logging.info(url)
        r_data = {
            'code': zqdm,
            'name': zqmc,
            'moneytype': '元',
            'type': '',
            'zqlx': 0,
            'mt': 2,
        }
        logging.info(r_data)
        if trade_type == 'B':
            r_data['type'] = 'buy'
            referer = 'https://jy.xzsec.com/Trade/Buy?{}'.format(urllib.parse.urlencode(r_data))
            logging.info(referer)
        elif trade_type == 'S':
            r_data['type'] = 'sale'
            r_data['gddm'] = gddm
            referer = 'https://jy.xzsec.com/Trade/Sale?{}'.format(urllib.parse.urlencode(r_data)).replace('&', '&amp;')
            logging.info(referer)
        else:
            referer = 'https://jy.xzsec.com/'
            logging.info(referer)
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '101',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Origin': 'https://jy.xzsec.com',
            'Referer': referer,
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        logging.info(headers)
        data = {
            'stockCode': zqdm,
            'price': price,
            'amount': amount,
            'tradeType': trade_type,
            'zqmc': zqmc
        }
        if trade_type == 'S':
            data['gddm'] = gddm
        logging.info(data)
        output = dict()
        output['data'] = data
        response = self.sess.post(url, data=data, headers=headers, verify=False)
        output['result'] = response.json()
        logging.info(output)
        return output

    def get_revoke_list(self):
        url = 'https://jy.xzsec.com/Trade/GetRevokeList?validatekey={}'.format(self.validate_key)
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Origin': 'https://jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/Trade/Revoke',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        response = self.sess.post(url, headers=headers, verify=False)
        r_json = response.json()
        revoke_list = r_json['Data']
        return revoke_list

    def submit_revoke(self, zqmc, wtrq, wtbh):
        url = 'https://jy.xzsec.com/Trade/RevokeOrders?validatekey={}'.format(self.validate_key)
        headers = {
            'Accept': 'text/plain, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Length': '21',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Origin': 'https://jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/Trade/Revoke',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        data = {
            'revokes': '{}_{}'.format(wtrq, wtbh)
        }
        output = {}
        output['Zqmc'] = zqmc
        output['data'] = data
        response = self.sess.post(url, data=data, headers=headers, verify=False)
        output['result'] = response.text
        return output

    def get_hold(self):
        t = round(time.time() * 1000)
        url = 'https://jy.xzsec.com/AccountAnalyze/Asset/GetHold?v={}'.format(t)
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'jy.xzsec.com',
            'Referer': 'https://jy.xzsec.com/AccountAnalyze/Asset',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
        }
        response = self.sess.get(url, headers=headers, verify=False)
        r_json = response.json()
        fund_avl = r_json['ResultObj'][0]['FundAvl']
        return fund_avl

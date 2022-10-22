# -*- encoding: utf-8 -*-
# Author: Roger·J
# Date: 2022/10/10 13:24
# File: main.py

import sys
import yaml
import requests
from time import sleep
from allpairspy import AllPairs
from collections import OrderedDict
from copy import deepcopy
from cacheout import Cache


class PairsData(object):

    def __init__(self):
        self.data = self.__get_yaml()
        self.cache = Cache(maxsize=256)

    def __get_yaml(self):
        stream = open(file='./api.yaml', mode='r', encoding='utf8')
        self.data = yaml.safe_load(stream)
        self.wx_app_host = self.data[0]['env']['wx-app']
        self.wx_code = self.data[0]['env']['wx-code']
        self.backend_host = self.data[0]['env']['backend']
        self.username = self.data[0]['env']['username']
        self.password = self.data[0]['env']['password']
        self.data.remove(self.data[0])

        return self.data

    def __get_all_pairs(self, d: dict):

        all_pairs = {}
        optional_params = None
        if 'optional' in d.keys():
            optional_params = d['optional']
            d.pop('optional')

        self.__dict_decursive_acronym(d, all_pairs, optional_params)

        return all_pairs

    def __dict_decursive_acronym(self, d, params_pairs, optional=None):

        for i in d.keys():

            if isinstance(d[i], dict):
                self.__dict_decursive_acronym(d[i], params_pairs, optional)

            elif isinstance(d[i], list) or isinstance(d[i], tuple):
                if optional and i in optional:
                    params_pairs[i] = []
                    params_pairs[i].append({"info": "去掉非必选",
                                            "key": i})

                for j in d[i]:

                    if isinstance(j, dict):
                        self.__dict_decursive_acronym(j, params_pairs, optional)

                    else:
                        if i not in params_pairs.keys():
                            params_pairs[i] = []
                            if optional and i in optional:
                                params_pairs[i].append({"info": "去掉非必选",
                                                        "key": i})

                        for k in j.split('/'):
                            try:
                                params_pairs[i].append({"info": k.split(':', 1)[0],
                                                        "value": k.split(':', 1)[1].split(','),
                                                        "key": i})
                            except IndexError:
                                params_pairs[i].append({"info": '正确',
                                                        "value": k.split(','),
                                                        "key": i})

            elif d[i]:
                params_pairs[i] = []
                try:
                    if i in optional:
                        params_pairs[i].append({"info": "去掉非必选",
                                                "key": i})
                except TypeError:
                    pass

                try:
                    for j in d[i].split('/'):
                        try:
                            params_pairs[i].append({"info": j.split(':', 1)[0],
                                                    "value": None if j.split(':', 1)[1] == 'null' else j.split(':', 1)[1],
                                                    "key": i})
                        except IndexError:
                            params_pairs[i].append({"info": '正确',
                                                    "value": j,
                                                    "key": i})
                except AttributeError:
                    params_pairs[i].append({"info": '正确',
                                            "value": d[i],
                                            "key": i})

    def __check_params_num(self, d):

        if len(d) > 1:
            return True

        else:
            index = 0
            for _ in d.values():
                index += 1
                if index > 1:
                    return True

        return False

    def get_request_pairs(self, d: dict):
        data = []
        flag = True
        optional = None

        if 'optional' in d.keys() and d['optional']:
            optional = d.pop('optional')

        if len(d.values()) <= 1 or None in d.values():
            for value in d.values():
                if value:
                    flag = self.__check_params_num(value)

        if optional:
            d['optional'] = optional

        if flag:
            for v, pairs in enumerate(AllPairs(OrderedDict(self.__get_all_pairs(d)))):
                app = []
                for j in pairs:
                    app.append(j)
                data.append(app)
        else:
            for v in self.__get_all_pairs(d).values():
                data.append(v)

        json_lists = []
        for t in data:
            if flag:
                d = {'info': ''}
                for j in t:
                    if j['info'] == '正确':
                        d['info'] = d['info'] + '\033[0;32m' + j['key'] + j['info'] + '\033[0m'
                    else:
                        d['info'] = d['info'] + '\033[0;31m' + j['key'] + j['info'] + '\033[0m'
                    if j['info'] != "去掉非必选":
                        d[j['key']] = j['value']
                json_lists.append(d)

            else:
                for j in t:
                    d = {'info': ''}
                    if j['info'] == '正确':
                        d['info'] = d['info'] + '\033[0;32m' + j['key'] + j['info'] + '\033[0m'
                    else:
                        d['info'] = d['info'] + '\033[0;31m' + j['key'] + j['info'] + '\033[0m'
                    if j['info'] != "去掉非必选":
                        d[j['key']] = j['value']
                    json_lists.append(d)

        return json_lists

    def __set_json_data(self, json, data):
        for i in json.keys():
            if isinstance(json[i], dict):
                self.__set_json_data(json[i], data)

            elif isinstance(json[i], list) or isinstance(json[i], tuple):

                for j in json[i]:

                    if isinstance(j, dict):
                        self.__set_json_data(j, data)

                    else:
                        if i in data.keys():
                            elem_index = json[i].index(j)
                            if elem_index == len(json[i])-1:
                                json[i] = data[i]
                            else:
                                json[i][elem_index] = data[i]
                        else:
                            json[i] = ''

            else:
                if i in data.keys():
                    json[i] = data[i]
                else:
                    json[i] = ''

    def get_request_json(self, d: dict, pairs_dict: dict):
        request_dict = {}
        for i in d.keys():
            if isinstance(d[i], dict):
                if d[i]:
                    self.__set_json_data(d[i], pairs_dict)

                if i == 'query':
                    request_dict['params'] = d['query']
                    continue

                elif i == 'body':
                    request_dict['json'] = d['body']
                    continue

                elif i == 'data':
                    request_dict['data'] = d['data']
                    continue

        return request_dict

    def check_auth(self, d: dict):
        for i in d.keys():
            if i == 'token':
                if d[i] is None and self.cache.get('token') is None:
                    response = requests.post(url=self.wx_app_host + '/xct/auth/customerLoginByWeixin',
                                             json={'data': {'code': self.wx_code}},
                                             headers={'Content-Type': 'application/json;charset=UTF-8'})
                    if response.status_code == 502:
                        raise Exception("后台服务正在重启，无法拿到token")

                    try:
                        d[i] = response.json()['data']['token']
                        self.cache.set('token', d[i])
                    except TypeError:
                        print("小程序code失效请重新输入")
                        sys.exit(0)

                else:
                    d[i] = self.cache.get('token')

                return True

            if i == 'x-token':
                if d[i] is None and self.cache.get('x-token') is None:
                    response = requests.post(url=self.backend_host + '/user/login',
                                             json={'username': self.username, 'password': self.password},
                                             headers={'Content-Type': 'application/json;charset=UTF-8'})
                    if response.status_code == 502:
                        raise Exception("后台服务正在重启，无法拿到token")

                    try:
                        d[i] = response.json()['data']['token']
                        self.cache.set('x-token', d[i])
                    except TypeError:
                        print("后台用户名密码有误，请修改配置文件")
                else:
                    d[i] = self.cache.get('x-token')

                return True

            elif isinstance(d[i], dict):
                if self.check_auth(d[i]):
                    return


if __name__ == '__main__':

    pairs = PairsData()
    for data in pairs.data:

        all_pairs_list = pairs.get_request_pairs(data['params'])

        for one_pairs in all_pairs_list:
            req_model = deepcopy(data['params'])
            info = one_pairs['info']
            one_pairs.pop('info')
            req_params = pairs.get_request_json(req_model, one_pairs)
            req_params['headers'] = data['headers']
            req_params['url'] = data['host'] + data['address']
            req_params['method'] = data['method']
            pairs.check_auth(req_params)
            response = requests.request(**req_params)
            print("正在测试=========>{url}\n{info}".format(url=response.url, info=info))
            print("请求头===============>\n\033[0;32m{headers}\033[0m".format(headers=response.request.headers))
            print("请求体===============>\n\033[0;32m{body}\033[0m".format(body=response.request.body))
            if response.status_code != 200:
                print('\033[0;31m状态码都不是200，还测个啥？？？？赶紧打开bilibili学习啦\033[0m')
                print('状态码为\033[0;31m{code}\033[0m'.format(code=response.status_code))
                print('返回数据为\033[0;31m{data}\033[0m'.format(data=response.text))
            else:
                print('状态码为\033[0;32m{code}\033[0m'.format(code=response.status_code))
                print('返回数据为===============>\n\033[0;32m{data}\033[0m'.format(data=response.text))
            print("===================分割线===================\n")
            sleep(1)

    pairs.cache.clear()

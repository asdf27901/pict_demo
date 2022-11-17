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
        self.username_no_permissions = self.data[0]['env']['username-no-permissions']
        self.password_no_permissions = self.data[0]['env']['password-no-permissions']
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

            elif d[i] is not None:
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
                                                    "value": None if j.split(':', 1)[1] == 'null'
                                                    else j.split(':', 1)[1],
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
            # index = 0
            keys = list(d.keys())
            # for _ in d[key]:
            #     index += 1
            if len(keys) > 1:
                return True
            elif len(keys) == 1:
                if not isinstance(d[keys[0]], str) and len(d[keys[0]]) > 1:
                    return True
                return False

        # return False

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
                            if elem_index == len(json[i]) - 1:
                                json[i] = data[i]
                            else:
                                json[i][elem_index] = data[i]
                        else:
                            json[i] = None

            else:
                if i in data.keys():
                    json[i] = data[i]
                else:
                    json[i] = None

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

    def __login_backend(self, username: str, password: str, permissions: bool):

        __login_backend_response = requests.post(url=self.backend_host + '/user/login',
                                                 json={'username': username, 'password': password},
                                                 headers={'Content-Type': 'application/json;charset=UTF-8'})

        if __login_backend_response.status_code == 502:
            raise Exception("后台服务正在重启，无法拿到token")

        try:
            if permissions:
                self.cache.set('x-token', __login_backend_response.json()['data']['token'])
            else:
                self.cache.set('x-token-no-permissions', __login_backend_response.json()['data']['token'])
        except TypeError:
            print("后台用户名密码有误，请修改配置文件")
            sys.exit(1)

    def __login_wxapp(self):
        __login_wxapp_response = requests.post(url=self.wx_app_host + '/xct/auth/customerLoginByWeixin',
                                               json={'data': {'code': self.code}},
                                               headers={'Content-Type': 'application/json;charset=UTF-8'})
        if __login_wxapp_response.status_code == 502:
            raise Exception("小程序服务正在重启，无法拿到token")

        try:
            self.cache.set('token', __login_wxapp_response.json()['data']['token'])
        except KeyError:
            print("小程序code失效请重新输入")
            sys.exit(1)

    def check_auth(self, d: dict, permissions: bool = True):
        for i in d.keys():
            if i == 'token':
                if self.cache.get('token') is None:
                    self.__login_wxapp()
                d[i] = self.cache.get('token')

                return True

            if i == 'x-token':
                if permissions:
                    if self.cache.get('x-token') is None:
                        self.__login_backend(self.username, self.password, permissions)
                    d[i] = self.cache.get('x-token')
                else:
                    if self.cache.get('x-token-no-permissions') is None:
                        self.__login_backend(self.username_no_permissions, self.password_no_permissions, permissions)
                    d[i] = self.cache.get('x-token-no-permissions')

                return True

            elif isinstance(d[i], dict):
                if self.check_auth(d[i], permissions):
                    return

    def __call__(self, *args):
        # TODO
        pass

    def set_auth_error_pair_dict(self, d: dict, pairs_list: list):
        for i in d.keys():
            if i == 'x-token':
                if not pairs_list:
                    pairs_list.append({'info': '\033[0;31mx-token正确\033[0m'})
                pairs_list.append({'info': '\033[0;31mx-token失效/无效\033[0m'})
                pairs_list.append({'info': '\033[0;31m无权限\033[0m'})
                return True

            elif i == 'token':
                pairs_list.append({'info': '\033[0;31mtoken失效/无效\033[0m'})
                pairs_list.append({'info': '\033[0;31m无权限\033[0m'})
                return True

            elif isinstance(d[i], dict):
                if self.set_auth_error_pair_dict(d[i], pairs_list):
                    return

    def set_auth_invalid(self, d: dict):
        for i in d.keys():
            if i == 'x-token' or i == 'token':
                d[i] = 'xxx'
                return True

            elif isinstance(d[i], dict):
                if self.set_auth_invalid(d[i]):
                    return


if __name__ == '__main__':

    pairs = PairsData()
    print("请输入你要测试的接口名：")
    request_list = input().split('，')
    for data in pairs.data:
        if data['name'] in request_list:

            all_pairs_list = pairs.get_request_pairs(data['params'])
            pairs.set_auth_error_pair_dict(data, all_pairs_list)

            for one_pairs in all_pairs_list:
                req_model = deepcopy(data['params'])
                info = one_pairs.pop('info')
                req_params = pairs.get_request_json(req_model, one_pairs)
                req_params['headers'] = data['headers']
                req_params['url'] = data['host'] + data['address']
                req_params['method'] = data['method']

                if info.__contains__('无权限'):
                    pairs.check_auth(req_params, False)

                elif info.__contains__('失效/无效'):
                    pairs.set_auth_invalid(req_params)

                else:
                    pairs.check_auth(req_params, True)

                response = requests.request(**req_params)
                print("正在测试\033[0;31m{name}\033[0m".format(name=data['name']))
                print('请求地址================>{url}'.format(url=response.url))
                print('测试条件===========>\n{info}'.format(info=info))
                print("请求头===============>\n\033[0;32m{headers}\033[0m".format(headers=response.request.headers))
                try:
                    print("请求体===============>\n\033[0;32m{body}\033[0m".format(
                        body=response.request.body.decode('unicode-escape')))
                except AttributeError:
                    print("\033[0;31m无请求体\033[0m")
                if response.status_code != 200:
                    print('\033[0;31m状态码都不是200，还测个啥？？？？赶紧打开bilibili学习啦\033[0m')
                    print('状态码为\033[0;31m{code}\033[0m'.format(code=response.status_code))
                    print('返回数据为\033[0;31m{data}\033[0m'.format(data=response.text))
                else:
                    print('状态码为\033[0;32m{code}\033[0m'.format(code=response.status_code))
                    print(
                        '响应时间为:{time}'.format(
                            time='\033[0;31m' + str(int(response.elapsed.total_seconds() * 1000)) + 'ms\033[0m'
                            if response.elapsed.total_seconds() > 0.2
                            else '\033[0;32m' + str(int(response.elapsed.total_seconds() * 1000)) + 'ms\033[0m')
                    )
                    print('返回数据为===============>\n\033[0;32m{data}\033[0m'.format(data=response.text))
                print("===================分割线===================\n")
                sleep(1)

    pairs.cache.clear()

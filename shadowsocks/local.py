#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns

# sslocal 两个主要功能
# 1. 做socks5 服务端, 负责监听本地socks5协议的请求
# 2. 加密数据, 并向远程的ssservser发送数据包


def main():
    shell.check_python()

    # fix py2exe
    # 如果将python程序转为exe可执行程序则进入如下配置
    if hasattr(sys, "frozen") and sys.frozen in \
            ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)

    config = shell.get_config(True)

    daemon.daemon_exec(config)

    try:
        logging.info("starting local at %s:%d" %
                     (config['local_address'], config['local_port']))

        # 生成dns寻址器
        dns_resolver = asyncdns.DNSResolver()
        # 生成tcp服务器
        tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
        # 生成udp服务器
        udp_server = udprelay.UDPRelay(config, dns_resolver, True)

        # 生成loop循环结构
        loop = eventloop.EventLoop()
        # 将dns寻址器, tcp服务器, upd服务器加入loop实例
        dns_resolver.add_to_loop(loop)
        tcp_server.add_to_loop(loop)
        udp_server.add_to_loop(loop)

        def handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            tcp_server.close(next_tick=True)
            udp_server.close(next_tick=True)
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        daemon.set_user(config.get('user', None))
        loop.run()
    except Exception as e:
        shell.print_exception(e)
        sys.exit(1)


if __name__ == '__main__':
    main()

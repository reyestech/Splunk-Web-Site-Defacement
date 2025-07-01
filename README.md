![Boss of the SOC](https://github.com/user-attachments/assets/523985a4-07ce-4084-a36c-52a2243e502e)

<h1> Splunk | Website Defacement </h1>
Hector M. Reyes  | SOC Analysis | Boss of the SOC 

[Google Docs Link | Splunk: Website Defacement](https://docs.google.com/document/d/1yfkpx3jznk6c5z8mrRk0SUCVaO03F9aNqglNuQ8HQSE/pub)

<div align="center">
  <img src="https://github.com/user-attachments/assets/aa505c5a-cad1-49ef-96b1-62fa6f2c2272" width="50%" alt="Splunk Image"/>
</div>

---

## Intro to the Web Defacement
Today is Alice's first day at Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her the first assignment: A memo from the Gotham City Police Department (GCPD). GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com, hosted on Wayne Enterprises' IP address space, has been compromised. The group has multiple objectives, but a key aspect of their modus operandi is defacing websites to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com (the personal blog of Wayne Corporation’s CEO) was compromised.

### Tools Used
> - Splunk | SIEM (Security Information and Event Management)
> - Windows Sandbox | Sandboxie-Plus
> - VirusTotal | AlientVault 
> - md5decrypt | REX Expressions

<div align="center">
  <img src="https://github.com/user-attachments/assets/cbdab132-71d3-4776-b254-bf15536e2354" width="60%" alt="spl43"/>
</div>

---

## Pre-Engagement
We need to examine two pieces of evidence before we begin our investigation.  First, we have Alice's journal, which dates from September 1, 2016, to September 13, 2016. Here, she documents the events of her day, allowing us to see events from her perspective. Then, we have the "Mission Document." Here, you can learn about our APT group, Poison Ivy.  We get a look at the suspects from the GCPD's point of view.

- <b> GCPD memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html
- <b> Alice's journal: https://botscontent.netlify.app/v1/alice-journal.html

<img src="https://github.com/reyestech/Splunk-Web-Site-Defacement/assets/153461962/73ea7b7f-5f81-47bb-9520-bea78b35fb88" width="55%" alt="giphy"/>

## Defacement 101: Find the Suspects (Pictures 1.1 – 1.4)

What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities? 
- <b>Using index= "botsv1," we searched for imreallynotbatman.com. (Picture 1.1)
- <b> When looking at fields on the left-hand side, we see Src_ip has 3 IP Addresses, and our target is the one with the most traffic. (Pictures 1.2)
- <b> You can check each IP Address's traffic to see if something fishy pops up. (Picture 1.3)
- <b> Enter Search: index="botsv1" imreallynotbatman.com
- <b> index=”botsv1” *poisonivy
 Answer: 40.80.148.42

Pictures 1.1 <br/>
<img src="https://i.imgur.com/COhw0VL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Pictures 1.2 <br/>
<img src="https://i.imgur.com/XejCZz1.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Pictures 1.3 <br/>
<img src="https://i.imgur.com/eqZ0Tl2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Pictures 1.4 <br/> 
<img src="https://i.imgur.com/W14EP4a.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 
<br/><br/>
 
## Defacement Step 102: Expose the Target (Pictures 1.5-1.6) 
What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

- <b> We continue looking through the “INTERESTING FIELDS” on the left side, in Src_header, which has Po1s0n1vy/40.80.148.42 traffic using a network vulnerability scanner, Acunetix. (Picture 1.5)  <br /> 
- <b> Answer: Acunetix

Pictures 1.5 <br/>
<img src="https://i.imgur.com/NktL4Z4.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


Pictures 1.6 <br/>
<img src="https://i.imgur.com/TYFA5e0.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

    
## Defacement Step 103: Look through the contents (Pictures 1.7)

 What content management system is imreallynotbatman.com likely using? 
- <b> We Googled which Content Management Systems (CMS) are most commonly used and saw some examples of what the domain could be using. 
- <b> WordPress, Magento, and Joomla are some of the most common.
- <b> Using Ctrl F, we found imreallynotbatman.com is using Joomla when we expanded the src_headers.
- <b> Answer: Joomla
  
Pictures 1.7 <br/>
<img src="https://i.imgur.com/vsk77i8.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


## Defacement Step 104: Find the target’s .exe file (Pictures 1.8 – 1.9)

What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the file name with the extension.
Answer guidance: For example, "notepad.exe" or "favicon.ico"
- <b> In the field HTTP. When we see an http_content_type of “image/jpeg”, we open it and see a .jpeg file associated with it. 
- Answer: Poisonivy-is-coming-for-you-batman.jpeg
 - <b> 	Pictures 1.8

Pictures 1.8 <br/> 
<img src="https://i.imgur.com/Sgyscoo.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
Pictures 1.9 <br/>
<img src="https://i.imgur.com/k1ZotyJ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
 
## Defacement Step 105: Target’s FQDN (Pictures 2.0) 

This attack used dynamic DNS to resolve the malicious IP. What fully qualified domain name (FQDN) is associated with this attack? <br /> 
- <b> In the same JPEG image file, you can see the FQDN prankglassinebracket.jumpingcrab.com. (Pictures 2.0)
- <b> Answer: Prankglassinebracket.jumpingcrab.com

Pictures 2.0 <br/>
<img src="https://i.imgur.com/oMIN67E.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

## Defacement Step 106: Get the dest_ip (Pictures 2.1) 

What IPv4 address has Po1s0n1vy tied to pre-staged domains to attack Wayne Enterprises? <br /> 
- <b> Then, we look for “dest_ip” in the text to find the IP Address associated with Wayne Enterprises.
- <b> Answer: 23.22.63.114

Pictures 2.1 <br/> 
<img src="https://i.imgur.com/Th6eN5T.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

## Defacement Step 108: Brute-force attacks leave a Network trail (Pictures 2.2)

What IPv4 address is likely attempting a brute-force password attack against imreallynotbatman.com? <br /> 
- <b> We can use the dest_ip to query what IP Address has been hitting the server using the query “sourcetype=stream” “ dest_ip” and head to src_ip. We see 99% for IP 23.22.63.114.
- <b> Enter Search: index="botsv1" sourcetype="stream:HTTP" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
- <b> Answer: 23.22.63.114

Pictures 2.2 <br/> 
<img src="https://i.imgur.com/5rf8PPf.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

## Defacement Step 109: Filenames (Pictures 2.3)

What is the name of the executable uploaded by Po1s0n1vy? <br /> 
Answer guidance: Please include the file extension. (For example, "notepad.exe" or "favicon.ico") <br /> 
- <b> Since we already have Po1s0n1vy’s network traffic, we can filter it by adding “.exe” to our index.
- <b> We find 3791.exe in the “fileinfo.filename." When we open it, we see that Po1s0n1vy uploaded it.
- <b> Enter Search: index="botsv1" sourcetype="suricata" dest_ip="192.168.250.70" http.http_method=POST .exe
- <b> Answer: 3791.exe

Pictures 2.3 <br/>
<img src="https://i.imgur.com/HFaDtm7.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

## Defacement Step 110: Crowd Source your way to a solution (Pictures 2.3)

What is the MD5 hash of the executable uploaded? 
- <b> Using AlientVault.com, we input the target’s IP address and examine the traffic details. We then find the SHA-Hash.
- <b> The command “|stats values (MD5)” inputs the IP and sees its traffic to verify the details.
- <b> Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0


Pictures 2.4 <br/> 
<img src="https://i.imgur.com/sRy6nnt.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


Pictures 2.5 <br/> 
<img src="https://i.imgur.com/ITOJ9DC.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 
<br/><br/>

## Defacement Step 111: Scan the IPv4 (Pictures 2.6) 

GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if the initial compromise fails, are to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys' initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware. <br /> 
- <b> We can use tools like Virustotal.com to scan the attacker’s IP address. This allows us to see the SHA256 found under the basic properties.                                                        
- <b> Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

Pictures 2.6 <br/>
<img src="https://i.imgur.com/JbHQUel.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


<h2> Defacement Step 112: Let's find Steve to buy him a beer (Pictures 2.7-2.8)</h2> 

What special hex code is associated with the customized malware discussed in question 111? <br /> 
Answer guidance: It's not in Splunk!! <br /> 
We have the attacker’s IP traffic on Virustotal.com and his username, Botsv1.
- <b> We can search and control F to find hex codes and Botsv1s and compare them to the traffic and timeline the code should have been made. (Picture 2.7)
- <b> Using Cyberchef, we insert the hex code and output, 
- <b> “Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer.!!!” (Pictures 2.8)
- <b> Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21 

Pictures 2.7 <br/>
<img src="https://i.imgur.com/4kk3brN.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Pictures 2.8 <br/> 
<img src="https://i.imgur.com/iYJYhLn.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 
<br/><br/>

## Defacement Step 114: When you are lost, return to basics (Pictures 2.9) 

What was the first brute-force password used? <br /> 
- <b> At first, you might get lost and overwhelmed by the hundreds of entries that could have your password. However, our search narrows when we return to the prior query, filter, and sort entries by date.
- <b> Go back to our index= "botsv1 query. " Remove the .exe and replace it with "| table _time form_data" to see the needed detail sorted by event time and date. We can head to the earliest date and see the first password attempted.
- <b> Enter Search: index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd* | table _time form_data
- <b> Answer: 12345678

Pictures 2.9 <br/> 
<img src="https://i.imgur.com/cLAp26f.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


## Defacement Step 115: Google is your best friend (Pictures 3.0-3.1) 

One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six-character word on this one. Which is it? <br /> 
- <b> Look online for Coldplay songs that contain only six characters.
- <b> We found 37 songs, in total, that James could have used. (Pictures 3.0)
- <b> We can cross-check from our index in Splunk and filter for passwords for the number of characters and length. 
- <b>We can use the “|” to insert the passwords we think might work. </b> Rinse and repeat until you have searched through all the songs.
- <b> Use “| where userpassword in” ("insert_1", "insert_1", "insert_1", "insert_1"")
- <b> Enter Search: index="botsv1" sourcetype=" stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | eval pwlen=len(userpassword) | search pwlen=6 | where - <b> userpassword in ("clocks", "oceans", "sparks", "shiver", "yellow") | table userpassword
- <b> Answer: Yellow (Pictures 3.1)

Pictures 3.0 <br/> 			
<img src="https://i.imgur.com/XQlhrA9.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


Pictures 3.1 <br/> 
<img src="https://i.imgur.com/OdfFsLm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 
<br/><br/>

## Defacement Step 116: Rex expressions (Pictures 3.2-3.3)

What was the correct password for admin access to the content management system running "imreallynotbatman.com"? <br /> 
- <b> Using the previous query from 114, we can look at adding rex expressions. 
- <b> Remove the password filter by count and add “| rex field=form_data” and | stats count by to get the amount. 
- <b> Now that we see the accessed passwords, we can sort them by count from top to bottom.
- <b> Batman has been used more than once, whereas the others seem only to have been accessed once. (Picture 3.2)
- <b> From here, we can open Batman to verify our suspicion. (Picture 3.3)
- <b> Enter Search: index="botsv1" sourcetype="stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | rex field=form_data "passwd=(?<userpassword>\w+)" | stats count by userpassword
- <b> Answer: Batman

Pictures 3.2 <br/> 	
<img src="https://i.imgur.com/OdfFsLm.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 

Pictures 3.3 <br/> 
<img src="https://i.imgur.com/WekBYMr.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


# Defacement Step 117: The Means (Pictures 3.4-3.5)

What was the average password length used in the password brute-forcing attempt? <br /> 
Answer guidance: Round to the closest whole integer. For example, "5" is not "5.23213" <br /> 
- <b> We know we have all the information in this index. We can start by organizing the data by using “| eval length=len(passwd) “ and heading to the “length” in INTERESTING FIELDS. And we see an average of 6. (Picture 3.7)
- <b> I also found that you can use “| eval length=len(passwd) “ and “| stats avg(length)” in our query to get the integer. (Picture 3.8)
- <b> Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd 
- <b> Enter Search: | rex field=form_data "passwd=(?<passwd>\w+)" | eval length=len(passwd) | stats avg(length)
- <b> Answer: 6

Pictures 3.4 <br/> 
<img src="https://i.imgur.com/32gRWnC.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Pictures 3.5 <br/>
<img src="https://i.imgur.com/swQisHs.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


## Defacement Step 118: Round 2 (Pictures 3.6) 

How many seconds elapsed between when the brute force password scan identified the correct password and the compromised login? <br /> 
Answer guidance: Round to 2 decimal places. <br /> 
- <b>Search for the password “batman” and filter the transaction and event duration filters. </b>
- <b> We use a “| transaction userpassword|  and “eval dur=round(duration, 2).” 
- <b> The “dur” field on the left shows 92.17.
- <b> Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd  | rex field=form_data "passwd=(?<passwd>\w+)"  | search passwd=batman | transaction passwd | eval dur=round(duration, 2) | table dur
- <b> Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd  | rex field=form_data "passwd=(?<passwd>\w+)"  | search passwd=batman  | transaction passwd | eval dur=round(duration, 2)
- <b> Answer: 92.17

Pictures 3.6 <br/>
<img src="https://i.imgur.com/JfGoFi8.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

How many unique passwords were attempted in the brute force attempt? <br /> 
- <b> We have two options from here: We can once again stay in the same query, remove the transaction filters, and filter it by events.
- <b> We can use the “ | stats dc by userpassword.”  
- Or we can go back to 116, since we searched by password events in that query and sorted them by count.
- <b> Instead, in that query, we can go to the “Statistics” bar and see that there are 412 events in total. Answer: 412	
- <b> Pictures 43..9

Pictures 3. <br/> 
<img src="https://i.imgur.com/oPq0f8K.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

Finding Diagrams  

<img src="https://i.imgur.com/gtZkjEX.png" height="80%" width="80%" alt="Disk Sanitization Steps"/> 


## Conclusion

This project showcases how Splunk can be utilized to detect and investigate website defacement attacks. Focusing on the subject company as the target, we analyzed logs to identify suspicious activities that resulted in alterations made by a hacker group. The process involved tracking unusual web traffic, identifying malicious IP addresses, and connecting various clues to understand how the attack occurred. 

By working through a realistic and common cybersecurity scenario, we explored Splunk's tools for monitoring threats and responding to incidents. This project emphasizes the importance of staying informed about best practices in cybersecurity and the critical skills required of a Security Analyst: data analysis, investigation of security issues, and the use of leading tools to safeguard digital environments. These are essential competencies for anyone pursuing a role in cybersecurity.
 











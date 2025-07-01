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
- GCPD memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html
- Alice's journal: https://botscontent.netlify.app/v1/alice-journal.html

<div align="center">
  <img src="https://github.com/reyestech/Splunk-Web-Site-Defacement/assets/153461962/73ea7b7f-5f81-47bb-9520-bea78b35fb88" width="60%" alt="giphy"/>
</div>

---

## Defacement 101: Find the Suspects (Pictures 1.1 – 1.4)
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities? 
- Using index= "botsv1," we searched for imreallynotbatman.com. (Picture 1.1)
- When looking at fields on the left-hand side, we see Src_ip has 3 IP Addresses, and our target is the one with the most traffic. (Pictures 1.2)
- You can check each IP Address's traffic to see if something fishy pops up. (Picture 1.3)
- Enter Search: index="botsv1" imreallynotbatman.com
- index=”botsv1” *poisonivy
- Answer: 40.80.148.42

Pictures 1.1 <br/>
<img src="https://github.com/user-attachments/assets/a1a91d56-9231-4446-974c-0c7eabffa4d6" width="40%" alt="Splunk Defacement - Pictures 1.1"/>

Pictures 1.2 <br/>
<img src="https://github.com/user-attachments/assets/e3d90817-1c5d-43c4-9213-5e2389c4efc2" width="60%" alt="Splunk Defacement - Pictures 1.2"/>

Pictures 1.3 <br/>
<img src="https://github.com/user-attachments/assets/b0763a8f-7295-4ca3-adb8-29d343d1ba67" width="60%" alt="Splunk Defacement - Pictures 1.3"/>

Pictures 1.4 <br/>
<img src="https://github.com/user-attachments/assets/7b1bb136-8e91-43ce-b6b0-86752fffce81" width="60%" alt="Splunk Defacement - Pictures 1.4"/>


## Defacement Step 102: Expose the Target (Pictures 1.5-1.6) 
What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.
- We continue looking through the “INTERESTING FIELDS” on the left side, in Src_header, which has Po1s0n1vy/40.80.148.42 traffic using a network vulnerability scanner, Acunetix. (Picture 1.5) 
- Answer: Acunetix

Pictures 1.5 <br/>
<img src="https://github.com/user-attachments/assets/1445a24a-fd6f-4aac-bf3a-6bd8257db97f" width="30%" alt="Splunk Defacement - Pictures 1.5"/>

Pictures 1.6 <br/>
<img src="https://github.com/user-attachments/assets/87d4c6b0-528d-4768-94ca-834aa2f449ad" width="60%" alt="Splunk Defacement - Pictures 1.6"/>


## Defacement Step 103: Look through the contents (Pictures 1.7)
What content management system is imreallynotbatman.com likely using? 
- We Googled which Content Management Systems (CMS) are most commonly used and saw some examples of what the domain could be using. 
- WordPress, Magento, and Joomla are some of the most common.
- Using Ctrl F, we found imreallynotbatman.com is using Joomla when we expanded the src_headers.
- Answer: Joomla

Pictures 1.7 <br/>
<img src="https://github.com/user-attachments/assets/9c4a4a0e-357c-472b-8889-2f84837dc576" width="55%" alt="Splunk Defacement - Pictures 1.7"/>


## Defacement Step 104: Find the target’s .exe file (Pictures 1.8 – 1.9)
What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the file name with the extension.
Answer guidance: For example, "notepad.exe" or "favicon.ico"
- In the field HTTP. When we see an http_content_type of “image/jpeg”, we open it and see a .jpeg file associated with it. 
- Answer: Poisonivy-is-coming-for-you-batman.jpeg

Pictures 1.8 <br/>
<img src="https://github.com/user-attachments/assets/65676b1a-b556-4974-a7a6-d746be3ef6c5" width="60%" alt="Splunk Defacement - Pictures 1.8"/>

Pictures 1.9 <br/>
<img src="https://github.com/user-attachments/assets/6140c651-1d52-4433-9672-9b12ac8a7d15" width="65%" alt="Splunk Defacement - Pictures 1.9"/>


## Defacement Step 105: Target’s FQDN (Pictures 2.0) 
This attack used dynamic DNS to resolve the malicious IP. What fully qualified domain name (FQDN) is associated with this attack? <br /> 
- In the same JPEG image file, you can see the FQDN prankglassinebracket.jumpingcrab.com. (Pictures 2.0)
- Answer: Prankglassinebracket.jumpingcrab.com

Pictures 2.0 <br/>
<img src="https://github.com/user-attachments/assets/bfa888cc-31ba-48b2-9970-71ab99ee5609" width="60%" alt="Splunk Defacement - Pictures 2.0"/>


## Defacement Step 106: Get the dest_ip (Pictures 2.1) 
What IPv4 address has Po1s0n1vy tied to pre-staged domains to attack Wayne Enterprises? <br /> 
- Then, we look for “dest_ip” in the text to find the IP Address associated with Wayne Enterprises.
- Answer: 23.22.63.114

Pictures 2.1 <br/>
<img src="https://github.com/user-attachments/assets/45dda3ca-d0de-415e-8cf8-55186478d963" width="40%" alt="Splunk Defacement - Pictures 2.1"/>


## Defacement Step 108: Brute-force attacks leave a Network trail (Pictures 2.2)
What IPv4 address is likely attempting a brute-force password attack against imreallynotbatman.com? <br /> 
- We can use the dest_ip to query what IP Address has been hitting the server using the query “sourcetype=stream” “ dest_ip” and head to src_ip. We see 99% for IP 23.22.63.114.
- Enter Search: index="botsv1" sourcetype="stream:HTTP" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
- Answer: 23.22.63.114

Pictures 2.2 <br/>
<img src="https://github.com/user-attachments/assets/08f4c7ab-f891-4453-9b5d-a56fbaa6d1b5" width="60%" alt="Splunk Defacement - Pictures 2.2"/>


## Defacement Step 109: Filenames (Pictures 2.3)
What is the name of the executable uploaded by Po1s0n1vy? <br /> 
Answer guidance: Please include the file extension. (For example, "notepad.exe" or "favicon.ico") <br /> 
- Since we already have Po1s0n1vy’s network traffic, we can filter it by adding “.exe” to our index.
- We find 3791.exe in the “fileinfo.filename." When we open it, we see that Po1s0n1vy uploaded it.
- Enter Search: index="botsv1" sourcetype="suricata" dest_ip="192.168.250.70" http.http_method=POST .exe
- Answer: 3791.exe

Pictures 2.3 <br/>
<img src="https://github.com/user-attachments/assets/dd743112-5bf9-4c1e-abd2-74ffcb6c0bf1" width="50%" alt="Splunk Defacement - Pictures 2.3"/>


## Defacement Step 110: Crowd Source your way to a solution (Pictures 2.3)
What is the MD5 hash of the executable uploaded? 
- Using AlientVault.com, we input the target’s IP address and examine the traffic details. We then find the SHA-Hash.
- The command “|stats values (MD5)” inputs the IP and sees its traffic to verify the details.
- Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

Pictures 2.4 <br/>
<img src="https://github.com/user-attachments/assets/331ec5b7-1b8a-48f8-8229-f829f78b9b4b" width="60%" alt="Splunk Defacement - Pictures 2.4"/>

Pictures 2.5 <br/>
<img src="https://github.com/user-attachments/assets/c24be66d-17a3-491d-a97f-6746cffa6e4f" width="60%" alt="Splunk Defacement - Pictures 2.5"/>


## Defacement Step 111: Scan the IPv4 (Pictures 2.6) 
GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if the initial compromise fails, are to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys' initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.
- We can use tools like Virustotal.com to scan the attacker’s IP address. This allows us to see the SHA256 found under the basic properties.                                                 
- Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

Pictures 2.6 <br/>
<img src="https://github.com/user-attachments/assets/4b8e44d5-d71a-44de-8e3a-48554d77dee5" width="60%" alt="Splunk Defacement - Pictures 2.6"/>


## Defacement Step 112: Let's find Steve to buy him a beer (Pictures 2.7-2.8)
What special hex code is associated with the customized malware discussed in question 111? <br /> 
Answer guidance: It's not in Splunk!! <br /> 
We have the attacker’s IP traffic on Virustotal.com and his username, Botsv1.
- We can search and control F to find hex codes and Botsv1s and compare them to the traffic and timeline the code should have been made. (Picture 2.7)
- Using Cyberchef, we insert the hex code and output, 
- “Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer.!!!” (Pictures 2.8)
- Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21 

Pictures 2.7 <br/>
<img src="https://github.com/user-attachments/assets/79c7cc85-19ce-4982-8c07-2beed3a45569" width="50%" alt="Splunk Defacement - Pictures 2.7"/>


Pictures 2.8 <br/>
<img src="https://github.com/user-attachments/assets/939b7095-4d34-46c5-82e9-fe1b10848a23" width="50%" alt="Splunk Defacement - Pictures 2.8"/>


## Defacement Step 114: When you are lost, return to basics (Pictures 2.9) 
What was the first brute-force password used? 
- At first, you might get lost and overwhelmed by the hundreds of entries that could have your password. However, our search narrows when we return to the prior query, filter, and sort entries by date.
- Go back to our index= "botsv1 query. " Remove the .exe and replace it with "| table _time form_data" to see the needed detail sorted by event time and date. We can head to the earliest date and see the first password attempted.
- Enter Search: index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd* | table _time form_data
- Answer: 12345678

Pictures 2.9 <br/>
<img src="https://github.com/user-attachments/assets/5fcbbf5c-9949-448c-ab78-daf65d1a2740" width="50%" alt="Splunk Defacement - Pictures 2.9"/>


## Defacement Step 115: Google is your best friend (Pictures 3.0-3.1) 
One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six-character word on this one. Which is it? <br /> 
- Look online for Coldplay songs that contain only six characters.
- We found 37 songs, in total, that James could have used. (Pictures 3.0)
- We can cross-check from our index in Splunk and filter for passwords for the number of characters and length. 
- We can use the “|” to insert the passwords we think might work. </b> Rinse and repeat until you have searched through all the songs.
- Use “| where userpassword in” ("insert_1", "insert_1", "insert_1", "insert_1"")
- Enter Search: index="botsv1" sourcetype=" stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | eval pwlen=len(userpassword) | search pwlen=6 | where - <b> userpassword in ("clocks", "oceans", "sparks", "shiver", "yellow") | table userpassword
- Answer: Yellow (Pictures 3.1)

Pictures 3.0 <br/>
<img src="https://github.com/user-attachments/assets/3d2d9308-fbde-4ed2-9265-641e3f0ea2e3" width="30%" alt="Splunk Defacement - Pictures 3.0"/>

Pictures 3.1 <br/>
<img src="https://github.com/user-attachments/assets/d05a8280-ffab-4da7-a8d6-a026f1fc5b10" width="50%" alt="Splunk Defacement - Pictures 3.1"/>


## Defacement Step 116: Rex expressions (Pictures 3.2-3.3)
What was the correct password for admin access to the content management system running "imreallynotbatman.com"? <br /> 
- Using the previous query from 114, we can look at adding rex expressions. 
- Remove the password filter by count and add “| rex field=form_data” and | stats count by to get the amount. 
- Now that we see the accessed passwords, we can sort them by count from top to bottom.
- Batman has been used more than once, whereas the others seem only to have been accessed once. (Picture 3.2)
- From here, we can open Batman to verify our suspicion. (Picture 3.3)
- Enter Search: index="botsv1" sourcetype="stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | rex field=form_data "passwd=(?<userpassword>\w+)" | stats count by userpassword
- Answer: Batman

Pictures 3.2 <br/>
<img src="https://github.com/user-attachments/assets/843b75e6-34a7-4a79-8a9c-dbc9d9eb5fb1" width="50%" alt="Splunk Defacement - Pictures 3.2"/>

Pictures 3.3 <br/>
<img src="https://github.com/user-attachments/assets/debc9f50-8bd5-4a38-b3c2-cc32ef7040f6" width="60%" alt="Splunk Defacement - Pictures 3.3"/>


## Defacement Step 117: The Means (Pictures 3.4-3.5)
What was the average password length used in the password brute-forcing attempt? <br /> 
Answer guidance: Round to the closest whole integer. For example, "5" is not "5.23213" <br /> 
- We know we have all the information in this index. We can start by organizing the data by using “| eval length=len(passwd) “ and heading to the “length” in INTERESTING FIELDS. And we see an average of 6. (Picture 3.7)
- I also found that you can use “| eval length=len(passwd) “ and “| stats avg(length)” in our query to get the integer. (Picture 3.8)
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd 
- Enter Search: | rex field=form_data "passwd=(?<passwd>\w+)" | eval length=len(passwd) | stats avg(length)
- Answer: 6

Pictures 3.4 <br/>
<img src="https://github.com/user-attachments/assets/28b1e057-150b-4320-98d5-a47f9e559b16" width="30%" alt="Splunk Defacement - Pictures 3.4"/>

Pictures 3.5 <br/>
<img src="https://github.com/user-attachments/assets/c0bb6fd8-4ae2-4650-9c3b-b1e19f561669" width="40%" alt="Splunk Defacement - Pictures 3.5"/>


## Defacement Step 118: Round 2 (Pictures 3.6) 
How many seconds elapsed between when the brute force password scan identified the correct password and the compromised login? <br /> 
Answer guidance: Round to 2 decimal places. <br /> 
- Search for the password “batman” and filter the transaction and event duration filters. </b>
- We use a “| transaction userpassword|  and “eval dur=round(duration, 2).” 
- The “dur” field on the left shows 92.17.
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd  | rex field=form_data "passwd=(?<passwd>\w+)"  | search passwd=batman | transaction passwd | eval dur=round(duration, 2) | table dur
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd  | rex field=form_data "passwd=(?<passwd>\w+)"  | search passwd=batman  | transaction passwd | eval dur=round(duration, 2)
- Answer: 92.17

Pictures 3.6 <br/>
<img src="https://github.com/user-attachments/assets/aef083df-24eb-4b5d-9d5a-50193ebb0b79" width="40%" alt="Splunk Defacement - Pictures 3.6"/>


## Defacement 119: More than one way to do it (Pictures 3.6) 
How many unique passwords were attempted in the brute force attempt? <br /> 
- <b> We have two options from here: We can once again stay in the same query, remove the transaction filters, and filter it by events.
- <b> We can use the “ | stats dc by userpassword.”  
- Or we can go back to 116, since we searched by password events in that query and sorted them by count.
- <b> Instead, in that query, we can go to the “Statistics” bar and see that there are 412 events in total. Answer: 412	
- <b> Pictures 43..9

Pictures 3.7 <br/>
<img src="https://github.com/user-attachments/assets/ec303263-24e8-4894-bb01-595d3a23cd5c" width="60%" alt="Splunk Defacement - Pictures 3.7"/>


## Conclusion
This project showcases how Splunk can be utilized to detect and investigate website defacement attacks. Focusing on the subject company as the target, we analyzed logs to identify suspicious activities that resulted in alterations made by a hacker group. The process involved tracking unusual web traffic, identifying malicious IP addresses, and connecting various clues to understand how the attack occurred. 

By working through a realistic and common cybersecurity scenario, we explored Splunk's tools for monitoring threats and responding to incidents. This project emphasizes the importance of staying informed about best practices in cybersecurity and the critical skills required of a Security Analyst: data analysis, investigation of security issues, and the use of leading tools to safeguard digital environments. These are essential competencies for anyone pursuing a role in cybersecurity.

Finding Diagrams <br/>
<div align="center">
  <img src="https://github.com/user-attachments/assets/060ffd6d-d398-45ae-b0fc-fd25c2969820" width="80%" alt="Splunk Defacement - Finding Diagrams"/>
</div>



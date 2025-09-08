
<div align="center">
  <img src="https://github.com/user-attachments/assets/523985a4-07ce-4084-a36c-52a2243e502e" width="90%" alt="Boss of the SOC"/>
</div>

---

# Splunk: Website Defacement
### Splunk IR Lab — Website Defacement: From Signal to Root Cause
Hector M. Reyes  | Boss of the SOC | [Google Docs Link | Splunk: Website Defacement](https://docs.google.com/document/d/1yfkpx3jznk6c5z8mrRk0SUCVaO03F9aNqglNuQ8HQSE/pub)

![1733695831697](https://github.com/user-attachments/assets/516a7c9d-ed7b-4567-9546-40909bd70e6c)

---

## **Scenario**
GCPD reports that imreallynotbatman[.]com (hosted in Wayne Enterprises' space) was defaced by APT Po1s0n1vy. Your job is to confirm the defacement, reconstruct the path to compromise, and document hardening steps. The lab uses BOSS of the SOC v1 data and includes supporting artifacts (memo & journal).

## **Intro to the Web Defacement**
Today is Alice's first day at Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her the first assignment: A memo from the Gotham City Police Department (GCPD). GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com, hosted on Wayne Enterprises' IP address space, has been compromised. The group has multiple objectives, but a key aspect of their modus operandi is defacing websites to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com (the personal blog of Wayne Corporation's CEO) was compromised.

<div align="center">
  <img src="https://github.com/user-attachments/assets/cbdab132-71d3-4776-b254-bf15536e2354" width="60%" alt="spl43"/>
</div>

---

## Pre-Engagement
We must examine two pieces of evidence before beginning our investigation. First, we have Alice’s journal, which spans from September 1, 2016, to September 13, 2016. Here, she documents the events of her day, allowing us to see events from her perspective. Then, we have the “Mission Document.” Here, you can learn about our APT group, Poison Ivy. We get a look at the suspects from the GCPD perspective.
- GCPD memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html
- Alice's journal: https://botscontent.netlify.app/v1/alice-journal.html

### 📦 Tools Reference 

| Category     | Tool / Feature             | Purpose                                              |
| ------------ | -------------------------- | ---------------------------------------------------- |
| SIEM         | Splunk                     | Security Information and Event Management (SIEM)     |
| Sandbox      | Windows Sandbox            | Isolated Windows test environment                    |
| Sandbox      | Sandboxie-Plus             | Lightweight application sandboxing                   |
| Threat Intel | VirusTotal                 | Multi-engine malware scanning and file/URL analysis  |
| Threat Intel | AlienVault OTX             | Threat intelligence and community-shared indicators  |
| Hash/Regex   | md5decrypt                 | Online MD5 hash lookup / cracking                    |
| Hash/Regex   | RegEx (Regular Expressions)| Pattern matching and data extraction                 |

---

## Defacement 101: Find the Suspects
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?
- Using index= "botsv1," we searched for imreallynotbatman.com. `Picture 1.1`
- When looking at fields on the left-hand side, we see Src_ip has 3 IP Addresses, and our target is the one with the most traffic. `Picture 1.2`
- You can check each IP Address's traffic to see if something fishy pops up. `Picture 1.3`
- Enter Search: index="botsv1" imreallynotbatman.com
- index=”botsv1” *poisonivy
- [ ] **Answer:** 40.80.148.42


<img src="https://github.com/user-attachments/assets/a1a91d56-9231-4446-974c-0c7eabffa4d6" width="40%" alt="Splunk Defacement - Picture 1.1"/>

`Picture 1.1`

<img src="https://github.com/user-attachments/assets/e3d90817-1c5d-43c4-9213-5e2389c4efc2" width="60%" alt="Splunk Defacement - Picture 1.2"/>

`Picture 1.2`

<img src="https://github.com/user-attachments/assets/b0763a8f-7295-4ca3-adb8-29d343d1ba67" width="60%" alt="Splunk Defacement - Picture 1.3"/>

`Picture 1.3`

<img src="https://github.com/user-attachments/assets/7b1bb136-8e91-43ce-b6b0-86752fffce81" width="60%" alt="Splunk Defacement - Picture 1.4"/>

`Picture 1.4`

---

## Defacement Step 102: Expose the Target 
What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.
- We continue looking through the “INTERESTING FIELDS” on the left side, in Src_header, which has Po1s0n1vy/40.80.148.42 traffic using a network vulnerability scanner, Acunetix. `Picture 1.5`
- [ ] **Answer:** Acunetix

<img src="https://github.com/user-attachments/assets/1445a24a-fd6f-4aac-bf3a-6bd8257db97f" width="30%" alt="Splunk Defacement - Picture 1.5"/>

`Picture 1.5`

<img src="https://github.com/user-attachments/assets/87d4c6b0-528d-4768-94ca-834aa2f449ad" width="60%" alt="Splunk Defacement - Picture 1.6"/>

`Picture 1.6`

---

## Defacement Step 103: Look Through the Contents
What content management system is imreallynotbatman.com likely using? 
- We Googled which Content Management Systems (CMS) are most commonly used and saw some examples of what the domain could be using. 
- WordPress, Magento, and Joomla are some of the most common.
- Using Ctrl F, we found imreallynotbatman.com is using Joomla when we expanded the src_headers.
- [ ] **Answer:** Joomla

<img src="https://github.com/user-attachments/assets/9c4a4a0e-357c-472b-8889-2f84837dc576" width="55%" alt="Splunk Defacement - Picture 1.7"/>

`Picture 1.7`

---

## Defacement Step 104: Find the Target .exe File
What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the file name with the extension.
> Answer guidance: For example, "notepad.exe" or "favicon.ico"
- In the field HTTP. When we see an HTTP content type of “image/jpeg”, we open it and see a .jpeg file associated with it. 
- [ ] **Answer:** Poisonivy-is-coming-for-you-batman.jpeg

<img src="https://github.com/user-attachments/assets/65676b1a-b556-4974-a7a6-d746be3ef6c5" width="60%" alt="Splunk Defacement - Picture 1.8"/>

`Picture 1.8`

<img src="https://github.com/user-attachments/assets/6140c651-1d52-4433-9672-9b12ac8a7d15" width="65%" alt="Splunk Defacement - Picture 1.9"/>

`Picture 1.9`

---

## Defacement Step 105: Target’s FQDN 
This attack utilized dynamic DNS to resolve the malicious IP address. What fully qualified domain name (FQDN) is associated with this attack? <br /> 
- In the same JPEG image file, you can see the FQDN prankglassinebracket.jumpingcrab.com. `Picture 2.0`
- [ ] **Answer:** Prankglassinebracket.jumpingcrab.com

<img src="https://github.com/user-attachments/assets/bfa888cc-31ba-48b2-9970-71ab99ee5609" width="60%" alt="Splunk Defacement - Picture 2.0"/>

`Picture 2.0`

---

## Defacement Step 106: Get the dest_ip
What IPv4 address is likely attempting a brute-force password attack against imreallynotbatman.com?
- We can use the dest_ip to query what IP Address has been hitting the server using the query "sourcetype=stream" " dest_ip" and head to src_ip. We see 99% for IP 23.22.63.114.
- Enter Search: index="botsv1" sourcetype="stream:HTTP" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
- [ ] **Answer:** 23.22.63.114

<img src="https://github.com/user-attachments/assets/45dda3ca-d0de-415e-8cf8-55186478d963" width="40%" alt="Splunk Defacement - Picture 2.1"/>

`Picture 2.1`

---

## Defacement Step 108: Brute-force Attacks Leave a Network Trail
What IPv4 address is likely attempting a brute-force password attack against imreallynotbatman.com? <br /> 
- We can use the dest_ip to query what IP Address has been hitting the server using the query "sourcetype=stream" "dest_ip" and head to the src_ip. We see 99% for IP 23.22.63.114.
- Enter Search: index="botsv1" sourcetype="stream:HTTP" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
- [ ] Answer: 23.22.63.114

<img src="https://github.com/user-attachments/assets/08f4c7ab-f891-4453-9b5d-a56fbaa6d1b5" width="60%" alt="Splunk Defacement - Picture 2.2"/>

`Picture 2.2`

---

## Defacement Step 109: Filenames
What is the name of the executable uploaded by Po1s0n1vy?
> Answer guidance: Please include the file extension. (For example, "notepad.exe" or "favicon.ico")
- Since we already have Po1s0n1vy's network traffic, we can filter it by adding ".exe" to our index.
- We find 3791.exe in the "fileinfo. Filename. " When we open it, we see that Po1s0n1vy uploaded it.
- Enter Search: index="botsv1" sourcetype="suricata" dest_ip="192.168.250.70" http.http_method=POST .exe
- [ ] **Answer:** 3791.exe

<img src="https://github.com/user-attachments/assets/dd743112-5bf9-4c1e-abd2-74ffcb6c0bf1" width="50%" alt="Splunk Defacement - Picture 2.3"/>

`Picture 2.3`

---

## Defacement Step 110: Crowdsource Your Way To a Solution
What is the MD5 hash of the executable uploaded? 
- Using AlienVault.com, we input the target's IP address and examine the traffic details. We then find the SHA-Hash.
- The command "|stats values (MD5)" inputs the IP and sees its traffic to verify the details.
- [ ] **Answer:** AAE3F5A29935E6ABCC2C2754D12A9AF0

<img src="https://github.com/user-attachments/assets/331ec5b7-1b8a-48f8-8229-f829f78b9b4b" width="60%" alt="Splunk Defacement - Picture 2.4"/>

`Picture 2.4`

<img src="https://github.com/user-attachments/assets/c24be66d-17a3-491d-a97f-6746cffa6e4f" width="60%" alt="Splunk Defacement - Picture 2.5"/>

`Picture 2.5`

---

## Defacement Step 111: Scan the IPv4 
GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if the initial compromise fails, are to send a spear phishing email with custom malware attached to their intended target. This malware is typically associated with Po1s0n1vys' initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.
- We can use tools like Virustotal.com to scan the attacker's IP address. This allows us to see the SHA256 found under basic properties.
- [ ] **Answer:** 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

<img src="https://github.com/user-attachments/assets/4b8e44d5-d71a-44de-8e3a-48554d77dee5" width="60%" alt="Splunk Defacement - Picture 2.6"/>

`Picture 2.6`

---

## Defacement Step 112: Let's Buy Steve a Beer
What special hex code is associated with the customized malware discussed in question 111?
> Answer guidance: It's not in Splunk!!
- We have the attacker's IP traffic in Virustotal.com and his username, Botsv1.
- We can search and control F to find hex codes and Botsv1s and compare them to the traffic and timeline the code should have been made. `Pictures 2.7`
- Using Cyberchef, we insert the hex code and output,
- "Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer.!!!" `Pictures 2.8`
- [ ] **Answer:** ```53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21```

<img src="https://github.com/user-attachments/assets/79c7cc85-19ce-4982-8c07-2beed3a45569" width="50%" alt="Splunk Defacement - Picture 2.7"/>

`Picture 2.7`

<img src="https://github.com/user-attachments/assets/939b7095-4d34-46c5-82e9-fe1b10848a23" width="50%" alt="Splunk Defacement - Picture 2.8"/>

`Picture 2.8`

---

## Defacement Step 114: Return to Basics 
What was the first brute-force password used?
- At first, you might get lost and overwhelmed by the hundreds of entries that could have your password. However, our search narrows when we return to the prior query, filter, and sort entries by date.
- Go back to our index "botsv1 query. " Remove the .exe and replace it with "| table _time form_data" to see the needed detail sorted by event time and date. We can head to the earliest date and see the first password attempted.
- Enter Search: index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd* | table _time form_data
- [ ] **Answer:** 12345678

<img src="https://github.com/user-attachments/assets/5fcbbf5c-9949-448c-ab78-daf65d1a2740" width="50%" alt="Splunk DefacemEnterprises'e 2.9"/>

`Picture 2.9`

---

## Defacement Step 115: Google's Your Friend
One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six-character word on this one. Which is it?
- You can look online for Coldplay songs that have only six characters.
- We found 37 songs, in total, that James could have used. `Pictures 3.0`
- We can cross-check from our index in Splunk and filter for passwords for the number of characters and length.
- We can use the pipe or "|" to insert the passwords we think could work. Rinse and repeat until you have searched through all the songs.
- Use "| where userpassword in" ("insert_1", "insert_1", "insert_1", "insert_1"")
- Enter Search: index="botsv1" sourcetype=" stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | eval pwlen=len(userpassword) | search pwlen=6 | where userpassword in ("clocks", "oceans", "sparks", "shiver", "yellow") | table userpassword
- [ ] **Answer:** Yellow `Picture 3.1`

<img width="484" height="275" alt="image" src="https://github.com/user-attachments/assets/6b05ae7c-c97e-4978-8af1-dc388486b443" />

`Picture 3.0`

<img width="553" height="286" alt="image" src="https://github.com/user-attachments/assets/6c05e6d8-2c69-49ed-8180-0580be59ea97" />

`Picture 3.1`

---

## Defacement Step 116: Rex Expressions
What was the correct password for admin access to the content management system running "imreallynotbatman.com"?
- Using the previous query from 114, we can look at adding rex expressions.
- Remove the password filter by count and add "| rex field=form_data" and | stats count by to get the amount.
- Now that we see the accessed passwords, we can sort them by count from top to bottom.
- Batman has been used more than once, whereas the others seem to have been accessed once. `Pictures 3.2`
- From here, we can open Batman to verify our suspicion. `Pictures 3.3`
- Enter Search: index="botsv1" sourcetype="stream:http" http_method=POST dest_ip="192.168.250.70" form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | rex field=form_data "passwd=(?<userpassword>\w+)" | stats count by userpassword
- [ ] **Answer:** Batman

<img width="451" height="106" alt="image" src="https://github.com/user-attachments/assets/ea1a2300-46b9-47ff-9ef8-66e0797512e9" />

`Picture 3.2`

<img width="664" height="144" alt="image" src="https://github.com/user-attachments/assets/6d22290d-e140-4150-aa1b-978ad055cb50" />

`Picture 3.3`

---

## Defacement Step 117: The Means 
What was the average password length used in the password brute-forcing attempt?
> Answer guidance: Round to the closest whole integer. For example, "5" is not "5.23213"
- We are confident that we have all the necessary information in this index. We can start by organizing the data by using "| eval length=len(passwd) " and heading to the "length" in INTERESTING FIELDS. And we see an average of 6. `Pictures 3.4`
- I also found that you can use "| eval length=len(passwd) " and "| stats avg(length)" in our query to get the integer. `Pictures 3.5`
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd
- Enter Search: | rex field=form_data "passwd=(?<passwd>\w+)" | eval length=len(passwd) | stats avg(length)
- [ ] **Answer:** 6

<img width="734" height="175" alt="image" src="https://github.com/user-attachments/assets/4516dee3-4fbe-410f-91cf-464ff1a0ea25" />

`Picture 3.4`

<img width="653" height="196" alt="image" src="https://github.com/user-attachments/assets/393edc19-cd81-4877-97f8-19b0550453b7" />

`Picture 3.5`

---

## Defacement Step 118: Round Two 
How many seconds elapsed between when the brute force password scan identified the correct password and the compromised login?
> Answer guidance: Round to 2 decimal places.
- Search for the password "batman" and filter the transaction and event durations.
- We use a "| transaction userpassword| and "eval dur=round(duration, 2)."
- The "dur" field on the left shows 92.17.
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd | rex field=form_data "passwd=(?<passwd>\w+)" | search passwd=batman | transaction passwd | eval dur=round(duration, 2) | table dur
- Enter Search: index=botsv1 imreallynotbatman.com sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" username passwd | rex field=form_data "passwd=(?<passwd>\w+)" | search passwd=batman | transaction passwd | eval dur=round(duration, 2)
- [ ] **Answer:** 92.17

<img width="563" height="277" alt="image" src="https://github.com/user-attachments/assets/be2aebe0-85bd-4f53-b308-06c75c7af1be" />

`Picture 3.6`

---

## Defacement 119: More Than One Way
How many unique passwords were attempted in the brute force attempt?
- We have two options from here: We can once again stay in the same query, remove the transaction filters, and filter it by events.
- We can use the " | stats dc by userpassword."
- Alternatively, we can go back to 116, as we searched for password events in that query and sorted them by count.
- Instead, in that query, we can go to the "Statistics" bar and see that there are 412 events in total.
- [ ] **Answer:** 412

<img src="https://github.com/user-attachments/assets/ec303263-24e8-4894-bb01-595d3a23cd5c" width="60%" alt="Splunk Defacement - Picture 3.7"/>

`Picture 3.7`

---

## 🔄 **Recap — Step by Step**
| Phase                  | Implementation                                             | Purpose                                  |
| --------------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Bound the Window      | Mark first complaint + last known-good render              | Keep searches tight and relevant         |
| Surface Scanners      | Find noisy sources probing the domain                      | Identify likely entry/pressure points    |
| Fingerprint the Stack | Confirm CMS/tech (e.g., Joomla)                            | Narrow vuln paths & admin/upload areas   |
| Prove Defacement      | Locate altered artifact + exact change time                | Validate impact and anchor the timeline  |
| Pivot to POSTs/Uploads| Trace requests right before change; inspect form data      | Reveal upload vectors and abused routes  |
| Auth Precursors       | Detect failed → success bursts / credential stuffing       | Tie credential misuse to the compromise  |
| Map Attacker Infra    | Extract dynamic-DNS FQDNs + staging IPs                    | Attribute infra; expand IoCs             |
| Tie to Victim Host    | Confirm destination IP serving defaced content             | Link activity to affected hosts          |
| Collect IoCs & Evidence | Capture IPs, UAs, filenames, hashes, screenshots        | Support containment & post-mortems       |
| Contain & Recover     | Block IoCs, restore clean files, rotate credentials        | Stop activity and return to good state   |
| Harden                | WAF/rate limits, restrict uploads/admin, tune FIM          | Reduce recurrence & shrink attack surface|
| Operationalize        | Save searches, alerts/dashboards, document runbook         | Make response repeatable and faster      |

---

## 📚 **Lessons Learned**
- [ ] **Visibility triad wins:** Web + Auth + FIM/IDS together told the full story.
     - File integrity, HTTP, and authentication logs, together, told the whole story - individually, they fell short.
- [ ] **Correlation over single signals:** Small clues become decisive when chained.
   - A stray JPEG, a brute-force login spike, or a POST to an upload path may mean little alone, but they become decisive when correlated.
- [ ] **Repeatability wins:** Turn ad-hoc queries into alerts/dashboards to cut toil.
   - Turning one-off queries into alerts and dashboards is how IR teams scale from reactive to proactive.
- [ ] **Context elevates detections:** VirusTotal lookups + decoded artifacts increase confidence.
   - Pivoting to VirusTotal and decoding artifacts sharpened attribution and raised confidence in the findings.
- [ ] **Evidence discipline:** IoCs + screenshots enable clean handoffs and audits.
    - Capturing IoCs and screenshots made the investigation auditable and ready for handoff.

<img width="392" height="558" alt="image" src="https://github.com/user-attachments/assets/dca220e9-9d45-4217-8b67-d8d35991f64a" />

---

## 🏁 **Conclusion**
This lab demonstrates how Splunk can turn raw logs into a clear timeline of compromise, containment, and hardening. By defining a time window, correlating data from multiple sources, and operationalizing detections, we not only confirmed the defacement but also created a repeatable playbook for future incidents.

In real-world Incident Response, the same rhythm applies: observe → correlate → validate → harden. Practicing this in labs builds the muscle memory so that when alerts are real, the workflow feels intuitive and efficient.

👉 **Next Up**: Ransomware IR Lab—early encryption signals, process lineage, and lateral movement.

<img width="536" height="343" alt="image" src="https://github.com/user-attachments/assets/bec354d2-ff0d-42b8-b29d-564524caf570" />

---

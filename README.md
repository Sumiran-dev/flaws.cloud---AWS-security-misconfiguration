 # 🔐 flaws.cloud – AWS Security Misconfiguration Report  
*A hands-on AWS security challenge completed by Sumiran Bastola*

![image](https://github.com/user-attachments/assets/b1536fa8-858e-4859-98d9-a7b72c4aa60c)

---

## 📖 Overview

**flaws.cloud** is an interactive challenge platform that simulates common AWS misconfigurations across services like S3, IAM, EC2, and EBS. I completed all 6 levels of this challenge using AWS CLI, Kali Linux (via Parallels VM), and a free-tier AWS account.

Each level reflects a real-world attack scenario, and I documented how I approached the problem, the vulnerabilities I found, challenges faced, and how such flaws can be mitigated in production environments.

This report includes a walkthrough of each level, lessons learned, and screenshots as proof of concept.

---

## 🧰 Tools Used

- **Operating System**: Kali Linux (running in Parallels VM)
- **Cloud Platform**: AWS Free Tier Account
- **AWS CLI v2**: For enumeration and exploitation
- **curl**: For SSRF and metadata testing
- **Browser**: For URL-based file discovery
- **Git**: For analyzing version control history
- **SSH**: For EC2 access
- **AWS Console**: For EC2 instance and volume management

---

## 📁 Challenge Levels

---

## 🪣 Level 1: Public S3 Bucket Enumeration

**Objective**: Enumerate and access content from a publicly exposed S3 bucket.

**Approach**:  
I started with domain enumeration using basic networking commands and identified the S3 bucket region. After attempting regular S3 CLI access and getting denied, I used the `--no-sign-request` flag to bypass credential checks. This successfully listed the contents of the public bucket.

![image](https://github.com/user-attachments/assets/af939567-ae23-4441-8d7b-547832acce0b)

![image](https://github.com/user-attachments/assets/9e57f30d-8c13-4776-9337-dfb2726852be)
![image](https://github.com/user-attachments/assets/f572f206-039b-46ad-ab7e-d78db62883ee)


**Lessons Learned**:
- Public S3 buckets with “List” permissions are easily accessible.
- Anonymous users can extract sensitive files if misconfigured.

**Remediation**:
- Block all public access to S3.
- Implement the principle of least privilege.

---

## 🔓 Level 2: Authenticated User Access

**Objective**: Access a bucket configured for "any authenticated AWS user".
![image](https://github.com/user-attachments/assets/c55e8d5a-d218-4770-bbdd-590fa32decfb)

**Approach**:  
I created a low-permission IAM user in my own AWS account. Using this IAM user’s credentials, I was able to access the bucket, since AWS treats *any authenticated user* across any AWS account as valid.

![image](https://github.com/user-attachments/assets/78e148ab-93ce-42d9-bc95-9e61a61d7627)

![image](https://github.com/user-attachments/assets/f63a7a5b-b1fc-4aa1-a312-ad0a891b2c99)

**Lessons Learned**:
- AWS allows cross-account access if a bucket policy permits "AuthenticatedUsers".
- This mistake is common in dev/staging environments.

**Remediation**:
- Use specific AWS account IDs or user ARNs in bucket policies.
- Never use `"Principal": "*"` for internal services.

---

## 🕵️ Level 3: Git Credentials Leak

**Objective**: Discover leaked AWS credentials in Git commit history.
![image](https://github.com/user-attachments/assets/fc59e834-9143-4b4d-81d2-795d4f60d78b)


**Approach**:  
I synced the bucket locally and discovered a hidden `.git` directory. I inspected the Git log and checked out an older commit that contained plaintext AWS credentials in a file named `access_keys.txt`. I used these credentials to access new buckets.

![image](https://github.com/user-attachments/assets/374fc638-e5c6-45d7-af9b-633dfd5fa090)

![image](https://github.com/user-attachments/assets/9c905d07-f09f-4117-aea0-6978923b4a77)

![image](https://github.com/user-attachments/assets/4d1680e1-2df3-4bc5-9c39-34f8716c4fe3)

![image](https://github.com/user-attachments/assets/43706fda-fbd0-47d8-9542-895662888596)

**Lessons Learned**:
- Committing secrets to version control can result in full compromise.
- Even deleted credentials remain in Git history.

**Remediation**:
- Use `.gitignore` to exclude sensitive files.
- Scan repos with tools like `git-secrets` or `truffleHog`.
- Rotate access keys frequently.

---

## 💽 Level 4: Unencrypted EBS Snapshot Exploitation

![image](https://github.com/user-attachments/assets/f8419a75-20fb-4b24-a8a0-dfe4e42e3e9b)

**Objective**: Mount a public EBS snapshot and extract login credentials.

**Approach**:  
I listed publicly available EBS snapshots and created a volume from one of them in my AWS account. I launched an EC2 instance, attached the volume, and SSH’d into the instance. After mounting the volume, I navigated to the user’s home directory and found a script file containing the EC2 credentials.
![image](https://github.com/user-attachments/assets/b76aa9b9-9c32-4546-b83f-0cb26fc4d9e2)
![image](https://github.com/user-attachments/assets/1b7ee4d9-9dfb-4946-9800-320976f3e21f)

![image](https://github.com/user-attachments/assets/decf931b-ccbd-47b1-81a5-a8f606cba69b)

![image](https://github.com/user-attachments/assets/c68bc542-0207-4f61-8959-5d5b2231968c)

![image](https://github.com/user-attachments/assets/42cda600-ad37-47d0-84b9-3d26e6ab988b)

![image](https://github.com/user-attachments/assets/ecfc0c35-48ac-4ce8-8503-cdb9f7b2a026)

![image](https://github.com/user-attachments/assets/84ed1cad-bea8-4ab7-b5ab-df5c5f40391d)

![image](https://github.com/user-attachments/assets/646e535d-0d0f-45da-a2cb-00737dc626e8)

![image](https://github.com/user-attachments/assets/016fde49-9761-4159-858e-3103a3854d46)

![image](https://github.com/user-attachments/assets/92bec151-324a-4eed-9076-43c6eba6fed3)

**Lessons Learned**:
- Public and unencrypted snapshots can be used to reconstruct entire systems.
- Sensitive data like passwords and configs can easily be extracted.

**Remediation**:
- Encrypt EBS snapshots and volumes.
- Remove unnecessary snapshot sharing.
- Avoid storing credentials in plain text on disk.

---

## 🌐 Level 5: Metadata Service Exploitation (SSRF)

**Objective**: Exploit a proxy that accesses the EC2 metadata API.
![image](https://github.com/user-attachments/assets/4028156d-f041-4beb-91cf-30ba55e8da32)

**Approach**:  
I used the provided domain to access `169.254.169.254` through a vulnerable proxy. This gave me temporary credentials for a high-privilege IAM role. I configured these credentials in AWS CLI and used them to list the next bucket.
![image](https://github.com/user-attachments/assets/e929b22f-ed1a-4c44-99e2-14670a25d221)

![image](https://github.com/user-attachments/assets/cb031fc7-c54b-4a67-9e94-930b506ec6d7)

![image](https://github.com/user-attachments/assets/1dd5ceb9-b2fe-4f35-a5cd-59fca0af84e7)

![image](https://github.com/user-attachments/assets/d593d581-15c5-4ef7-a97a-4eb5d917ffcc)

![image](https://github.com/user-attachments/assets/0cb9c258-ead3-46a9-afbb-8cc981461884)

**Lessons Learned**:
- IMDSv1 is vulnerable to SSRF attacks.
- Attackers can steal temporary credentials via web app bugs.

**Remediation**:
- Enforce IMDSv2 on all instances.
- Protect metadata IP via firewall/security group rules.
- Never expose internal URLs to external users.

---

## 🛠️ Level 6: IAM Policy Misconfiguration

**Objective**: Abuse over-permissive IAM policies to discover and invoke hidden Lambda functions.
![image](https://github.com/user-attachments/assets/c8eacffd-9759-45e0-b40a-d4a2e7022021)

**Approach**:  
I enumerated attached policies and noticed that the `SecurityAudit` policy was attached to the IAM user. This allowed me to list all Lambda functions and associated API Gateways. Using the discovered endpoint, I invoked the function and completed the challenge.
![image](https://github.com/user-attachments/assets/796cec17-d318-40ea-97a2-92532e270e16)

![image](https://github.com/user-attachments/assets/108d0aea-6e55-4a20-8eb4-35a028449f4b)

![image](https://github.com/user-attachments/assets/0366feee-4d8c-4caa-b167-20fbdc558215)

![image](https://github.com/user-attachments/assets/bf06583e-4624-4aec-934b-d3dd5225aa1a)

![image](https://github.com/user-attachments/assets/9edb31ac-58e8-4971-9430-d8e9673bd9ad)

![image](https://github.com/user-attachments/assets/dc6a599c-a2e1-4617-94fe-ad4eac41ba15)


**Lessons Learned**:
- Overly broad IAM permissions expose critical infrastructure.
- AWS managed policies like `SecurityAudit` should not be used by regular users.

**Remediation**:
- Follow the principle of least privilege.
- Use scoped, custom IAM policies.
- Audit IAM roles and attached policies regularly.

---

## 📊 Summary of Flaws & Fixes

| Level | Vulnerability                     | Description                                      | Remediation                                    |
|-------|----------------------------------|--------------------------------------------------|------------------------------------------------|
| 1     | Public S3 Bucket                 | Bucket listing allowed without credentials       | Block public access, least privilege           |
| 2     | Authenticated User Bucket Access| Any AWS user could access the bucket             | Restrict to specific accounts/roles            |
| 3     | Leaked AWS Keys in Git          | Git commit history revealed access keys          | Avoid committing secrets, rotate credentials   |
| 4     | Public EBS Snapshot             | Unencrypted snapshot leaked credentials          | Encrypt & restrict snapshot access             |
| 5     | EC2 Metadata Exposure           | SSRF exposed IAM credentials                     | Use IMDSv2, restrict access                     |
| 6     | IAM Policy Misconfiguration     | Over-permissioned policies leaked API endpoints  | Use custom scoped IAM policies                 |

---

## ✅ What I Learned

- Real-world cloud security vulnerabilities can often result from small oversights.
- Attackers exploit trust boundaries across accounts and services.
- Enumeration is the most powerful step in the attacker’s playbook.
- AWS CLI is an invaluable tool for both attackers and defenders.

---


## 🙌 Final Thoughts

Completing the flaws.cloud challenge gave me real-world experience in identifying and exploiting AWS misconfigurations, as well as understanding how to fix them properly.

I recommend this challenge to anyone interested in cloud security, red teaming, or incident response.

---


**Challenge**: [flaws.cloud](https://flaws.cloud)  
**Focus Areas**: AWS Misconfigurations, IAM Security, Cloud Enumeration, Defense in Depth

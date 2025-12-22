
rule Backdoor_Linux_Mirai_A_AMTB{
	meta:
		description = "Backdoor:Linux/Mirai.A!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 30 36 2e 32 34 38 2e 32 35 31 2e 31 38 39 } //1 106.248.251.189
		$a_01_1 = {2f 74 6d 70 2f 2e 62 6f 74 5f 6c 6f 63 6b } //1 /tmp/.bot_lock
		$a_01_2 = {63 64 20 2f 72 6f 6f 74 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 63 61 74 2e 73 68 } //1 cd /root wget http://%s/cat.sh
		$a_01_3 = {30 6d 50 61 73 73 77 6f 72 64 } //1 0mPassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
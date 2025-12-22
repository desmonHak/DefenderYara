
rule Trojan_Win64_Vidar_GTD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //1 File Grabber Rules
		$a_01_1 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //1 Wallet Rules
		$a_01_2 = {43 68 72 6f 6d 69 75 6d 20 50 6c 75 67 69 6e 73 } //1 Chromium Plugins
		$a_01_3 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //1 Loader Tasks
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 00 a0 82 97 84 81 81 8c c2 d8 c3 dd } //2
		$a_01_6 = {44 48 46 4a 48 48 50 4b 4c 51 5c 0b 46 4a 48 25 } //2 䡄䩆䡈䭐兌ଡ଼䩆╈
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=9
 
}
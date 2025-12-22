
rule Trojan_Win64_VidarStealer_RH_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 74 65 6c 65 67 72 61 6d 2e 6d 65 2f 6b 30 64 64 72 } //2 //telegram.me/k0ddr
		$a_01_1 = {43 68 72 6f 6d 69 75 6d 20 50 6c 75 67 69 6e 73 } //1 Chromium Plugins
		$a_01_2 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //1 File Grabber Rules
		$a_01_3 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //1 Wallet Rules
		$a_01_4 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //1 Browser List
		$a_01_5 = {46 69 72 65 66 6f 78 20 50 6c 75 67 69 6e 73 } //1 Firefox Plugins
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}
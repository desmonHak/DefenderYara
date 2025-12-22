
rule Trojan_Win64_Stealer_AHC_MTB{
	meta:
		description = "Trojan:Win64/Stealer.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 6f 6d 65 3a 43 72 79 70 74 6f 2e 63 6f 6d 20 44 65 46 69 20 57 61 6c 6c 65 74 } //10 Chrome:Crypto.com DeFi Wallet
		$a_01_1 = {43 68 72 6f 6d 65 3a 4a 61 78 78 20 4c 69 62 65 72 74 79 } //20 Chrome:Jaxx Liberty
		$a_01_2 = {49 6e 73 74 61 6c 6c 65 64 20 61 6e 74 69 76 69 72 75 73 20 70 72 6f 67 72 61 6d 73 20 3a 20 25 73 } //30 Installed antivirus programs : %s
		$a_01_3 = {43 72 79 70 74 6f 20 77 61 6c 6c 65 74 20 62 72 6f 77 73 65 72 20 65 78 74 65 6e 73 69 6f 6e 73 20 3a } //40 Crypto wallet browser extensions :
		$a_81_4 = {41 74 6f 6d 69 63 20 57 61 6c 6c 65 74 } //50 Atomic Wallet
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40+(#a_81_4  & 1)*50) >=150
 
}
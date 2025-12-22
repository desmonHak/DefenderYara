
rule Trojan_Win64_Muddywater_GVA_MTB{
	meta:
		description = "Trojan:Win64/Muddywater.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 39 34 2e 31 31 2e 32 34 36 2e 31 30 31 3a 34 34 33 } //5 194.11.246.101:443
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 SOFTWARE\Microsoft\Cryptography
		$a_01_2 = {6d 61 69 6e 2e 72 75 6e 52 65 6d 6f 74 65 50 72 6f 78 79 52 65 6c 61 79 } //1 main.runRemoteProxyRelay
		$a_01_3 = {6d 61 69 6e 2e 47 65 6e 65 72 61 74 65 43 41 } //1 main.GenerateCA
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}

rule Trojan_Linux_MsfwBindShell_NA_{
	meta:
		description = "Trojan:Linux/MsfwBindShell.NA!!MsfwBindShell.gen!NA,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 50 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 85 c0 78 [0-0e] 51 48 89 e6 54 5e 6a 31 58 6a 10 5a 0f 05 6a 32 58 6a 01 5e 0f 05 6a 2b 58 99 52 52 54 5e 6a 1c 48 8d 14 24 0f 05 } //1
		$a_01_1 = {5e 48 31 c0 48 ff c0 0f 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
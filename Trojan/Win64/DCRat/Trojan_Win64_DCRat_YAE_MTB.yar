
rule Trojan_Win64_DCRat_YAE_MTB{
	meta:
		description = "Trojan:Win64/DCRat.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 0f be 0c 01 49 ff c0 03 ca 69 d1 ?? ?? ?? ?? 8b ca c1 e9 06 33 d1 4c 3b c0 75 e4 8d 04 d2 8b c8 c1 e9 0b 33 c8 } //1
		$a_01_1 = {4f 6e 6c 79 4e 6f 43 6f 6e 73 6f 6c 65 5c 73 76 63 2e 70 64 62 } //1 OnlyNoConsole\svc.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
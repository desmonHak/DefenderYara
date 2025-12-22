
rule Trojan_Win64_ShellCodeRunnz_ZA_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunnz.ZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 47 68 87 03 29 3b 87 03 29 3b 87 03 29 3b 54 71 2a 3a 82 03 29 3b 54 71 2c 3a 11 03 29 3b 54 71 2d 3a 8d 03 29 3b 26 74 2d 3a 89 03 29 3b 26 74 2a 3a 8e 03 29 3b 26 74 2c 3a b7 03 29 3b 54 71 28 3a 84 03 29 3b 87 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
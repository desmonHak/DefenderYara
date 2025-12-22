
rule Trojan_Win64_KillDisk_MX_MTB{
	meta:
		description = "Trojan:Win64/KillDisk.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6e c6 0f 57 c9 0f 5b c0 f3 0f 11 4c 24 2c 0f 2f c1 0f 86 a3 } //1
		$a_01_1 = {66 65 64 65 72 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 } //1 feder\source\repos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
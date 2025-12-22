
rule Trojan_Win32_CerberCrypt_RMX_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.RMX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 42 46 90 47 } //5
		$a_01_1 = {8a 06 90 32 c2 88 07 90 42 46 47 } //5
		$a_01_2 = {6a 40 68 00 10 00 00 68 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=6
 
}
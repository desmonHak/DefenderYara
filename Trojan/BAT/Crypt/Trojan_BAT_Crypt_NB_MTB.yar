
rule Trojan_BAT_Crypt_NB_MTB{
	meta:
		description = "Trojan:BAT/Crypt.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 00 00 65 4f fe 0e 05 00 fe 0d 05 00 00 48 68 39 00 00 00 00 02 73 22 00 00 0a 0a 38 00 00 00 00 } //2
		$a_01_1 = {07 08 6f 25 00 00 0a 08 6f 26 00 00 0a 0d dd 76 01 00 00 20 01 00 4e 0d fe 0e 05 00 fe 0d 05 00 00 48 68 d3 13 04 38 0a 00 00 00 } //1
		$a_01_2 = {6d 73 76 73 6d 6f 6e 2e 65 78 65 } //1 msvsmon.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
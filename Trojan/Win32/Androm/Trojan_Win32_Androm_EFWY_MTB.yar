
rule Trojan_Win32_Androm_EFWY_MTB{
	meta:
		description = "Trojan:Win32/Androm.EFWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 45 0c 33 c8 8d 04 33 33 c8 2b f9 8b cf 8b c7 } //2
		$a_01_1 = {8a 0c 1a 88 0c 02 42 8b 45 a0 3b d0 72 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
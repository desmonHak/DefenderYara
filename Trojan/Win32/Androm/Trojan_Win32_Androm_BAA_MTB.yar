
rule Trojan_Win32_Androm_BAA_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0e 8d 49 01 88 41 ff 42 8b 45 10 3b d0 72 } //2
		$a_01_1 = {8b c1 c1 e8 10 30 04 1a 42 3b 55 10 7c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
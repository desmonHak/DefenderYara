
rule Trojan_Win32_Jaik_BAA_MTB{
	meta:
		description = "Trojan:Win32/Jaik.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0f f6 d0 c0 c8 04 34 58 88 04 0f 41 3b ca 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
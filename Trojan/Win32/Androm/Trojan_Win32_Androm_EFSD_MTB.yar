
rule Trojan_Win32_Androm_EFSD_MTB{
	meta:
		description = "Trojan:Win32/Androm.EFSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce c1 e1 04 03 4d ec 33 c1 8d 0c 33 33 c1 2b f8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
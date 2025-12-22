
rule Trojan_Win32_Androm_BAD_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 54 1d ff 33 d7 f7 d2 88 54 18 ff 43 4e 75 ?? 59 5a 5d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
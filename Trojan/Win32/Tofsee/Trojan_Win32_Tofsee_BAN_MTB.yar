
rule Trojan_Win32_Tofsee_BAN_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 29 d3 31 d2 09 da 89 1f f8 83 d7 04 8d 49 fc } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
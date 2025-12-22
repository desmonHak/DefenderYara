
rule Trojan_Win64_Mikey_AC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 db 4c 8b d1 41 8b c3 41 b8 c0 02 00 00 41 ?? ?? ?? 44 39 59 10 ?? ?? 48 63 41 10 48 83 c8 01 48 0f bd c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
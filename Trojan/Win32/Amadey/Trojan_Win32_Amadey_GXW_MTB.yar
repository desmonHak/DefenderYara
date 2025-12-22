
rule Trojan_Win32_Amadey_GXW_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 f3 51 b9 00 00 00 00 01 d9 31 01 59 8b 1c 24 83 c4 } //5
		$a_03_1 = {31 eb 5d 53 81 2c 24 ?? ?? ?? ?? 8b 14 24 83 c4 04 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
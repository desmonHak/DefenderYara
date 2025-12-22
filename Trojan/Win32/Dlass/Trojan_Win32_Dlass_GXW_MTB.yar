
rule Trojan_Win32_Dlass_GXW_MTB{
	meta:
		description = "Trojan:Win32/Dlass.GXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ab ?? ?? ?? ?? 2b 6d 00 00 a2 ?? ?? ?? ?? 1f c4 98 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
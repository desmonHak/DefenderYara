
rule Trojan_Win32_AsyncRat_CBK_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.CBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce 8b c3 83 e1 ?? 8b d7 e8 ?? ?? 00 00 30 86 ?? ?? ?? ?? 46 81 fe 00 ?? 00 00 72 } //2
		$a_03_1 = {80 f9 40 73 ?? 80 f9 20 73 ?? 0f ad d0 d3 fa c3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}

rule Trojan_Win32_ValleyRat_CG_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f2 88 00 00 00 83 f2 66 8b 45 ?? 88 90 90 ?? ?? ?? ?? eb } //5
		$a_03_1 = {0f b6 82 00 ?? ?? ?? 83 f0 1a 8b 4d ?? 88 81 ?? ?? ?? ?? eb } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
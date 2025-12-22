
rule Trojan_Win32_ValleyRAT_NW_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 07 47 99 f7 f9 8b 46 08 8b 4d 10 80 c2 36 89 7d 08 32 14 08 88 14 01 b8 64 1d 00 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win32_ValleyRat_YAH_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 03 4d f4 0f b6 11 83 f2 21 8b 45 fc 03 45 f4 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
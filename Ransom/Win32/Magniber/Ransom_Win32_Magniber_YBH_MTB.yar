
rule Ransom_Win32_Magniber_YBH_MTB{
	meta:
		description = "Ransom:Win32/Magniber.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 8e a2 01 00 00 90 13 8a 9e 47 78 00 00 90 13 32 cb 90 13 88 0f 90 13 48 ff c6 eb 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
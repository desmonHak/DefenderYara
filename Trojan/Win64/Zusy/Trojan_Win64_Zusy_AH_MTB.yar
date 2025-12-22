
rule Trojan_Win64_Zusy_AH_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 ce 48 0f af ca 48 89 d7 48 31 f2 48 01 ca 48 89 f9 48 09 f7 49 89 c8 49 21 f0 49 31 f8 49 85 d0 ?? ?? 48 89 4c 24 18 48 89 ca 48 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_Win64_CobaltStrike_WH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 10 48 8b 4d 10 48 8b 45 f8 48 01 c8 83 f2 ?? 88 10 48 83 45 f8 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
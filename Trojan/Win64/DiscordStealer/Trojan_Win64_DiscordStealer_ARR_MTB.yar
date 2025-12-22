
rule Trojan_Win64_DiscordStealer_ARR_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d2 44 8b 44 24 ?? f7 f1 44 01 c2 89 54 24 } //2
		$a_03_1 = {89 c2 41 32 01 49 83 c1 ?? 0f b6 c0 c1 ea ?? 33 14 81 89 d0 4d 39 d1 } //8
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*8) >=10
 
}
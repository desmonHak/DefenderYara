
rule Trojan_Win64_PureLogsStealer_TBK_MTB{
	meta:
		description = "Trojan:Win64/PureLogsStealer.TBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 11 83 e0 ?? 29 c8 48 98 41 0f b6 04 01 41 30 04 10 48 83 c2 ?? 48 81 fa } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
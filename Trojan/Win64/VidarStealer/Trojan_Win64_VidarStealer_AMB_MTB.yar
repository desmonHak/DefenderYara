
rule Trojan_Win64_VidarStealer_AMB_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 ff c1 49 63 c9 42 8a 04 19 43 88 04 1a 42 88 1c 19 43 0f b6 0c 1a 48 03 cb 0f b6 c1 42 8a 0c 18 30 0f 48 ff c7 49 83 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
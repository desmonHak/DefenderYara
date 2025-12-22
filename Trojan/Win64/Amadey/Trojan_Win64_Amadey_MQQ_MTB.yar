
rule Trojan_Win64_Amadey_MQQ_MTB{
	meta:
		description = "Trojan:Win64/Amadey.MQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d8 83 e0 0f 0f b6 84 04 80 00 00 00 32 04 1e 41 88 04 19 48 83 c3 01 48 39 d9 75 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
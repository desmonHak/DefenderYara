
rule Trojan_Win64_Tedy_OKQ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.OKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 48 8d 52 01 0f b6 4c 3c 30 8d 04 31 0f b6 f0 0f b6 44 34 ?? 88 44 3c 30 88 4c 34 30 0f b6 44 3c 30 03 c1 0f b6 c0 0f b6 4c 04 30 30 4a ff 49 83 e8 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
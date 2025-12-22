
rule Trojan_Win64_Vidar_LPQ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.LPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 c8 48 8d 52 01 43 0f b6 0c 11 41 8d 04 0b 44 0f b6 d8 43 0f b6 04 13 43 88 04 11 43 88 0c 13 43 0f b6 04 11 48 03 c8 0f b6 c1 42 0f b6 0c 10 30 4a ff 49 83 e8 01 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
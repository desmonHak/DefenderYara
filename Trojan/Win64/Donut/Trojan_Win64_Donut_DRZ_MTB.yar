
rule Trojan_Win64_Donut_DRZ_MTB{
	meta:
		description = "Trojan:Win64/Donut.DRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 38 48 8d 40 01 80 f1 fb 88 48 ff 48 83 eb 01 75 ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
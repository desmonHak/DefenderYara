
rule Trojan_Win64_Zusy_ATR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 8b c8 8d 47 ?? 33 ca 2b ca 80 f9 ?? 0f 45 c7 46 } //3
		$a_03_1 = {09 f0 09 f8 8b 4c 24 ?? 89 04 a9 bf } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
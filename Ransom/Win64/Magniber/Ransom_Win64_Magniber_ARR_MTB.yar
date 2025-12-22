
rule Ransom_Win64_Magniber_ARR_MTB{
	meta:
		description = "Ransom:Win64/Magniber.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 18 18 5f 9b 55 d3 c4 31 f0 3a 57 4c } //20
		$a_03_1 = {8a 1e f6 fc b4 ?? 5e c9 86 4c 78 04 f6 f5 fc 03 7f a0 } //15
		$a_03_2 = {ea f6 ec ac 2d ?? ?? ?? ?? c0 6d 46 07 1c ?? 13 0f 11 f9 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*15+(#a_03_2  & 1)*5) >=40
 
}
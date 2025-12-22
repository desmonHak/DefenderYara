
rule Ransom_Win64_LockBit_MZZ_MTB{
	meta:
		description = "Ransom:Win64/LockBit.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 31 d2 45 31 da 44 30 14 06 c1 e5 0b 44 31 cd 45 89 d1 41 c1 e9 ?? 89 ea c1 ea 08 31 ea 44 31 d2 44 31 ca 30 54 06 01 45 89 d9 48 83 c0 02 49 39 c0 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
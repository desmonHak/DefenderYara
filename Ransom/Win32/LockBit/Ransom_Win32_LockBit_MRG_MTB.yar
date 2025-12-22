
rule Ransom_Win32_LockBit_MRG_MTB{
	meta:
		description = "Ransom:Win32/LockBit.MRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 d2 8a 9c 14 ?? ?? ?? ?? 00 d9 0f b6 f1 8a bc 34 b0 01 00 00 88 bc 14 b0 01 00 00 88 9c 34 b0 01 00 00 02 9c 14 b0 01 00 00 0f b6 f3 8a 9c 34 b0 01 00 00 30 1c 07 40 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
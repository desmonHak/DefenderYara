
rule Ransom_Win32_Mamona_AB_MTB{
	meta:
		description = "Ransom:Win32/Mamona.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a bd 6d 10 00 00 0f 94 45 ec 80 3d c4 6e 43 00 00 88 45 d2 8a 85 6f 10 00 00 88 45 d1 8a 85 71 10 00 00 88 45 c0 8a 85 73 10 00 00 88 45 b0 88 5d a0 74 22 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
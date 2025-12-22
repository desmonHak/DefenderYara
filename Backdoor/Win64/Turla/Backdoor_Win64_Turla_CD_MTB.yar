
rule Backdoor_Win64_Turla_CD_MTB{
	meta:
		description = "Backdoor:Win64/Turla.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 44 14 40 00 4c 8d 15 ?? ?? ?? ?? 80 7c 24 40 00 4c 8d 4c 24 40 74 3e 41 0f b6 02 84 c0 74 36 45 0f b6 01 41 8d 48 20 44 0f b6 d9 41 8d 50 bf 80 fa 19 8d 48 bf 45 0f 47 d8 80 f9 19 77 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
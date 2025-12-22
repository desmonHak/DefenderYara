
rule Trojan_Win64_Rhadamanthys_AHD_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 01 41 c0 c8 ?? 4d 89 db 44 88 01 4d 87 ff 90 90 4d 89 ff } //30
		$a_01_1 = {4d 87 f6 4d 89 f6 4d 87 f6 4d 89 f6 48 89 c0 48 89 db 48 89 c9 48 89 d2 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}
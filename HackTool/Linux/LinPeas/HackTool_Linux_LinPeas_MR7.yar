
rule HackTool_Linux_LinPeas_MR7{
	meta:
		description = "HackTool:Linux/LinPeas.MR7,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_80_0 = {2f 50 45 41 53 53 2d 6e 67 2f 50 45 41 53 53 2d 6e 67 2f } ///PEASS-ng/PEASS-ng/  2
	condition:
		((#a_80_0  & 1)*2) >=2
 
}
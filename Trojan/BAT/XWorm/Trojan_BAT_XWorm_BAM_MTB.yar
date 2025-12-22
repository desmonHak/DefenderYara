
rule Trojan_BAT_XWorm_BAM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 33 66 65 38 66 61 37 39 2d 35 64 63 65 2d 34 35 30 33 2d 61 62 32 33 2d 34 36 34 65 61 32 34 62 61 62 66 66 } //10 $3fe8fa79-5dce-4503-ab23-464ea24babff
		$a_81_1 = {4d 75 52 4c 7a 36 71 43 42 47 63 70 50 30 72 79 59 6f 4f 58 45 31 6b 65 57 76 4b 55 74 39 67 54 39 6f 38 4f 52 6e 69 4d 71 36 72 46 32 66 78 72 55 36 4a 59 70 } //10 MuRLz6qCBGcpP0ryYoOXE1keWvKUt9gT9o8ORniMq6rF2fxrU6JYp
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c } //1 Software\
		$a_81_3 = {37 53 68 5a 47 74 59 44 4e 42 4e 38 47 75 39 54 47 57 6e 4c 74 38 47 6b 32 4a 70 6e 67 69 6d 33 41 63 78 51 5a 63 5a 41 30 30 33 44 77 6d 57 65 53 31 52 67 64 44 71 61 } //10 7ShZGtYDNBN8Gu9TGWnLt8Gk2Jpngim3AcxQZcZA003DwmWeS1RgdDqa
		$a_81_4 = {76 43 42 42 58 62 42 79 35 7a 55 49 33 48 7a 66 42 6e 68 64 4d 41 32 42 42 47 33 46 55 73 6a 6b 6e 75 46 77 63 49 64 66 51 38 30 79 6e 52 7a 49 6e 77 62 36 4f 50 62 6b } //10 vCBBXbBy5zUI3HzfBnhdMA2BBG3FUsjknuFwcIdfQ80ynRzInwb6OPbk
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10) >=41
 
}
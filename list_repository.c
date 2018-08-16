#include <stdlib.h>					// standard library
#include <stdio.h>				// input and output library
#include <dirent.h>					// directory manipulation library
#include <string.h>						// string manipulation library

#ifndef WIN32						// if current program is not running on windows
    #include <sys/types.h> 		// typedef of directory object
#endif

# define SIZE_DEPTH 20					// maximum depth of folder recursivity
# define SIZE_NAME 50							// maximum size of a folder name

unsigned int CPT_FILE_FOUND;															// number of file found
unsigned int CPT_FILE_CRYPT;														// number of file under encryption operation
const unsigned char TAB_CRYPT[10]={0, 1, 2, 3, 4, 5, 6, 7, 8, 9};						// only for test : arbitrary key

void menu_initial(void)															// user menu
{
	printf("\n\n");
	printf("###############################\n");
	printf("#                             #\n");
	printf("#   massive encryption tool   #\n");
	printf("#                             #\n");
	printf("###############################\n\n\n");
	printf("IMPORTANT WARNINGS :\n\n");
	printf("Don't interrupt the program during encryption/decryption.\n");
	printf("Or data will be permanently lost.\n");
	printf("Also, use a random key and hide it to avoid data recovery.\n\n\n");
}

void visu_array(unsigned char *path_dir)			// only for test
{
	unsigned int cpt_l, cpt_c;
	
	for(cpt_l=0 ; cpt_l<SIZE_DEPTH ; cpt_l++)
	{
		for(cpt_c=0 ; cpt_c<SIZE_NAME ; cpt_c++)
		{
			printf("%02x ", path_dir[(cpt_l*SIZE_NAME)+cpt_c]);					// display HEX value, like a matrix (debug)
		}
		printf("\n");
	}
	
	printf("\n\n");
}

void string_concatenation(unsigned char *string_1, unsigned char *string_2)				// add str_2 to str_1
{
	unsigned int cpt_1, cpt_2;
	
	cpt_1=0;
	cpt_2=0;
	
	while(string_1[cpt_1]!=0)
	{
		cpt_1++;
	}
	
	while(string_2[cpt_2]!=0)
	{
		string_1[cpt_1]=string_2[cpt_2];
		cpt_2++;
		cpt_1++;
	}
}

void string_copy(unsigned char *string_1, unsigned char *string_2)						// copy str_2 to str_1
{
	unsigned int cpt;
	
	for(cpt=0 ; cpt<(SIZE_DEPTH*SIZE_NAME) ; cpt++)
	{
		string_1[cpt]=string_2[cpt];
	}
}

void crypt_intern(FILE *ptr_file)											// encryption core
{
	unsigned long int file_size, file_size_512, file_size_rest;						// size of the pointing file
	unsigned long int cpt_file;									// typical counter, to browse each byte of the file
	//unsigned char file_char;								// file bytes are recovered in this value
	unsigned char sector_tab[512]={0};									// array to store a sector of 512 bytes
	unsigned long int test_array[10]={0};						// to show encryption progress (not used yet)
	unsigned int cpt_sector;							// sector counter for sector recovery
	
	fseek(ptr_file, 0, SEEK_END);   						// warning : non portable routine, end of file is pointing
    file_size=ftell(ptr_file);									// return file size (in bytes number)
    file_size_512=(file_size/512);									// return file size (in 512 bytes sectors number)
    file_size_rest=(file_size&0x1FF);								// keep the rest of the division by 512 (0x1FF in hex format)
    
    for(cpt_file=0 ; cpt_file<file_size_512 ; cpt_file++)										// analysis by sector of 512 bytes : really fast, according to memory architecture
	{
		fseek(ptr_file, cpt_file*512, SEEK_SET);						// points to "cpt_file" sector
		
		for(cpt_sector=0 ; cpt_sector<512 ; cpt_sector++)
		{
			sector_tab[cpt_sector]=(unsigned char)fgetc(ptr_file);						// file bytes are recovered
		}
		
		for(cpt_sector=0 ; cpt_sector<512 ; cpt_sector++)
		{
			sector_tab[cpt_sector]=(sector_tab[cpt_sector]^TAB_CRYPT[cpt_sector%10]);							// XOR with the key (XOR keying)
		}
		
		fseek(ptr_file, cpt_file*512, SEEK_SET);								// points to "cpt_file" sector
		
		for(cpt_sector=0 ; cpt_sector<512 ; cpt_sector++)
		{
			fputc(sector_tab[cpt_sector], ptr_file);										// new file bytes (they are encrypted)
		}
	}
    
    for(cpt_file=0 ; cpt_file<file_size_rest ; cpt_file++)					// last sector (less than 512 bytes) is encrypted
    {
    	fseek(ptr_file, ((512*file_size_512)+cpt_file), SEEK_SET);
    	sector_tab[cpt_file]=(unsigned char)fgetc(ptr_file);					// file bytes are recovered
    }
    
    for(cpt_file=0 ; cpt_file<file_size_rest ; cpt_file++)
    {
    	fseek(ptr_file, ((512*file_size_512)+cpt_file), SEEK_SET);				
    	fputc(sector_tab[cpt_file], ptr_file);								// new file bytes (they are encrypted)
    }
    
    CPT_FILE_CRYPT++;																// one more file is encrypted
    printf("    %05d - %05d   done\n", CPT_FILE_CRYPT, CPT_FILE_FOUND);					// display its list number
}

void crypt_file(unsigned char *path_data)							// extraction of a file
{
	FILE *ptr_file=NULL;									// points to original file
	FILE *temp_ptr_file=NULL;							// points to original file (to avoid seg fault)
	
	ptr_file=fopen(path_data, "rb+");					// file is opened
	
	if(ptr_file==NULL)													// if the file doesn't exists (bad user operation during encryption)
	{
		printf("ERROR, can't open file :   %s\n", path_data);					// display errror message
	}
	else																	// normal case, the file is present
	{
		//CPT_FILE_CRYPT++;
		printf("Existing file :    ");							// advert user of correct file manipulation
		temp_ptr_file=ptr_file;												// because of possible change on ptr_file in direct assignement, a clone is created
		crypt_intern(temp_ptr_file);								// pointer is send to encryption operation
		fclose(ptr_file);										// file is closed at the end of encryption process
	}
}

void crypt_all_files(DIR *rep, unsigned char depth, unsigned char *path_dir)							// recursive search of file from the first directory
{
	unsigned char temp_string[SIZE_DEPTH*SIZE_NAME]={0}, ref_string[SIZE_DEPTH*SIZE_NAME]={0};		// string for file path manipulation
	unsigned int cpt;										// typical counter
	struct dirent *file_read = NULL;												// file or directory ID, structure of values (name and serial number)
	
	//visu_array(path_dir);
	
	string_concatenation(ref_string, path_dir);								// add to temporary string the name of original folder
	
	for(cpt=1 ; cpt<depth ; cpt++)											// according to the depth of the recursivity, add folder path
	{
		string_concatenation(ref_string, "/");
		string_concatenation(ref_string, &path_dir[cpt*SIZE_NAME]);
	}
	
	while((file_read=readdir(rep))!=NULL)										// while all the files present in the current folder are not checked
	{
		if(strcmp((file_read->d_name), ".")!=0)									// don't care of parent folder data
		{
			if(strcmp((file_read->d_name), "..")!=0)									// don't care of parent folder data
			{
				string_copy(temp_string, ref_string);										// last temp_string is cleared by a new one
				string_concatenation(temp_string, "/");										// separate the data file from the current depth position
				string_concatenation(temp_string, file_read->d_name);					// get the name of the pointing data name
				
				if(opendir(temp_string)==NULL)												// if a file is pointing
				{
					crypt_file(temp_string);											// encrypt this file, giving the way to find it
					//printf("file found : %s\n", file_read->d_name);							// debug display
				}
				else																	// else, a directory is pointing
				{
					for(cpt=0 ; cpt<SIZE_NAME ; cpt++)							// current depth level path is cleared
					{
						path_dir[(depth*SIZE_NAME)+cpt]=0;					// put 0 in the array
					}
					
					string_concatenation(&path_dir[depth*SIZE_NAME], file_read->d_name);			// add the folder name to continue recursive search
					
					if(depth<=19)								// if the maximum level of recursivity is not reached
					{
						crypt_all_files(opendir(temp_string), depth+1, path_dir);				// recursive call with a new depth level and a new folder name
					}
				}
			}
		}
	}
}

void find_all_files(DIR *rep, unsigned char depth, unsigned char *path_dir)							// recursive search of file from the first directory
{
	unsigned char temp_string[SIZE_DEPTH*SIZE_NAME]={0}, ref_string[SIZE_DEPTH*SIZE_NAME]={0};		// string for file path manipulation
	unsigned int cpt;										// typical counter
	struct dirent *file_read = NULL;												// file or directory ID, structure of values (name and serial number)
	
	//visu_array(path_dir);
	
	string_concatenation(ref_string, path_dir);								// add to temporary string the name of original folder
	
	for(cpt=1 ; cpt<depth ; cpt++)											// according to the depth of the recursivity, add folder path
	{
		string_concatenation(ref_string, "/");
		string_concatenation(ref_string, &path_dir[cpt*SIZE_NAME]);
	}
	
	while((file_read=readdir(rep))!=NULL)										// while all the files present in the current folder are not checked
	{
		if(strcmp((file_read->d_name), ".")!=0)									// don't care of parent folder data
		{
			if(strcmp((file_read->d_name), "..")!=0)									// don't care of parent folder data
			{
				string_copy(temp_string, ref_string);										// last temp_string is cleared by a new one
				string_concatenation(temp_string, "/");										// separate the data file from the current depth position
				string_concatenation(temp_string, file_read->d_name);					// get the name of the pointing data name
				
				if(opendir(temp_string)==NULL)												// if a file is pointing
				{
					printf("File found : %s\n", temp_string);							// file path is displayed on screen
					//printf("file found : %s\n", file_read->d_name);
					CPT_FILE_FOUND++;
				}
				else																	// else, a directory is pointing
				{
					for(cpt=0 ; cpt<SIZE_NAME ; cpt++)							// current depth level path is cleared
					{
						path_dir[(depth*SIZE_NAME)+cpt]=0;					// put 0 in the array
					}
					
					string_concatenation(&path_dir[depth*SIZE_NAME], file_read->d_name);			// add the folder name to continue recursive search
					
					if(depth<=19)								// if the maximum level of recursivity is not reached
					{
						find_all_files(opendir(temp_string), depth+1, path_dir);				// recursive call with a new depth level and a new folder name
					}
				}
			}
		}
	}
}

int main(void)
{
	DIR *rep=NULL;								// points to directory
	DIR *temp_rep=NULL;									// points to directory (to avoid seg fault)
	unsigned int cpt;										// typical counter
	unsigned int sure;												// user is sure to encrypt data
	unsigned char path_dir[SIZE_DEPTH*SIZE_NAME]={0};					// first folder name is store in this string
	
	CPT_FILE_FOUND=0;						// reset of global counter
	CPT_FILE_CRYPT=0;										// reset of global counter
	menu_initial();													// user menu is displayed on screen
	printf("Enter the directory name to encrypt :\n\n");					// give me the name of desired folder
	scanf("%s", path_dir);								// get the name of the folder to encrypt
	printf("\n\n");					
	rep=opendir(path_dir);								// open the folder
	
	if(rep==NULL)														// if the folder doesn't exist
	{
		printf("ERROR, can't open directory : %s\n", path_dir);				// display error message
		printf("Be sure to enter a valid directory name.\n\n");					// display error message
	}
	else															// else, folder is ready for operations
	{
		printf("Folder found\n\n");											// display everything is OK
		temp_rep=rep;												// clone of the original folder pointer
		find_all_files(temp_rep, 1, path_dir);									// list all the files present in this folder
		printf("\n");	
		printf("Total number of file(s) found : %05d\n\n", CPT_FILE_FOUND);					// display total number of files
		
		do
		{
			printf("Are you sure to continue encryption operation ? (1-yes    0-no)\n");				// sure to continue ?
			scanf("%d", &sure);
			printf("\n");
		}while((sure!=0)&&(sure!=1));					// while the user is stupid
		
		if(sure==1)														// encryption operations are started
		{
			closedir(rep);										// close current folder (pointer is corrupted)
			rep=opendir(path_dir);									// open a new one
			temp_rep=rep;										// clone of the original folder pointer
			crypt_all_files(temp_rep, 1, path_dir);						// encrypt all the files recursively
			printf("\n\n");
			printf("Encryption successful.\n\n");						// end of encryption
			closedir(rep);												// folder is closed
		}
		else												// user is not sure
		{
			printf("Encryption process aborted.\n\n");					// abort current encryption process, without damage
			closedir(rep);									// folder is closed
		}
	}
	
	return 0;									// return to operating system
}

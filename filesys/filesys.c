#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */

bool
filesys_create (const char *name, off_t initial_size, bool isfile) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = findDir (name);
	//grab name of just the file
	char* n = getname(name);
	bool success;
	if(strcmp(n, ".") != 0 && strcmp(n, "..") != 0){
	 	 success = (dir != NULL
		              && free_map_allocate (1, &inode_sector)
		              && inode_create (inode_sector, initial_size, isfile)
		              && dir_add (dir, name, inode_sector));
	}
	else success = false;
	
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
	//dealloc
	free(n);

  return success;
}

//helper
//grab just the name from the end of the path
char* getname (const char* dir){
	int len = strlen(dir) + 1;
  	char copy[len];
  	memcpy(copy, dir, len);

	char *ptr;
  	char *cur;	
	char *prev = "";
  	for (cur = strtok_r(copy, "/", &ptr); cur != NULL; cur = strtok_r (NULL, "/", &ptr)){
      prev = cur;
    }
	
	//allocate and memcopy the result	
	int size = strlen(prev) + 1;
  	char *name = malloc(size);
  	memcpy(name, prev, size);
  	return name;
}

//helper
//use dir functions to find the dir that contains the path
struct dir* findDir(const char* src){

	int len = strlen(src) + 1;
	
	//copy into string
	char str[len];
	memcpy(str, src, len);

	struct dir* d;
	//check if starting at root 
	//ascii character "/" = 47	
	if(str[0] == 47){
		d = dir_open_root();
	}
	//check if thread has current working directory
	//if not must start at root	
	else if(thread_current()->cwdir == NULL){
		d = dir_open_root();
	}
	else{
		d = dir_reopen(thread_current()->cwdir);
	}
	
	char *ptr;
	char *cur = strtok_r(str, "/", &ptr);
	char *next = NULL;

	if(cur != NULL){
		next = strtok_r(NULL, "/", &ptr);
	}

	while(next != NULL){
		//check for . and ..
		if(strcmp(cur, ".") == 0){
			cur = next;
			next = strtok_r(NULL, "/", &ptr);
		}
		else{
			struct inode *in;
			if(strcmp(cur, "..") == 0 && findParent(d, &in) == false){
				//no such dir
				return NULL;
			}
			if(dir_lookup(d, cur, &in) == false){
				return NULL;
			}
			//If not file, then its dir
			if(!inode_is_file(in)) {		
				//set d to in dir
				dir_close(d);
				d = dir_open(in);
			}
			else{
				//close
				inode_close(in);
			}
			cur = next;
			next = strtok_r(NULL, "/", &ptr);
		}

	}
	return d;
}	


//MODIFIED
/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  //struct dir *dir = dir_open_root ();
  //struct inode *inode = NULL;
	//if no file specified
	if(strlen(name) == 0)return NULL;

	struct dir* d = findDir(name);
	char* n = getname(name);

	struct inode *i = NULL;
	
  //if (dir != NULL)
  //  dir_lookup (dir, name, &inode);
	if(d){
		if(strcmp(n, "..") == 0 && findParent(d, &i) == false){
			//dealloc and return fail			
			free(n);
			return NULL;
		}
		//check if the directory matches the root dir inum
		bool isroot = ROOT_DIR_SECTOR == inode_get_inumber(dir_get_inode(d));
		isroot &= (strlen(n) == 0);
		if(strcmp(n, ".") == 0 || isroot){
			//dealloc and return file at root
			free(n);
			return (struct file* )d;
		}
		
		//look up and put in i
		dir_lookup(d, n, &i);
	}  
	//dont need d anymore
	dir_close (d);

	//free n
	free(n);

	//check if dir lookup faild
	if(!i)return NULL;
	
	//check if path is directory or file 
	if(inode_is_file(i)  == false){
		//open the file specified by the inode given by the directory returned by dir open
		return (struct file *)dir_open(i);
	}
	//else if it is a file
  return file_open (i);
}


//MODIFIED
/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  //struct dir *dir = dir_open_root ();
	struct dir* d = findDir(name);  
	char* n = getname(name);

	bool success = d != NULL && dir_remove (d, n);
  	dir_close (d); 
	//dealloc
	free(n);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

//moved from syscall.c for consistency
//chdir system call
bool checkDirectory(const char* path){
	struct dir* d = findDir(path);

	struct inode* i = NULL;

	//get file name
	char* n = getname(path);

	//if findDir succeeds
	if(d){
		if(strcmp(n, "..") == 0 && findParent(d, &i) == false){
			//dealloc and return fail			
			free(n);
			return false;
		}
		//check if the directory matches the root dir inum
		bool isroot = ROOT_DIR_SECTOR == inode_get_inumber(dir_get_inode(d));
		isroot &= (strlen(n) == 0);
		if(strcmp(n, ".") == 0 || isroot){
			//set current thread working directory to this d
			thread_current()->cwdir = d;
			free(n);
			//success
			return true;
		}
		//else try to lookup
		dir_lookup(d, n, &i);
		//dealloc		
		free(n);
	}
	
	//inode should now be set by lookup
	dir_close(d);
	
	//set dir to file i refs
	d = dir_open(i);
	//if success	
	if(d){
		//close current working directory and change it to d
		dir_close(thread_current()->cwdir);
		thread_current()->cwdir = d;
		//success		
		return true;
	}
	//failure
	return false;	
}



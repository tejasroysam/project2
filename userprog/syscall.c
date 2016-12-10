#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/vaddr.h"



//global lock for running threads (from synch.h)
//call lock_init(mylock) somewhere
struct lock mylock;

static void syscall_handler (struct intr_frame *);
int user_to_kernel_ptr(const void *vaddr);

void
syscall_init (void) 
{
  lock_init(&mylock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/******************************************************************************
	REFERENCE FOR PINTOS FILES/API
	http://www.cse.iitd.ernet.in/~sbansal/os/pintos/doc/pintos_html/files.html
******************************************************************************/

//concurrency -> threads/synch.c
//useful methods (locking):
//lock_acquire -> gets lock for current thread (sleep until available)
//lock_try_acquire -> same as lock_acquire but does not sleep if unavailable, instead returns false
//lock_release -> release lock owned by current thread
//lock_held_by_current_thread -> boolean check if this thread has the lock

void halt(void){
	shutdown_power_off();
}

void exit(int status){
	//terminate current user program
	//return status to the kernel
	//0->success, nonzero->errors
	
	//get the current thread
	struct thread* proc = thread_current();	

	//send exit status to child
	int isInAllList = inAllList(proc->parent);
	if(isInAllList == 1){
		proc->child->status = status;
		//proc->child->has_exited = true;
	}		
	printf("%s: exit(%d)\n", proc->name, status);
	thread_exit(status);
	//
	//check if it has parent and send the status to the parent if so
	//if(proc->parent != NULL){
	//	tid_t parent = proc->parent;
	//	thread
	//}
	
}

tid_t exec(const char* cmd_line){
	//get executing thread
	//struct thread* curr = thread_current();
	//printf("reached exec");
	//execute the process with the given args and get the pid
	tid_t newproc = process_execute(cmd_line);
	if(newproc == -1){exit(-1);}

	//wait for child process to init
	bool child = false;
	struct list_elem *current;
	struct childproc *curr;
	for(current = list_begin(&thread_current()->children); current != list_end(&thread_current()->children);
			current = list_next(current)){
		curr = list_entry(current, struct childproc, index);
		//compare with current thread tid
		if(curr->tid == newproc){
			child = true;
			break;
		}
	}
	//if(!child || curr->is_loaded < 0 || curr->has_exited){	
	//	exit(-1);
	//}
	if(!child)return -1;

	if(curr->is_loaded == 0)sema_down(&curr->loaded);

	if(curr->is_loaded == -1){
		//kill all children
		list_remove(&curr->index);
		free(curr);
		return -1;
	}
	
	//spin on child init
	/*while(true){
		if(curr->is_loaded == 1){
			break;
		}
		if(curr->is_loaded < 0){
			return -1;
		}
		barrier();
	}*/
	

	//add to children of current
	//curr->children[curr->numchild] = newproc;
	//list_pish_back(curr->children, 
	
	//return the pid of the new process
	return newproc;
	
}

//should be complete 
int wait(tid_t pid){
	//wait for lock (we are waiting anyways)
	//lock_acquire(&mylock);
	//critical section
	int t = process_wait(pid);
	//release
	//lock_release(&mylock);
	return t;
}
//should be complete
//just uses the filesys built in
bool create (const char *file, unsigned initial_size){
	//wait for the lock to become available
	//lock_acquire(&mylock);
	//critical section
	bool success = filesys_create(file, initial_size, true);
	//release lock
	//lock_release(&mylock);
	return success;
}
//should be complete 
//filesys builtin
bool remove (const char *file){
	//wait for lock to become available
	//lock_acquire(&mylock);
	//critical section
	bool success = filesys_remove(file);
	//release lock
	//lock_release(&mylock);
	return success;
}

//need a lock for all file ops so that only one process can modify a file at a time

/***************************************************************************
	REFERENCE FOR PINTOS LISTS:
	https://jeason.gitbooks.io/pintos-reference-guide-sysu/content/list.html
***************************************************************************/


int open(const char *file){
	//acquire lock
	//lock_acquire(&mylock);
	//cs

	//create a file
	struct file *newfile = filesys_open(file);
	//open missing and open empty tests
	if(newfile == NULL){
		//lock_release(&mylock);
		return -1;
	}
	//allocate and create an openfile object with the file and its descriptor
	/*	
	struct openfile *n = malloc(sizeof(struct openfile));
	n->fd = thread_current()->numfd;
	//increment numfd in the running thread
  	thread_current()->numfd++;
  	n->f = newfile;
	*/
  	
	int fd;
	if(!inode_is_file(file_get_inode(file))){	

		//init openfile
		//add dir 
		struct openfile *curr = malloc(sizeof(struct openfile));
		if (!curr){
		  return -1;
		}
		curr->directory = (struct dir*)file;
		curr->isfile = false;
		curr->fd = thread_current()->numfd;
		thread_current()->numfd++;
		list_push_back(&thread_current()->files, &curr->index);
		fd = curr->fd;
	}
	else{
		//init openfile
		//add file 
		struct openfile *curr = malloc(sizeof(struct openfile));
		if (!curr){
		  return -1;
		}
		curr->f = file;
		curr->isfile = false;
		curr->fd = thread_current()->numfd;
		thread_current()->numfd++;
		list_push_back(&thread_current()->files, &curr->index);
		fd = curr->fd;
	}

/*
	int ifd;
	struct inode* i = file_get_inode(newfile);
	//if directory, init openfile as such
	if(inode_is_file(i) == false){
		curr->directory = (struct dir*)newfile;
		curr->isfile = false;
		curr->dircheck = true;
	}
	//if file init openfile as such
	else{
		curr->f = newfile;
		curr->isfile = true;
		curr->dircheck = false;
	}
*/

	//ifd = curr->fd;
	//add the openfile object to the end of the list of open files in the current thread
  	//list_push_back(&thread_current()->files, &n->index);
	
	//release
	//lock_release(&mylock);
	return fd;
}

int filesize(int fd){
	//get the file with the file descriptor fd from the list and calc its size
	//search the current thread's list of file descriptors for fd and use built in to get length

	//lock
	//lock_acquire(&mylock);

	//cs
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			if(curr->isfile == false)return -1;
			int size = file_length(curr->f);
			//release 
			//lock_release(&mylock);
			return size;
		}
	}
	//file descriptor not found
	//release 
	//lock_release(&mylock);
	return -1;
}

int read(int fd, void *buffer, unsigned size){
	//check for standard FD (stdin/stdout)
	//make a buffer and grab SIZE characters 
	//return the size actually read
	//bad fd test
	if(fd < 0 || fd > thread_current()->numfd){
		exit(-1);
	}
	//read stdout test
	if(fd == STDOUT_FILENO){
		exit(-1);
	}
	
	//unchanged
	//get lock
	//lock_acquire(&mylock);
	//if stdin
	if(fd == STDIN_FILENO){
		uint8_t *buf = (uint8_t*) buffer;
		for(unsigned i = 0; i < size; i++){
			buf[i] = input_getc();//from devices/input.h
		}
		//lock_release(&mylock);
		return size;
	}
 
	
	//cs
	//get file
	struct openfile *readfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			readfile = current;
			break;
		}
	}
	if(readfile == NULL){
		//error reading
		//release
		//lock_release(&mylock);
		return -1;
	}
	//if directory
	if(readfile->isfile == false)return -1;

	int s = file_read(readfile->f, buffer, size);
	

	//read from file to buffer using filesys
	//returns size written 
	//int s = file_read(readfile, buffer, size);;
	//release
	//lock_release(&mylock);
	return s;
	
	
}

int write(int fd, const void *buffer,  unsigned size){
	//similar to read
	//check for stdin/stdout
	//write buffer to file
	//return the size as written
	//printf("\nfd:%d  size:%d current TID:%d\n", fd, size, thread_current()->tid);
	//lock
	//bad fd test
	if(fd < 0 || fd > thread_current()->numfd){
		exit(-1);
	}
	//read stdout test
	if(fd == STDIN_FILENO){
		exit(-1);
	}
	//lock_acquire(&mylock);
	//cs
	//if stdout
	if(fd == STDOUT_FILENO){
		//printf("\nUsing stdout to putbuf\n");
		putbuf(buffer, size);
		//lock_release(&mylock);
		return size;
	}

	//printf("\nSHOULD NOT BE HERE. MY FD IS:%d\n", fd);
	//get file
	struct openfile *writefile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			writefile = curr;
			break;
		}
	}
	if(writefile == NULL){
		//error writing
		//release
		//lock_release(&mylock);
		return -1;
	}

	if(writefile->isfile == false)return -1;

	//write buffer to file using filesys
	
	//int s =  file_write(writefile, buffer, size);
	int s = file_write(writefile->f, buffer, size);
	//release
	//lock_release(&mylock);
	return s;
	
}

void seek(int fd, unsigned position){
	//moves the next read/write byte in the open file fd to position
	//position is the number of bytes from the start of the file
	//seek past end of file?-> not error-> will either read nothing or write zeroes to skipped area
	//lock
	//lock_acquire(&mylock);
	//get file
	struct openfile *seekfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			seekfile = curr;
			break;
		}
	}
	if(seekfile == NULL){
		//file not found, skip seek
		//release
		//lock_release(&mylock);
		return;
	}

	if(seekfile->isfile == false)return ;

	//filesys method does the hard work again! yay! file_seek(struct file, unsigned offset)
	//file_seek(seekfile, position);
	file_seek(seekfile->f, position);
	//release
	//lock_release(&mylock);
}

unsigned tell(int fd){
	//returns position of next byte to be read or written in fd 

	//lock
	//lock_acquire(&mylock);
	
	//cs
	//get file
	struct openfile *tellfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			tellfile = curr;
			break;
		}
	}
	if(tellfile == NULL){
		//file not found, skip tell
		//release
		//lock_release(&mylock);
		return -1;
	}

	if(tellfile->isfile == false)return ;

	//filesys method does all the work as usual. thanks buddy. file_tell(struct file)
	//unsigned pos = file_tell(tellfile);
	unsigned pos = file_tell(tellfile->f);	
	//release
	//lock_release(&mylock);
	return pos;

}

void close(int fd){
	//close fd (exit/terminate process also closes all its open fds)
	//search for fd, dealloc, remove from list of fds in thread
	
	//lock
	//lock_acquire(&mylock);
	
	//cs
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){

		struct openfile *curr = list_entry(current, struct openfile, index);
		//check if current is the element we are looking to close
		if(curr->fd == fd){
			//close file and remove from list using filesys method and list method
			//file_close(struct file) , list_remove(struct list_elem)
			if(curr->isfile == false){
				dir_close(curr->directory);
			}
			else{
				file_close(curr->f);
			}
			list_remove(&curr->index);
			//deallocate curr
			free(curr);
			break;
		}
	}

	//release
	//lock_release(&mylock);
}	

//isdir
bool isdir(int fd){

	struct openfile *dirfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			dirfile = curr;
			break;
		}
	}
	if(dirfile == NULL){
		//file not found, skip tell
		//release
		//lock_release(&mylock);
		return false;
	}
	return dirfile->dircheck;
}

//inode number
int inumber(int fd){

	struct openfile *dirfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			dirfile = curr;
			break;
		}
	}
	if(dirfile == NULL){
		//file not found, skip tell
		//release
		//lock_release(&mylock);
		return false;
	}

	block_sector_t sec;
	
	//if the open file is a directory
	if(dirfile->dircheck == true){
		sec = inode_get_inumber(dir_get_inode(dirfile->directory));
	}
	//if it is an actual file
	else{
		sec = inode_get_inumber(file_get_inode(dirfile->f));
	}
	return sec;
}


//check dir
bool chdir(const char *dir){
	bool success = checkDirectory(dir);
	return success;
}

//make dir
bool mkdir(const char *dir){
	//initial size of 0
	bool success = filesys_create(dir, 0, false);
	return success;
}

//read dir
bool readdir(int fd, char* name){
	struct openfile *dirfile;
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){
		struct openfile *curr = list_entry(current, struct openfile, index);
		if(curr->fd == fd){
			dirfile = curr;
			break;
		}
	}
	if(dirfile == NULL){
		//file not found, skip tell
		//release
		//lock_release(&mylock);
		return false;
	}

	if(dirfile->dircheck == false)return false;

	if(dir_readdir(dirfile->directory, name) == false)return false;

	return true;
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("top of syscall handler\n\n");
	//int* sp = (int*) f->esp;
	//if(sp == NULL) { printf("User passed in NULL ptr\n\n\n"); exit(-1); }
	//int top_stack = *sp;
	//sp += 1;
	//printf("\n%x\n", f->esp);
	if(f->esp == NULL){exit(-1);}
	if(pagedir_get_page(thread_current()->pagedir, f->esp) == NULL){exit(-1);}
	if(!is_user_vaddr((const void*)f->esp) || ((const void*)f->esp < (void*) 0x08048000 )){ exit(-1); }
	int *sp = (int *)f->esp;
    int sysc;
    sysc = *sp;
	
	
	switch(sysc){
		case(SYS_HALT):		//Halt the operating system. 
		{
			//Do not print a termination message.
			halt();
			//no return value, so we do not update f->eax
			break;
		}
		case(SYS_EXIT):		//Terminate this process. 
		{
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
			//uint32_t err = f->error_code;
			exit(arg);
			//no return value, so we do not update f->eax
			break;
		}
		case(SYS_EXEC):		 //Start another process. 
		{
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			//get kernel pointer from the user pointer arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg = (int) karg;
			f->eax = exec((const char*) arg);			
			break;

			/*
			char* cmd_line = (char*) sp;
			tid_t proc_id = exec(cmd_line);
			f->eax = (unsigned) proc_id;
			break;
			*/
		}
		case(SYS_WAIT):		//Wait for a child process to die. 
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
			
			f->eax = wait(arg);
			break;

			/*
			tid_t pid = *((tid_t*) sp);
			int status = wait(pid);
			//Not sure if this is really an error, just testing
			if(status < 0) { printf("status obtained from wait() is negative"); exit(-1); }	
			f->eax = (unsigned) status;	
			break;
			*/
		}
		case(SYS_CREATE):	//Create a file. 
		{
			//grab 2 arguments
			int arg[2];
			int i = 0;
			int* ptr;
			for(i = 0; i < 2; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}

			//get kernel pointer from the first arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg[0]);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg[0] = (int) karg;

			//syscall
			f->eax = create((const char*)arg[0], (unsigned) arg[1]);
			break;
			
			/*
			unsigned initial_size = *((unsigned*) sp);
			sp = (int*) ((unsigned*) sp + 1);
			char* file = (char*) sp;
			bool tmp = create(file, initial_size);
			f->eax = (unsigned) tmp;
			break;
			*/
		}
		case(SYS_REMOVE):	//Delete a file. 
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			//get kernel pointer from the first arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg = (int) karg;
			
			f->eax = remove((const char*) arg);
			break;

			/*
			char* file = (char*) sp;
			bool tmp = remove(file);
			f->eax = (unsigned) tmp;
			break;
			*/
		}
		case(SYS_OPEN):		//Open a file. 
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			//get kernel pointer from the first arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg = (int) karg;
			
			f->eax = open((const char*) arg);
			break;
			/*
			char* file = (char*) sp;
			int new_file_descriptor = open(file);
			f->eax = (unsigned) new_file_descriptor;
			break;
			*/
		}
		case(SYS_FILESIZE):	//Obtain a file's size. 
		{
			
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
			
			f->eax = filesize(arg);
			break;

			/*
			int fd = *sp;
			int size = filesize(fd);
			f->eax = (unsigned) size;
			break;
			*/
		}
		case(SYS_READ):		//Read from a file. 
		{
			
			//grab 3 arguments
			int arg[3];
			int i = 0;
			int* ptr;
			for(i = 0; i < 3; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}
		
			//make sure read buffer is in valid range, exits if it is not
			unsigned j;
  			char* argcpy = (char *) (void*)arg[1];
  			for (j = 0; j < (unsigned)arg[2]; j++){
      			if(!is_user_vaddr((const void*)argcpy) || ((const void*)argcpy < (void*) 0x08048000)){ exit(-1); }
      			argcpy++;
			}	
			
			//get kernel pointer from the second arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg[1]);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg[1] = (int) karg;

			f->eax = read(arg[0], (void*)arg[1], (unsigned)arg[2]);
			break;

			/*
			int fd = *sp;
			sp += 1;
			if(!is_user_vaddr(sp) || (sp < (void*) 0x08048000)){ exit(-1); }
			void *buffer = pagedir_get_page(thread_current()->pagedir,sp);
			sp += 1;
			

			unsigned size = *((unsigned*) sp);
			int bytes_read = read(fd, buffer, size);
			f->eax = (unsigned) bytes_read;
			break;
			*/
		}
		case(SYS_WRITE):	//Write to a file. basically same handling as read 
		{

			//grab 3 arguments
			int arg[3];
			int i = 0;
			int* ptr;
			for(i = 0; i < 3; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}
			
			//make sure read buffer is in valid range, exits if it is not
			unsigned j;
  			char* argcpy = (char *) (void*)arg[1];
  			for (j = 0; j < (unsigned)arg[2]; j++){
      			if(!is_user_vaddr((const void*)argcpy) || ((const void*)argcpy < (void*) 0x08048000)){ exit(-1); }
      			argcpy++;
			}	
			
			//get kernel pointer from the second arg
			void *karg = pagedir_get_page(thread_current()->pagedir, (const void *) arg[1]);
			if(karg == NULL){
				//null pointer->error
				exit(-1);
			}
			arg[1] = (int) karg;
			//printf("\nhandler-> arg[0]:%d arg[1]:%s arg[2]:%u\n", arg[0], arg[1], arg[2]);
			f->eax = write(arg[0], (const void*)arg[1], (unsigned)arg[2]);
			break;
			
			/*
			int arg[3];
			int i = 0;
			int* ptr;
			for(i = 0; i < 3; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}

			int fd = arg[0];

			if(!is_user_vaddr(arg[1]) || (arg[1] < (void*) 0x08048000)){ exit(-1); }
			void *buffer = pagedir_get_page(thread_current()->pagedir,arg[1]);

			unsigned size = (unsigned) arg[2];
			printf("WE HAVE ARRIVED AT SYSCALL- WRITE. FD = %d\n", fd);
			printf("Buffer points to location %x\n", buffer);
			printf("size value is equal to %d\n", size);
			f->eax = write(fd, buffer, size);
			*/

			/*int fd = *sp;
			sp += 1;
			void* tmp = sp;
			//now grab the actual value of physical memory
			//if(!is_user_vaddr(tmp)) { exit(-1); }
			if(!is_user_vaddr(sp) || (sp < (void*) 0x08048000)){ exit(-1); }
			void *buffer = pagedir_get_page(thread_current()->pagedir,sp);
			//void* buffer = vtop(tmp);
			sp += 1;
			unsigned size = *((unsigned*) sp);
			//sp = (int*) ((unsigned*) sp + 1);*/
			
			//printf("WE HAVE ARRIVED AT SYSCALL- WRITE. FD = %d\n", fd);
			//printf("Buffer points to location %x\n", buffer);
			//printf("size value is equal to %d\n", size);
			//int bytes_written = write(fd, buffer, size);
			//f->eax = (unsigned) bytes_written;
			//break;
		}
		case(SYS_SEEK):		//Change position in a file. 
		{
			//grab 2 arguments
			int arg[2];
			int i = 0;
			int* ptr;
			for(i = 0; i < 2; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}

			seek(arg[0], (unsigned) arg[1]);
			break;
			/*
			int fd = *sp;
			sp += 1;
			unsigned position = *((unsigned*) sp);
			//sp = (int*) ((unsigned*) sp + 1);
			//int fd = *sp;
			seek(fd, position);
			//no return value, so we do not update f->eax
			break;
			*/
		}
		case(SYS_TELL):		//Report current position in a file. 
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
			
			f->eax = tell(arg);
			break;
			/*
			int fd = *sp;
			unsigned position = tell(fd);
			f->eax = position;
			break;
			*/
		}
		case(SYS_CLOSE):	//Close a file.
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			close(arg);
			break;
			/*
			int fd = *sp;
			close(fd);
			//no return value, so we do not update f->eax
			break;
			*/
		}
		case(SYS_ISDIR):
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
;
			f->eax = isdir(arg);
			break;
	
		}
		case(SYS_INUMBER):
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;
;
			f->eax = inumber(arg);
			break;
	
		}
		case(SYS_CHDIR):
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			const void* copy = arg;
			while(*(char *)user_to_kernel_ptr(copy) != 0){
				copy = (char *) copy + 1;
			}

			arg = user_to_kernel_ptr((const void *) arg);
			f->eax = chdir((const char*)arg);
			break;
	
		}
		case(SYS_MKDIR):
		{
			//get the argument
			int arg;
			int* ptr;
			ptr = (int*) f->esp + 1;
			if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
			arg = *ptr;

			const void* copy = arg;
			while(*(char *)user_to_kernel_ptr(copy) != 0){
				copy = (char *) copy + 1;
			}

			arg = user_to_kernel_ptr((const void *) arg);
			f->eax = mkdir((const char*)arg);
			break;
	
		}
		case(SYS_READDIR):
		{
			//grab 2 arguments
			int arg[2];
			int i = 0;
			int* ptr;
			for(i = 0; i < 2; i++){
				ptr = (int*) f->esp + 1 + i;
				if(!is_user_vaddr(ptr) || (ptr < (void*) 0x08048000)){ exit(-1); }
				arg[i] = *ptr;
			}

			const void* copy = arg[1];
			while(*(char *)user_to_kernel_ptr(copy) != 0){
				copy = (char *) copy + 1;
			}

			arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			f->eax = readdir(arg[0], (const char*)arg[1]);
			break;
	
		}
		
		default:
		{
			exit(-1);
			break;
		}
	}
	//thread_exit (0);
}
int user_to_kernel_ptr(const void *vaddr) {
	if(!is_user_vaddr(vaddr) || (vaddr < (void*) 0x08048000)) exit(-1); 
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if(!ptr) exit(-1);
	return (int) ptr;
}

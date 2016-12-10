#include "userprog/process.h"
#include <ctype.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"



static thread_func start_process NO_RETURN;
static bool load (const char*, void (**) (void), void**, char*);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
	
	//modified from original
	// divide into words at spaces: first word is program name, second word is arg[1],etc...
  char *fn_copy;
  tid_t tid;

  //printf("\nPROCESS HAS BEEN CALLED\n");

	//	pls work im begging you
  // Make a copy of FILE_NAME.
  //   Otherwise there's a race between the caller and load().
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
	
  char * dummy = malloc(strlen(file_name)+1);
  memcpy(dummy, file_name, strlen(file_name)+1);

  char * args;
  file_name = strtok_r(dummy, " ", &args);

  //fn_copy = fn_copy + strlen(dummy)+1;
	
  //printf("\n\ndummy:%s file_name:%s fn_copy:%s\n", dummy, file_name, fn_copy);
  /* Create a new thread to execute FILE_NAME. */
  //thread_create(const char *name, int priority,thread_func *function, void *aux)
  //Creates a new kernel thread named NAME with the given initial
  //PRIORITY, which executes FUNCTION passing AUX as the argument,
  //and adds it to the ready queue.
	//printf("\n\nasda %s %s\n\n", file_name, fn_copy);
	
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy);
  }
  free(dummy);
  //printf("end of process execute\n");
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void* cmd)
{
  char* save_ptr  = NULL;
  char* file_name = strtok_r((char*)cmd, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  struct intr_frame if_;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  bool success = load(file_name, &if_.eip, &if_.esp, save_ptr);
	struct thread *curr = thread_current();
	if(success == true){
		curr->child->is_loaded = 1;
	}
	else{
		curr->child->is_loaded = -1;
	}
	
	if(curr->cwdir == NULL){
		curr->cwdir = dir_open_root();
	}  
	sema_up(&curr->child->loaded);


  /* If load failed, quit. */
  palloc_free_page (cmd);
  if (!success){ 
	//printf("\n\nwe got here\n\n");
	thread_exit(-1);
  }

  // PANIC("WE GOT HERE");

  //check process loads and correctly 
	//if(!success){
	//	thread_exit(0);
	//}

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

//define barrier as asm instruction which tells compiler that operation changes all memory locations
//from caltech cs124 lecture 10 slides
//#define bar() asm volatile ("" : : : "memory")

int
process_wait (tid_t child_tid UNUSED) 
{
	/*
	//check if child_tid was a child of the calling process
	bool child = false;
	struct list_elem *current;
	struct childproc *curr;
	for(current = list_begin(&thread_current()->children); current != list_end(&thread_current()->children);
			current = list_next(current)){
		curr = list_entry(current, struct childproc, index);
		//compare with current thread tid
		if(curr->child.tid == thread_current()->tid){
			child = true;
			break;
		}
	}
	if(!child){	
		return -1;
	}
	//if valid, wait for thread to die
	while(true){
		if(curr->child.status == THREAD_DYING){
			break;
		}
	}
	//kill all children 
	struct thread *running = thread_current();

	struct list_elem *curthread = list_begin(&running->children);
	struct list_elem *copy; //so that we dont lose place in list when we deallocate

	while (curthread != list_end (&running->children)){
		copy = curthread;
		struct childproc *curr = list_entry(current, struct childproc, index);
		//kill child
		list_remove(&curr->index);
		free(curr);
		curthread = list_next(curthread);
	}
	
	return curr->child.status;
*/
	
	//if pid didnt call exit but has been terminated by the kernel, immediately return -1
	//int isInAllList = inAllList(child_tid);
	//if(isInAllList == 0){
	//	return -1;
	//}	

	//if(checkStatus(child_tid) == THREAD_DYING){
	//		return -1;			
	//	}
	
	//printf("\n\nprocess wait");
	bool child = false;
	struct list_elem *current;
	struct childproc *curr;
	for(current = list_begin(&thread_current()->children); current != list_end(&thread_current()->children);
			current = list_next(current)){
		curr = list_entry(current, struct childproc, index);
		//compare with current thread tid
		if(curr->tid == child_tid){
			child = true;
			break;
		}
	}
	//pid does not refer to a direct child of the calling process
	if(!child){	
		return -1;
	}
	
	//curr now contains the childproc
	//check if it is already waiting
	//The process that calls wait has already called wait on pid 
	// That is, a process may wait for any given child at most once
	if(curr->is_waiting){
		return -1;
	}
	else{
		curr->is_waiting = true;
	}
	//use semaphore instead of busywait
	if(curr->has_exited == false)sema_down(&curr->exited);
	//spin until the child process exits
	//use threads/synch.h barrier
	/*while(true){
		if(curr->has_exited){
			break;
		}	
		//if(!inAllList(thread_current()->tid)){
		//	exit(-1);
		//}
		barrier();		
	}
	*/
	//get exit status and delete once finished
	int exit_status = curr->status;
	list_remove(&curr->index);
	free(curr);
	return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
	
	//printf("\n\nprocess exit");
  struct thread *cur = thread_current ();
  uint32_t *pd;

	//kill all children
	struct list_elem *ind = list_begin(&cur->children);
	struct list_elem *last = list_end(&cur->children);
	struct list_elem *next;
	while(ind != last){
		//save pointer to next element before freeing
		next = list_next(ind);
		struct childproc *current = list_entry(ind, struct childproc, index);
		list_remove(&current->index);
		free(current);
		ind = next;
	}

	//close files (from syscall close)

	struct list_elem *ind2 = list_begin(&cur->files);
	struct list_elem *last2 = list_end(&cur->files);
	struct list_elem *next2;
	while(ind2 != last2){
		//save pointer to next element before freeing
		next2 = list_next(ind2);
		struct openfile *current = list_entry(ind2, struct openfile, index);
		file_close(current->f);
		list_remove(&current->index);
		free(current);
		ind2 = next2;
	}

	//close denial file
	//hey that rhymed
	if(cur->deny != NULL){
		file_close(cur->deny);
	}

	//close current working directory
	if(cur->cwdir != NULL){
		dir_close(cur->cwdir);
	}
/*
	struct list_elem *current;
	for(current = list_begin(&thread_current()->files); current != list_end(&thread_current()->files);
			current = list_next(current)){

		struct openfile *curr = list_entry(current, struct openfile, index);
		//check if current is the element we are looking to close
		//if(curr->fd == fd){
			//close file and remove from list using filesys method and list method
			//file_close(struct file) , list_remove(struct list_elem)
			file_close(curr->f);
			list_remove(&curr->index);
			//deallocate curr
			free(curr);
			//break;
		//}
	}
*/
//rox-> file close in process exit,  file_deny_write 
	
	//int inReadyList = inReadyList(cur->tid);
	int isInAllList = inAllList(cur->parent);
	//update exit flag 
	if(isInAllList == 1 && cur->child != NULL && cur->deny != NULL){
		//printf("\n\nwe got here as well\n\n");
		cur->child->has_exited = true;
		sema_up(&cur->child->exited);
	}
	//file_close(cur->deny);
	
	
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (const char* file_name, void **esp, char* save_ptr);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, char* save_ptr) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
	  //exit(-1);
      printf ("load: %s: open failed\n", file_name);
		//exit(-1);
      goto done; 
    }

	//rox tests
	//t->deny  = file;
	file_deny_write(file);
	t->deny = file;	

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (file_name, esp, save_ptr))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
	
	//file_deny_write(file);

 done:
  /* We arrive here whether the load is successful or not. */
  //if(!success){file_close (file);}
	if(success == false){file_close (file); }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
//changed from original 
static bool
setup_stack (const char* file_name, void **esp, char* save_ptr) 
{
  //printf("\nSETUPSTACK FILENAME:%s\n", file_name);
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else{
      palloc_free_page (kpage);
		return success;
	}
  }

  if (success)
  {

    
    

	/*
    { // Push argv[0][...] 
      size_t len = strlen(file_name);
      *esp -= sizeof(char) * (len + 1);
      memcpy(*esp, file_name, len + 1);
      argv[argc++] = *esp;
    } */   
    
	/*
    { // Push argv[1][...] through argv[argc][...] 
      char *arg = strtok_r(NULL, " ", &save_ptr);
      
      while (arg != NULL) 
      {
		//resize if necessary
        if (argc == argn) 
        {
          argn = argn * 2;
          argv = realloc(argv, sizeof(char*) * (argn + 1));
        }
        size_t len = strlen(arg);
        *esp -= sizeof(char) * (len + 1);
        memcpy(*esp, arg, len + 1);  
        argv[argc++] = *esp;

        arg = strtok_r(NULL, " ", &save_ptr);
      }
    }
	*/

	
	/*
	//IMP 2
	char * dummy = malloc(strlen(file_name)+1);
  	memcpy(dummy, file_name, strlen(file_name)+1);

	//compute size beforehand to allocate enough space to begin with
	for(arg = dummy //strtok_r(dummy, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr)){
		argc += 1;
	}
	char** argv = calloc(argc, sizeof(int));
	int q = 0;
	for(arg = strtok_r(file_name, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr),q++){
		size_t decr = strlen(arg) + 1;
		*esp -= decr;
		memcpy(*esp, arg, decr);
		argv[q] = *esp;
	}
	//END IMP 2
	*/

	//start with esp at bottom and add args1,2,3,c.. bottom to top
	
/*
	char * dummy = malloc(strlen(file_name)+1);
  	memcpy(dummy, file_name, strlen(file_name)+1);
	
	//move esp down
	for(arg = dummy; arg != NULL; arg = strtok_r(NULL, " ", &save_ptr)){
		size_t decr = strlen(arg) + 1;
		*esp -= decr;
	}

	//tokenize file_name and put on stack
	for(arg = (char*) file_name; arg != NULL; arg = strtok_r(NULL, " ", &save_ptr),argc++){
		printf("\nTokenizing. File_nme : %s\n", arg);
		size_t decr = strlen(arg) + 1;	
		//*((int*)(*esp)) = arg;  
		argv[argc] = *esp;
		*esp += decr;
	}*/
	
	//printf("file_name: %s", file_name);

	int argn = 24;
    char** argv = malloc(sizeof(char*) * (argn));
	
	int argc = 0;
	char *arg;
	
	char *addresses[argn];

	//move pointer to bottom then fill stack upwards

	argv[0] = file_name;
	argc++;

	//get argc
	for(arg = strtok_r(NULL, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr)){
		argv[argc] = arg;
		argc++;
	}
	
	//null return pointer
	addresses[argc] = NULL;
	//push values
	for(int i = argc-1; i >= 0; i--){
		int decr = strlen(argv[i])+1;
		*esp -= decr;
		addresses[i] = *esp;
		memcpy(*esp, argv[i], decr);
	}
	
	//align
	int padding = 4 - (PHYS_BASE - *esp) % 4;
	if(padding != 0){
		*esp -= padding;
		//copy nulls into padding
		memcpy(*esp, &addresses[argc], padding);
	}
	//push addresses
	for(int j = argc; j >= 0; j--){
		int decr = sizeof(char*);
		*esp -= decr;
		memcpy(*esp, &addresses[j], decr);
	} 

	//push addresses of args
	//esp is still pointing to argv[0] from above loop
	char **tmp = *esp;
	int decr = sizeof(char**);
	*esp -= decr;
	memcpy(*esp, &tmp, decr);
	
	decr = sizeof(int);
	*esp -= decr;
	memcpy(*esp, &argc, decr);

	decr = sizeof(void*);
	*esp -= decr;
	memcpy(*esp, &addresses[argc], decr);
	
	free(argv);
	//printf("\n\nend of setupstack\n\n");
	}
	/*
	for(arg = (char*) file_name; arg != NULL; arg = strtok_r(NULL, " ", &save_ptr)){
		size_t decr = strlen(arg) + 1;
		*esp -= decr;
		argv[argc] = *esp;
		argc += 1;
		if(argc >= argn){
			argn = argn * 2;
			argv = realloc(argv, argn*sizeof(char*));
		}
		memcpy(*esp, arg, decr);
	}
	*/
	/*

    // Push argv[argc][...] 
    argv[argc] = NULL;  

	//align to 4 bytes by padding excess
	int i = (uint32_t) *esp % 4;
	if(i != 0){
		*esp -= i;
		memcpy(*esp, &argv[argc], i);
	}

    // Push argv[0] through argv[argc] 
	int j;

	for (j = argc; j >= 0; j--) 
	{
	*esp -= sizeof(char*);
	memcpy(*esp, &argv[i], sizeof(char*));
	}

	arg = *esp;
    // Push argv 
    *esp -= sizeof(char**);
    //*((char***)(*esp)) = (char**)(*esp + sizeof(char**)); 
	memcpy(*esp, &arg, sizeof(char**));   

    // Push argc 
    *esp -= sizeof(int);
    //*((int*)(*esp)) = argc;  
	memcpy(*esp, &argc, sizeof (int)); 

    // Push return address ----- (NULL)
    *esp -= sizeof(void*);
    //*((void**)(*esp)) = NULL;
	memcpy(*esp, &argv[argc], sizeof(void*));

    // Clean up allocated space
    free(argv);
	//free(dummy);
  } */

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

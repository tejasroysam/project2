#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
//#include "threads/synch.c"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//8 mb disk
#define EIGHTMEGS 8980480

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
   
	//data blocks
	size_t dindex;
	//indirect blocks
	size_t idindex;
	//doubly indirect
	size_t didindex;
	
	//from inode struct
	bool isfile;	
	block_sector_t parent;
	//fill space to make it block_sector_size bytes on disk
 	uint32_t unused[107];               /* Not used. */
	//pointers to data blocks	
	block_sector_t arr[14];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */

    struct inode_disk data;             /* Inode content. */
	off_t length;
	off_t readlen;
	
	//added metadata
	block_sector_t parent;

	bool isfile;// false for dir, true for file

	struct lock mutex;

	//reference number
	int references;

	//indices
	//data blocks
	size_t dindex;
	//indirect blocks
	size_t idindex;
	//doubly indirect
	size_t didindex;
	//pointers to data blocks
	block_sector_t arr[14];
  };

//data block of pointers for indirect/doubly indirect 
struct indblock{
	//block of pointers to data blocks
	block_sector_t arr[128];
};



//alloc inode
bool allocInode(struct inode_disk *di){
	struct inode i;
	i.length = 0;
	i.dindex = 0;
	i.idindex = 0;
	i.didindex = 0;

	inode_expand(&i, di->length);
	di->dindex = i.dindex;
	di->idindex = i.idindex;
	di->didindex = i.didindex;
	memcpy(&di->arr, &i.arr, 128*sizeof(block_sector_t));
	return true;
}

void deallocInode(struct inode *i){
	//data
	size_t data = DIV_ROUND_UP (i->length, BLOCK_SECTOR_SIZE);

	//indir blocks
	size_t indirect;
	if (i->length <= BLOCK_SECTOR_SIZE*4)indirect = 0;
	else{
	  	i->length -= BLOCK_SECTOR_SIZE*4;
		indirect = DIV_ROUND_UP(i->length, BLOCK_SECTOR_SIZE*128);
	}

	//double indir blocks
	size_t dindirect;
	int maxsize = BLOCK_SECTOR_SIZE*(4+(9*128));
	if (i->length <= maxsize)dindirect = 0;
	return 1;

	//dealloc
	//data
	unsigned int index = 0;
	while(data != 0 && index < 4){
		free_map_release(i->arr[index], 1);
		data -= 1;
		index += 1;
	}
	//ind 
	while(indirect != 0 && index < 13){
		size_t darr = data;
		if(darr >= 14)darr = 14;

		//dealloc next indirect block
		struct indblock ib;
		block_read(fs_device, i->arr[index], &ib); 
		for(size_t i = 0; i < darr; i++){
			free_map_release(ib.arr[i], 1);
		}
		free_map_release(i->arr[index], 1);
	
		data -= darr;
		indirect -= 1;
		index += 1;
	}

	//double ind
	if(dindirect != 0){
		struct indblock ib;
		block_read(fs_device, i->arr[index], &ib); 

		for(size_t i = 0; i < indirect; i++){
			size_t temp = data;
			if(temp >= 128)temp = 128;

			//dealloc current indirect block
			struct indblock ib2;
			block_read(fs_device, ib.arr[i], &ib2); 
			for(size_t j = 0; j < temp; j++){
				free_map_release(ib2.arr[j], 1);
			}
			free_map_release(ib.arr[i], 1);
			//

			data -= temp;
		}
		free_map_release(i->arr[index], 1);
	}
}

//MODIFIED
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t len, off_t pos) 
{
  ASSERT (inode != NULL);
  	if (pos < len){
		uint32_t indirect[128];
		uint32_t index;		
		//max size using indirect pointers		
		int maxsize = 	BLOCK_SECTOR_SIZE*(4+(9*128));
		//check if small enough for direct		
		if(pos < BLOCK_SECTOR_SIZE*4){
			return inode->arr[pos/BLOCK_SECTOR_SIZE];
		}
		//check if can use indirect
		else if(pos < maxsize){
			//subtract direct blocks
			pos -= BLOCK_SECTOR_SIZE*4;
			index = pos/(BLOCK_SECTOR_SIZE*128)+4;
			block_read(fs_device, inode->arr[index], &indirect);
			pos %= BLOCK_SECTOR_SIZE*128;
			return indirect[pos/BLOCK_SECTOR_SIZE];
		}
		//doubly indirect needed
		else{
			//doubly indirect block starts @ index 13
			//read double indirect blocks
			block_read(fs_device, inode->arr[13], &indirect);
			pos -= maxsize;
			index -= pos/(BLOCK_SECTOR_SIZE*128);
			//read indirect blocks
			block_read(fs_device, indirect[index], &indirect);
			pos %= BLOCK_SECTOR_SIZE*128;
			return indirect[pos/BLOCK_SECTOR_SIZE];
		}
	}
	else{
		//too large
		return -1;
	}
    
}


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

//MODIFIED
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool isfile)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
		//normalize
		if(disk_inode->length > EIGHTMEGS)disk_inode->length = EIGHTMEGS;
      disk_inode->magic = INODE_MAGIC;
		disk_inode->isfile = isfile;
		disk_inode->parent = ROOT_DIR_SECTOR;
      if (allocInode(disk_inode) == true) 
        {
          block_write (fs_device, sector, disk_inode);
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
	lock_init(&inode->mutex);
	struct inode_disk datablocks;
	//populate
  block_read (fs_device, inode->sector, &datablocks);
	//copy over
	inode->length = datablocks.length;
	inode->readlen = datablocks.length;
	inode->dindex =  datablocks.dindex;
	inode->idindex = datablocks.idindex;
	inode->didindex = datablocks.didindex;
	inode->isfile = datablocks.isfile;
	inode->parent = datablocks.parent;
	//deep copy list
	memcpy(&inode->arr, &datablocks.arr, 128*sizeof(block_sector_t));

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

//MODIFIED
/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          deallocInode(inode);
        }
		else{
			struct inode_disk di;
			di.length = inode->length;
			di.dindex = inode->dindex;
			di.idindex = inode->idindex;
			di.didindex = inode->didindex;
			di.isfile = inode->isfile;
			di.parent = inode->parent;
			di.magic = INODE_MAGIC;
			memcpy(&di.arr, &inode->arr, 128*sizeof(block_sector_t));
			block_write(fs_device, inode->sector, &di);
		}
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}


//MODIFIED
/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  off_t len = inode->readlen;
	uint8_t *bounce = NULL;

	//dont read if offset too large
	if(offset >= len){
		return 0;
	}

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, len, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = len - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;


	if(inode_length(inode) < (offset + size)){
		//atomically extend
		if(inode->isfile == false)inode_lock(inode);
		inode->length = inode_expand(inode, (offset + size));
		if(inode->isfile == false)inode_unlock(inode);
	}

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, inode_length (inode), offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

//moved from directory for consistency
//getter for the inode's parent sector
block_sector_t getInodeParent(const struct inode* i){
	return i->parent;
}


//expand 
off_t inode_expand (struct inode *inode, off_t newlen){
	static char blank[BLOCK_SECTOR_SIZE];
	size_t newsec = DIV_ROUND_UP (newlen, BLOCK_SECTOR_SIZE) - DIV_ROUND_UP (inode->length, BLOCK_SECTOR_SIZE);

	if (newsec == 0)return newlen;

	while (inode->dindex < 4) {
		free_map_allocate (1, &inode->arr[inode->dindex]);
		block_write(fs_device, inode->arr[inode->dindex], blank);
		inode->dindex++;
		newsec--;
		if (newsec == 0)return newlen;
	}
	while (inode->dindex < 13){
		//
		newsec = inode_expand_i(inode, newsec);
		if (newsec == 0)return newlen;
	}
	if (inode->dindex == 13){
		//
		newsec = inode_expand_di(inode, newsec);
	}
	return (newlen - newsec*BLOCK_SECTOR_SIZE);
}

//helpers for expand for indirect/doubly indirect
//indirect
size_t inode_expand_i (struct inode *inode, size_t newsec){

	static char blank[BLOCK_SECTOR_SIZE];
	struct indblock b;

	if (inode->idindex == 0){
		free_map_allocate(1, &inode->arr[inode->dindex]);
	}

	else block_read(fs_device, inode->arr[inode->dindex], &b);
	
	while (inode->idindex < 128){
	  free_map_allocate(1, &b.arr[inode->idindex]);
	  block_write(fs_device, b.arr[inode->idindex], blank);
	  inode->idindex++;
	  newsec--;
	  if (newsec == 0) break;
	}

	block_write(fs_device, inode->arr[inode->dindex], &b);
	if (inode->idindex == 128)
	{
	  inode->idindex = 0;
	  inode->dindex++;
	}
	return newsec;
}

//helper
size_t inode_expand_sublevel (struct inode *inode, size_t newsec, struct indblock* uplevel);

//doubly indirect
size_t inode_expand_di (struct inode *inode, size_t newsec){

  	struct indblock b;

	if (inode->didindex == 0 && inode->idindex == 0){
		free_map_allocate(1, &inode->arr[inode->dindex]);
	}

	else{
		block_read(fs_device, inode->arr[inode->dindex], &b);
	}

	while (inode->idindex < 128){
		newsec = inode_expand_sublevel(inode, newsec, &b);

		if (newsec == 0)break;
	}

	block_write(fs_device, inode->arr[inode->dindex], &b);

	return newsec;
}

size_t inode_expand_sublevel (struct inode *inode, size_t newsec, struct indblock* uplevel){

	static char blank[BLOCK_SECTOR_SIZE];

	struct indblock b;

	if (inode->didindex == 0){
		free_map_allocate(1, &uplevel->arr[inode->idindex]);
	}
	else{
		block_read(fs_device, uplevel->arr[inode->idindex], &b);
	}
	while (inode->didindex < 128){
		free_map_allocate(1, &b.arr[inode->didindex]);

		block_write(fs_device, b.arr[inode->didindex], blank);

		inode->didindex++;
		newsec--;

		if (newsec == 0)break;

	}

	block_write(fs_device, uplevel->arr[inode->idindex], &b);

	//move on to next indirect block
	if (inode->didindex == 128){
		inode->didindex = 0;
		inode->idindex++;
	}
	return newsec;
}

bool inode_is_file(const struct inode *inode) {
	return inode->isfile;
}

void inode_lock (const struct inode *inode) {
 lock_acquire(&((struct inode *)inode)->mutex);
}
void inode_unlock (const struct inode *inode) {
 lock_release(&((struct inode *)inode)->mutex);
}
bool inode_add_parent(block_sector_t parent_sector, block_sector_t child_sector) {
	struct inode* inode = inode_open(child_sector);
	if(!inode) return false;
	inode->parent = parent_sector;
	inode_close(inode);
	return true;
}

int inode_get_open_cnt (const struct inode *inode) {
	return inode->open_cnt;
}

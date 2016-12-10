#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;

void inode_init (void);
bool inode_create (block_sector_t sector, off_t length, bool isfile);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

block_sector_t getInodeParent(const struct inode* i);


off_t inode_expand (struct inode *inode, off_t newlen);
size_t inode_expand_i (struct inode *inode, size_t newsec);
size_t inode_expand_di (struct inode *inode, size_t newsec);


bool inode_is_file(const struct inode *);
void inode_lock (const struct inode *inode);
void inode_unlock (const struct inode *inode);
bool inode_add_parent(block_sector_t parent_sector, block_sector_t child_sector);
int inode_get_open_cnt(const struct inode *);

#endif /* filesys/inode.h */

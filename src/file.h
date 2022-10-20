#ifndef _FILE_H_
#define _FILE_H_

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <list.h>

struct file {
        struct list_head        list;   /* sscp->file_list */

        char            *path;
        bool            remote;
        size_t          size;   /* size of this file */
};

struct chunk {
        struct list_head        list;   /* sscp->chunk_list */
        struct file *f;
        size_t  off;    /* offset of this chunk on the file f */
        size_t  len;    /* length of this chunk */
};

char *file_find_hostname(char *path);
bool file_has_hostname(char *path);
int file_is_directory(char *path, sftp_session sftp);

int file_fill(sftp_session sftp, struct list_head *head, char **src_array, int count);

int chunk_fill(struct list_head *file_head, struct list_head *chunk_head,
               int nr_conn, int min_chunk_sz, int max_chunk_sz);

#ifdef DEBUG
void file_dump(struct list_head *file_head);
void chunk_dump(struct list_head *chunk_head);
#endif


#endif /* _FILE_H_ */

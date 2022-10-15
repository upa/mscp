#ifndef _FILE_H_
#define _FILE_H_

struct path {
        char *path;
        bool remote;
};

struct file {
        struct path     src;    /* copy source */
        struct path     dst;    /* copy desitnation */
        size_t          size;   /* size of this file */
};

struct chunk {
        struct file *f;
        size_t  off;    /* offset of this chunk on the file f */
        size_t  len;    /* length of this chunk */
};

struct file *file_expand(char **src_array, char *dst)
{
        /* return array of files expanded from sources and dst */
        return NULL;
}


#endif /* _FILE_H_ */

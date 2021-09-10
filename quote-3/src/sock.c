#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>
#include <sys/vmsystm.h>
#include <sys/policy.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/isa_defs.h>
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/filio.h>
#include <sys/sendfile.h>
#include <sys/ddi.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <sys/stream.h>
#include <sys/thread.h>

#include "sock.h"


//static proc_t * sock_task				  = NULL;
//static uf_info_t* sock_files			  = NULL;
//static struct file * sock_file			  = NULL;
//static struct sonode  * sock_socket		  = NULL;

static void
release_tf(proc_t * task, int fd)
{
	uf_info_t *fip = &task->p_user.u_finfo;
	uf_entry_t *ufp;

	UF_ENTER(ufp, fip, fd);
	ASSERT(ufp->uf_refcnt > 0);
	clear_active_fd(fd);    /* clear the active file descriptor */
	if (--ufp->uf_refcnt == 0)
	  cv_broadcast(&ufp->uf_closing_cv); 
	UF_EXIT(ufp);
}

static struct sonode *
get_sonode(file_t *fp, int *errorp)
{
	vnode_t *vp;
	struct sonode *so;

	vp = fp->f_vnode;
	/* Check if it is a socket */
	if (vp->v_type != VSOCK) {
		//release_tf(sock);
		*errorp = ENOTSOCK;
		cmn_err(CE_WARN, "ENOTSOCK : file(%p) is not a socket\n", fp);
		return (NULL);
	}
	/*
	 * Use the stream head to find the real socket vnode.
	 * This is needed when namefs sits above sockfs.
	 */
	if (vp->v_stream) {
		ASSERT(vp->v_stream->sd_vnode);
		vp = vp->v_stream->sd_vnode;

		so = VTOSO(vp);
		if (so->so_version == SOV_STREAM) {
			//release_tf(sock);
			*errorp = ENOTSOCK;
			cmn_err(CE_WARN, "ENOTSOCK : not a socket\n");
			return (NULL);
		}
	} else {
		so = VTOSO(vp);
	}
	return (so);
}


//static struct sock_socket *
//sock_from_file(struct file * file)
//{
//	struct vnode * vnode = file->f_vnode;
//	if (vnode->v_type == VSOCK)
//	  return vnode->v_data;	/* set in sock_map_fd */
//
//	return NULL;
//}

static const char *
proc_stat2str(char stat)
{
	switch((int) stat)
	{
		case SSLEEP: return "SLEEP";
		case SRUN: return "RUNABLE";
		case SZOMB: return "ZOMB";
		case SSTOP: return "STOP";
		case SIDL: return "SIDL";
		case SONPROC: return "ONPROC";
		default: return "UNKOWN";
	}
}

static void
show_task(const proc_t * task)
{
	cmn_err(CE_NOTE, "task: stat=%s\n",  proc_stat2str(task->p_stat));
}

static void
show_files(const uf_info_t * files)
{
	cmn_err(CE_NOTE, "files : nfiles=%d\n", files->fi_nfiles);
}

static void
show_file(const struct file * file)
{
	cmn_err(CE_NOTE, "file : ref_count=%d\n", file->f_count);
}

//static void
//show_socket(const struct socket * sock)
//{
//	cmn_err(CE_NOTE, "socket : \n");
//}

static void
task_lock(proc_t * task)
{
	mutex_enter(&task->p_lockp->pl_lock);
}

static void
task_unlock(proc_t * task)
{
	mutex_exit(&task->p_lockp->pl_lock);
}


//static void
//files_lock(uf_info_t * files)
//{
//	mutex_enter(&files->fi_lock);
//}
//
//static void
//files_unlock(uf_info_t * files)
//{
//	mutex_exit(&files->fi_lock);
//}
//
//static void
//fd_lock(uf_info_t * files, int fd)
//{
//	uf_entry_t * ufp;
//	/**acquire the mutex for fi_list */
//	mutex_enter(&files->fi_lock);
//	ufp = &files->fi_list[fd];
//	/**acquire the mutex for a fi_list entry */
//	mutex_enter(&ufp->uf_lock);
//}
//
//static void
//fd_unlock(uf_info_t * files, int fd)
//{
//	uf_entry_t * ufp;
//	/**acquire the mutex for fi_list */
//	ufp = &files->fi_list[fd];
//	mutex_exit(&ufp->uf_lock);
//	mutex_exit(&files->fi_lock);
//}

static void
set_active_fd(int fd, kthread_t * kthread)
{
	afd_t *afd = &kthread->t_activefd;
	int i;
	int *old_fd;
	int old_nfd;
	int *new_fd;
	int new_nfd;

	if (afd->a_nfd == 0) {  /* first time initialization */
		ASSERT(fd == -1);
		mutex_enter(&afd->a_fdlock);
		free_afd(afd);
		mutex_exit(&afd->a_fdlock);
	}

	/* insert fd into vacant slot, if any */
	for (i = 0; i < afd->a_nfd; i++) {
		if (afd->a_fd[i] == -1) {
			afd->a_fd[i] = fd;
			return;
		}
	}

	/*
	 * Reallocate the a_fd[] array to add one more slot.
	 */
	ASSERT(fd == -1);
	old_nfd = afd->a_nfd;
	old_fd = afd->a_fd;
	new_nfd = old_nfd + 1;
	new_fd = kmem_alloc(new_nfd * sizeof (afd->a_fd[0]), KM_SLEEP);
	//MAXFD(new_nfd);
	//COUNT(afd_alloc);

	mutex_enter(&afd->a_fdlock);
	afd->a_fd = new_fd;
	afd->a_nfd = new_nfd;
	for (i = 0; i < old_nfd; i++)
	  afd->a_fd[i] = old_fd[i];
	afd->a_fd[i] = fd;
	mutex_exit(&afd->a_fdlock);

	if (old_nfd > sizeof (afd->a_buf) / sizeof (afd->a_buf[0])) {
		//COUNT(afd_free);
		kmem_free(old_fd, old_nfd * sizeof (afd->a_fd[0]));
	}
}

static file_t *
get_file(proc_t * task, int fd)
{
	uf_info_t* files;//include  a file list	
	file_t * file;	
	uf_entry_t * ufp;
	
	/** get file*/
	files = &task->p_user.u_finfo;
	show_files(files);
	if ((uint_t)fd >= files->fi_nfiles) 
	{
		cmn_err(CE_WARN, "get_file_by_files_fd : invalid fd(%d) > nfiles(%d)\n",
					fd, files->fi_nfiles);
		return (NULL);
	}
	set_active_fd(-1, &task->p_tlist[0]);
	UF_ENTER(ufp, files, fd);
	
	if ((file = ufp->uf_file) == NULL) {
		UF_EXIT(ufp);

		if(fd == files->fi_badfd && files->fi_action > 0)
		  tsignal(&task->p_tlist[0], files->fi_action);

		return (NULL);
	}
	ufp->uf_refcnt++;
	show_file(file);
	
	set_active_fd(fd, &task->p_tlist[0]);
	UF_EXIT(ufp);
	return file;
}

static struct sonode*
find_sock_by_pid_fd(pid_t pid, int fd, file_t **fpp, proc_t ** taskpp)
{
	file_t * file;
	struct sonode *so;
	int error;
	proc_t * task = prfind(pid);

	if(!task)
	{
		*fpp = NULL;
		*taskpp = NULL;
		cmn_err(CE_NOTE, "prfind faild, pid = %d\n", pid);
		return NULL;
	}
	task_lock(task);
	show_task(task);
	
	file = get_file(task, fd);
	if(!file)
	{
		release_tf(task, fd);
		task_unlock(task);
		*fpp = NULL;
		*taskpp = NULL;
		cmn_err(CE_WARN, "find_sock_by_pid_fd: get_file failed\n");
		return NULL;
	}
	so = get_sonode(file, &error);
	if(!so)
	{
		release_tf(task, fd);
		task_unlock(task);
		*fpp = NULL;
		*taskpp = NULL;
		cmn_err(CE_WARN, "find_sock_by_pid_fd: get_sonode failed\n");
		return NULL;
	}
	*fpp = file;
	*taskpp = task;
	return so;
}

/** DONNOT work */
//static struct sonode *
//find_sock_by_fd(int fd, int * err, file_t ** fp)
//{
//	struct sonode * so;
//
//	so = get_sonode(fd, err, fp);
//	return  so;
//}

static struct sockaddr *
copyin_name(struct sonode *so, struct sockaddr *name, socklen_t *namelenp,
			int *errorp)
{
	char    *faddr;
	size_t  namelen = (size_t)*namelenp;

	cmn_err(CE_NOTE, "copyin_name : name = %p, namelen = %ld\n", name, namelen);
	ASSERT(namelen != 0);
	if (namelen > SO_MAXARGSIZE) {
		*errorp = EINVAL;
		eprintsoline(so, *errorp);
		cmn_err(CE_WARN, "copyin_name: namelen = %ld > SO_MAXARGSIZE = %d",
					namelen, SO_MAXARGSIZE);
		return (NULL);
	}

	faddr = (char *)kmem_alloc(namelen, KM_SLEEP);
	if (ddi_copyin(name, faddr, namelen, FKIOCTL)) {
		kmem_free(faddr, namelen);
		*errorp = EFAULT;
		eprintsoline(so, *errorp);
		cmn_err(CE_WARN, "copyin_name : ddi_copyin failed");
		return (NULL);
	}

	/*
	 * Add space for NULL termination if needed.
	 * Do a quick check if the last byte is NUL.
	 */
	if (so->so_family == AF_UNIX && faddr[namelen - 1] != '\0') {
		/* Check if there is any NULL termination */
		size_t  i;
		int foundnull = 0;

		for (i = sizeof (name->sa_family); i < namelen; i++) {
			if (faddr[i] == '\0') {
				foundnull = 1;
				break;
			}
		}
		if (!foundnull) {
			/* Add extra byte for NUL padding */
			char *nfaddr;

			nfaddr = (char *)kmem_alloc(namelen + 1, KM_SLEEP);
			bcopy(faddr, nfaddr, namelen);
			kmem_free(faddr, namelen);

			/* NUL terminate */
			nfaddr[namelen] = '\0';
			namelen++;
			ASSERT((socklen_t)namelen == namelen);
			*namelenp = (socklen_t)namelen;
			faddr = nfaddr;
		}
	}
	return ((struct sockaddr *)faddr);
}

static int
sock_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
			cred_t *cr)
{
	int error = 0;
	ssize_t orig_resid = uiop->uio_resid;

	/*
	 * Do not bypass the cache if we are doing a local (AF_UNIX) write.
	 */
	if (so->so_family == AF_UNIX)
	  uiop->uio_extflg |= UIO_COPY_CACHED;
	else
	  uiop->uio_extflg &= ~UIO_COPY_CACHED;

	error = SOP_SENDMSG(so, msg, uiop, cr);
	switch (error) {
		default:
			break;
		case EINTR:
		case ENOMEM:
			/* EAGAIN is EWOULDBLOCK */
		case EWOULDBLOCK:
			/* We did a partial send */
			cmn_err(CE_NOTE, "sock_sendmsg : partial send\n");
			if (uiop->uio_resid != orig_resid)
			  error = 0;
			break;
		case EPIPE:
			if ((so->so_mode & SM_KERNEL) == 0)
			  tsignal(curthread, SIGPIPE);
			break;
	}
	cmn_err(CE_NOTE, "sock_sendmsg : old = %ld, new = %ld\n",
				orig_resid, uiop->uio_resid);
	cmn_err(CE_NOTE, "sock_sendmsg : error = %d\n", error);

	return (error);
}

ssize_t 
sock_send_pid_fd(pid_t pid, int sock, struct nmsghdr *msg, struct uio * uiop, int flags)
{
	struct sonode *so;
	file_t *fp;
	void * name;
	socklen_t namelen;
	void *control;
	socklen_t controllen;
	ssize_t len;
	int error;
	proc_t * task;

	so = find_sock_by_pid_fd(pid, sock, &fp, &task);

	if(!so) 
	{
		cmn_err(CE_WARN, "could find socket by sockfd(%d)\n", sock);
		return set_errno(error);
	}

	uiop->uio_fmode = fp->f_flag;

	if (so->so_family == AF_UNIX)
	  uiop->uio_extflg = UIO_COPY_CACHED;
	else
	  uiop->uio_extflg = UIO_COPY_DEFAULT;

	/* Allocate and copyin name and control */
	name = msg->msg_name;
	namelen = msg->msg_namelen;
	if (name != NULL && namelen != 0) {
		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		name = copyin_name(so,
					(struct sockaddr *)name,
					&namelen, &error);
		if (name == NULL)
		{
			cmn_err(CE_WARN, "copyin_name failed\n");
			goto done3;
		}
		/* copyin_name null terminates addresses for AF_UNIX */
		msg->msg_namelen = namelen;
		msg->msg_name = name;
	} else {
		msg->msg_name = name = NULL;
		msg->msg_namelen = namelen = 0;
	}

	control = msg->msg_control;
	controllen = msg->msg_controllen;
	if ((control != NULL) && (controllen != 0)) {
		/*
		 * Verify that the length is not excessive to prevent
		 * an application from consuming all of kernel memory.
		 */
		if (controllen > SO_MAXARGSIZE) {
			error = EINVAL;
			goto done2;
		}
		control = kmem_alloc(controllen, KM_SLEEP);

		ASSERT(MUTEX_NOT_HELD(&so->so_lock));
		if (copyin(msg->msg_control, control, controllen)) {
			error = EFAULT;
			goto done1;
		}
		msg->msg_control = control;
	} else {
		msg->msg_control = control = NULL;
		msg->msg_controllen = controllen = 0;
	}

	len = uiop->uio_resid;
	msg->msg_flags = flags;

	error = sock_sendmsg(so, msg, uiop, fp->f_cred);
done1:
	if (control != NULL)
	  kmem_free(control, controllen);
done2:
	if (name != NULL)
	  kmem_free(name, namelen);
done3:
	if (error != 0) {
		release_tf(task, sock);
		task_unlock(task);
		return (set_errno(error));
	}
	lwp_stat_update(LWP_STAT_MSGSND, 1);
	release_tf(task, sock);
	task_unlock(task);
	cmn_err(CE_NOTE, "sock_send : len = %ld, uio_resid = %ld\n", len, uiop->uio_resid);
	return (len - uiop->uio_resid);
}

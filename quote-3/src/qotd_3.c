#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksocket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>
#include <sys/vnode.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/prsystm.h>
#include <sys/modctl.h>
#include <sys/avl.h>
#include <sys/door.h>
#include <sys/zone.h>
#include <sys/tsol/label.h>
#include <sys/sid.h>
#include <sys/idmap.h>
#include <sys/varargs.h>
#include <sys/sysconf.h>

#include "qotd.h"
#include "sock.h"

#define QOTD_NAME       "qotd_3"

static char init_qotd[] = "On the whole, I'd rather be in Philadelphia. - W. C. Fields\n";
static const size_t init_qotd_len = 128;

#define QOTD_MAX_LEN		65536           /* Maximum quote in bytes */
#define QOTD_CHANGED    	0x1             /* User has made modifications */
#define QOTD_DIDMINOR   	0x2             /* Created minors */
#define QOTD_DIDALLOC   	0x4             /* Allocated storage space */
#define QOTD_DIDMUTEX   	0x8             /* Created mutex */
#define QOTD_DIDCV      	0x10            /* Created cv */
#define QOTD_BUSY       	0x20            /* Device is busy */
#define QOTD_PIDCHANGED 	0x40            /* PID has been changed */
#define QOTD_FDCHANGED  	0x80            /* sockfd has been changed */
#define QOTD_IPCHANGED		0x100            /* IP has been changed */
#define QOTD_PORTCHANGED	0x200            /* port has been changed */

static void *qotd_state_head	= NULL;
//static pid_t qotd_pid			= 0;
//static int qotd_sockfd              = 0;
//static uint32_t qotd_ip         = 0;
//static uint16_t qotd_port       = 0;

struct qotd_state {
	int             instance;
	dev_info_t      *devi;
	kmutex_t        lock;
	kcondvar_t      cv;
	char            *qotd;//memory addr return by ddi_umem_alloc
	size_t          qotd_len;
	ddi_umem_cookie_t qotd_cookie;//used by the ddi_umem_free(9F) function to free the memory
	int             flags;
	pid_t			pid;
	int				sockfd;
	uint32_t		ip;
	uint16_t		port;
};

static int qotd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int qotd_attach(dev_info_t *, ddi_attach_cmd_t);
static int qotd_detach(dev_info_t *, ddi_detach_cmd_t);
static int qotd_open(dev_t *, int, int, cred_t *);
static int qotd_close(dev_t, int, int, cred_t *);
static int qotd_read(dev_t, struct uio *, cred_t *);
static int qotd_write(dev_t, struct uio *, cred_t *);
static int qotd_rw(dev_t, struct uio *, enum uio_rw);
static int qotd_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops qotd_cb_ops = {
	qotd_open,              /* cb_open */
	qotd_close,             /* cb_close */
	nodev,                  /* cb_strategy */
	nodev,                  /* cb_print */
	nodev,                  /* cb_dump */
	qotd_read,              /* cb_read */
	qotd_write,             /* cb_write */
	qotd_ioctl,             /* cb_ioctl */
	nodev,                  /* cb_devmap */
	nodev,                  /* cb_mmap */
	nodev,                  /* cb_segmap */
	nochpoll,               /* cb_chpoll */
	ddi_prop_op,            /* cb_prop_op */
	(struct streamtab *)NULL,       /* cb_str */
	D_MP | D_64BIT,         /* cb_flag */
	CB_REV,                 /* cb_rev */
	nodev,                  /* cb_aread */
	nodev                   /* cb_awrite */
};

static struct dev_ops qotd_dev_ops = {
	DEVO_REV,               /* devo_rev */
	0,                      /* devo_refcnt */
	qotd_getinfo,           /* devo_getinfo */
	nulldev,                /* devo_identify */
	nulldev,                /* devo_probe */
	qotd_attach,            /* devo_attach */
	qotd_detach,            /* devo_detach */
	nodev,                  /* devo_reset */
	&qotd_cb_ops,           /* devo_cb_ops */
	(struct bus_ops *)NULL, /* devo_bus_ops */
	nulldev,                /* devo_power */
	ddi_quiesce_not_needed, /* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Quote of the day 3.0",
	&qotd_dev_ops};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int retval;
	cmn_err(CE_NOTE, "loading module qotd_3...\n");

	if ((retval = ddi_soft_state_init(&qotd_state_head,
						sizeof (struct qotd_state), 1)) != 0)
	  return retval;
	if ((retval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&qotd_state_head);
		return (retval);
	}

	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int retval;
	cmn_err(CE_NOTE, "unloading module qotd_3...\n");

	if ((retval = mod_remove(&modlinkage)) != 0)
	  return (retval);
	ddi_soft_state_fini(&qotd_state_head);

	return (retval);
}

/*ARGSUSED*/
static int
qotd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	struct qotd_state *qsp;
	int retval = DDI_FAILURE;

	ASSERT(resultp != NULL);

	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			if ((qsp = ddi_get_soft_state(qotd_state_head,
								getminor((dev_t)arg))) != NULL) {
				*resultp = qsp->devi;
				retval = DDI_SUCCESS;
			} else
			  *resultp = NULL;
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = (void *)(intptr_t)getminor((dev_t)arg);
			retval = DDI_SUCCESS;
			break;
	}

	return (retval);
}

static int
qotd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	struct qotd_state *qsp;
	cmn_err(CE_NOTE, "attaching...\n");

	switch (cmd) {
		case DDI_ATTACH:
			if (ddi_soft_state_zalloc(qotd_state_head, instance)
						!= DDI_SUCCESS) {
				cmn_err(CE_WARN, "Unable to allocate state for %d\n",
							instance);
				return (DDI_FAILURE);
			}
			if ((qsp = ddi_get_soft_state(qotd_state_head, instance))
						== NULL) {
				cmn_err(CE_WARN, "Unable to obtain state for %d\n",
							instance);
				ddi_soft_state_free(dip, instance);
				return (DDI_FAILURE);
			}
			if (ddi_create_minor_node(dip, QOTD_NAME, S_IFCHR, instance,
							DDI_PSEUDO, 0) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Unable to create minor node for %d\n",
							instance);
				(void)qotd_detach(dip, DDI_DETACH);
				return (DDI_FAILURE);
			}
			qsp->flags |= QOTD_DIDMINOR;
			qsp->qotd = ddi_umem_alloc(init_qotd_len, DDI_UMEM_NOSLEEP,
						&qsp->qotd_cookie);
			if (qsp->qotd == NULL) {
				cmn_err(CE_WARN, "Unable to allocate storage for %d",
							instance);
				(void)qotd_detach(dip, DDI_DETACH);
				return (DDI_FAILURE);
			}
			qsp->flags |= QOTD_DIDALLOC;
			mutex_init(&qsp->lock, NULL, MUTEX_DRIVER, NULL);
			qsp->flags |= QOTD_DIDMUTEX;
			cv_init(&qsp->cv, NULL, CV_DRIVER, NULL);//initialize a condition variable.
			qsp->flags |= QOTD_DIDCV;

			(void)strlcpy(qsp->qotd, init_qotd, init_qotd_len);
			qsp->qotd_len = init_qotd_len;
			qsp->instance = instance;
			qsp->devi = dip;

			ddi_report_dev(dip);
			return (DDI_SUCCESS);
		case DDI_RESUME:
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}
}


static int
qotd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	struct qotd_state *qsp;

	switch (cmd) {
		case DDI_DETACH:
			qsp = ddi_get_soft_state(qotd_state_head, instance);
			if (qsp != NULL) {
				ASSERT(!(qsp->flags & QOTD_BUSY));
				if (qsp->flags & QOTD_CHANGED)
				  return (EBUSY);
				if (qsp->flags & QOTD_DIDCV)
				  cv_destroy(&qsp->cv);
				if (qsp->flags & QOTD_DIDMUTEX)
				  mutex_destroy(&qsp->lock);
				if (qsp->flags & QOTD_DIDALLOC) {
					ASSERT(qsp->qotd != NULL);
					ddi_umem_free(qsp->qotd_cookie);
				}
				if (qsp->flags & QOTD_DIDMINOR)
				  ddi_remove_minor_node(dip, NULL);
			}
			ddi_soft_state_free(qotd_state_head, instance);
			return (DDI_SUCCESS);
		case DDI_SUSPEND:
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
qotd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int instance = getminor(*devp);
	struct qotd_state *qsp;

	if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
	  return (ENXIO);

	ASSERT(qsp->instance == instance);

	if (otyp != OTYP_CHR)
	  return (EINVAL);

	return (0);
}

/*ARGSUSED*/
static int
qotd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	struct qotd_state *qsp;
	int instance = getminor(dev);

	if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
	  return (ENXIO);

	ASSERT(qsp->instance == instance);

	if (otyp != OTYP_CHR)
	  return (EINVAL);

	return (0);
}

/*ARGSUSED*/
static int
qotd_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return 0;
	return qotd_rw(dev, uiop, UIO_READ);
}

/*ARGSUSED*/
static int
qotd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return qotd_rw(dev, uiop, UIO_WRITE);
}

static int
qotd_rw(dev_t dev, struct uio *uiop, enum uio_rw rw)
{
	struct qotd_state *qsp;
	int instance = getminor(dev), retval;
	size_t len = uiop->uio_resid;/*	remaining bytes	to copy	*/
	struct sockaddr_in to;
	struct nmsghdr lmsg;

	if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
	  return (ENXIO);

	ASSERT(qsp->instance == instance);
	
	/** packet message from user*/
	cmn_err(CE_NOTE, "send message : qotd_sockfd = %d, len = %ld\n",
				qsp->sockfd, len);
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = qsp->ip;
	to.sin_port = qsp->port;

	lmsg.msg_name = (char *)&to;
	lmsg.msg_namelen = sizeof(to);
	lmsg.msg_control = NULL;
	return (len - sock_send_pid_fd(qsp->pid, qsp->sockfd, &lmsg, uiop, 0));

	return 0;


	if (len == 0)
	  return (0);

	mutex_enter(&qsp->lock);

	while (qsp->flags & QOTD_BUSY) {
		if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
			mutex_exit(&qsp->lock);
			return (EINTR);
		}
	}

	if (uiop->uio_offset < 0 || uiop->uio_offset > qsp->qotd_len) {
		mutex_exit(&qsp->lock);
		return (EINVAL);
	}

	if (len > qsp->qotd_len - uiop->uio_offset)
	  len = qsp->qotd_len - uiop->uio_offset;

	if (len == 0) {
		mutex_exit(&qsp->lock);
		return (rw == UIO_WRITE ? ENOSPC : 0);
	}

	qsp->flags |= QOTD_BUSY;
	mutex_exit(&qsp->lock);

	retval = uiomove((void *)(qsp->qotd + uiop->uio_offset), len, rw, uiop);

	mutex_enter(&qsp->lock);
	if (rw == UIO_WRITE)
	  qsp->flags |= QOTD_CHANGED;
	qsp->flags &= ~QOTD_BUSY;
	cv_broadcast(&qsp->cv);
	mutex_exit(&qsp->lock);

	return (retval);
}

/*ARGSUSED*/
static int
qotd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
			int *rvalp)
{
	struct qotd_state *qsp;
	int instance = getminor(dev);

	if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
	  return (ENXIO);

	ASSERT(qsp->instance == instance);

	switch (cmd) {
		case QOTDIOCGSZ: {
							 /* We are not guaranteed that ddi_copyout(9F) will read
							  * automatically anything larger than a byte.  Therefore we
							  * must duplicate the size before copying it out to the user.
							  */
							 size_t sz = qsp->qotd_len;

							 if (!(mode & FREAD))
							   return (EACCES);

#ifdef _MULTI_DATAMODEL
							 switch (ddi_model_convert_from(mode & FMODELS)) {
								 case DDI_MODEL_ILP32: {
														   size32_t sz32 = (size32_t)sz;
														   /** report the current device size back to the user */
														   if (ddi_copyout(&sz32, (void *)arg, sizeof (size32_t),
																		   mode) != 0)
															 return (EFAULT);
														   return (0);
													   }
								 case DDI_MODEL_NONE:
													   if (ddi_copyout(&sz, (void *)arg, sizeof (size_t),
																	   mode) != 0)
														 return (EFAULT);
													   return (0);
								 default:
													   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																   ddi_model_convert_from(mode & FMODELS));
													   return (ENOTSUP);
							 }
#else /* ! _MULTI_DATAMODEL */
							 if (ddi_copyout(&sz, (void *)arg, sizeof (size_t), mode) != 0)
							   return (EFAULT);
							 return (0);
#endif /* _MULTI_DATAMODEL */
						 }
		case QOTDIOCSSZ: {
							 size_t new_len;
							 char *new_qotd;
							 ddi_umem_cookie_t new_cookie;
							 uint_t model;

							 if (!(mode & FWRITE))
							   return (EACCES);

#ifdef _MULTI_DATAMODEL
							 model = ddi_model_convert_from(mode & FMODELS);

							 switch (model) {
								 case DDI_MODEL_ILP32: {
														   size32_t sz32;
														   if (ddi_copyin((void *)arg, &sz32, sizeof (size32_t),
																		   mode) != 0)
															 return (EFAULT);
														   new_len = (size_t)sz32;
														   break;
													   }
								 case DDI_MODEL_NONE:
													   if (ddi_copyin((void *)arg, &new_len, sizeof (size_t),
																	   mode) != 0)
														 return (EFAULT);
													   break;
								 default:
													   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																   model);
													   return (ENOTSUP);
							 }
#else /* ! _MULTI_DATAMODEL */
							 if (ddi_copyin((void *)arg, &new_len, sizeof (size_t),
											 mode) != 0)
							   return (EFAULT);
#endif /* _MULTI_DATAMODEL */

							 if (new_len == 0 || new_len > QOTD_MAX_LEN)
							   return (EINVAL);

							 new_qotd = ddi_umem_alloc(new_len, DDI_UMEM_SLEEP, &new_cookie);

							 mutex_enter(&qsp->lock);
							 while (qsp->flags & QOTD_BUSY) {
								 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
									 mutex_exit(&qsp->lock);
									 ddi_umem_free(new_cookie);
									 return (EINTR);
								 }
							 }
							 memcpy(new_qotd, qsp->qotd, min(qsp->qotd_len, new_len));
							 ddi_umem_free(qsp->qotd_cookie);
							 qsp->qotd = new_qotd;
							 qsp->qotd_cookie = new_cookie;
							 qsp->qotd_len = new_len;
							 qsp->flags |= QOTD_CHANGED;
							 mutex_exit(&qsp->lock);
							 cmn_err(CE_NOTE, "set size : %ld\n", qsp->qotd_len);

							 return (0);
						 }
		case QOTDIOCDISCARD: {
								 char *new_qotd = NULL;
								 ddi_umem_cookie_t new_cookie;

								 if (!(mode & FWRITE))
								   return (EACCES);

								 if (qsp->qotd_len != init_qotd_len) {
									 new_qotd = ddi_umem_alloc(init_qotd_len,
												 DDI_UMEM_SLEEP, &new_cookie);
								 }

								 mutex_enter(&qsp->lock);
								 while (qsp->flags & QOTD_BUSY) {
									 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
										 mutex_exit(&qsp->lock);
										 if (new_qotd != NULL)
										   ddi_umem_free(new_cookie);
										 return (EINTR);
									 }
								 }
								 if (new_qotd != NULL) {
									 ddi_umem_free(qsp->qotd_cookie);
									 qsp->qotd = new_qotd;
									 qsp->qotd_cookie = new_cookie;
									 qsp->qotd_len = init_qotd_len;
								 } else {
									 bzero(qsp->qotd, qsp->qotd_len);
								 }
								 (void)strlcpy(qsp->qotd, init_qotd, init_qotd_len);
								 qsp->flags &= ~QOTD_CHANGED;
								 mutex_exit(&qsp->lock);
								 break;
							 }
		case QOTDIOCSPID:
							 {
								 size_t new_pid;
								 uint_t model;

								 if (!(mode & FWRITE))
								 {
									 cmn_err(CE_WARN, "QOTDIOCSPID : mode not FWRITE\n");
									 return (EACCES);
								 }

#ifdef _MULTI_DATAMODEL
								 model = ddi_model_convert_from(mode & FMODELS);
								 if(mode & FKIOCTL)
								   cmn_err(CE_NOTE, "QOTDIOCSPID : kcpoy\n");
								 else
								   cmn_err(CE_NOTE, "QOTDIOCSPID : cpoyin\n");

								 switch (model) {
									 case DDI_MODEL_ILP32: {
															   size32_t pid32;
															   if (ddi_copyin((void *)arg, &pid32, sizeof(size32_t),
																			   mode) != 0)
															   {
																   cmn_err(CE_WARN, "QOTDIOCSPID DDI_MODEL_ILP32 : ddi_copyin failed\n");
																 return (EFAULT);
															   }
															   new_pid = (pid_t)pid32;
															   break;
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyin((void *)arg, &new_pid, sizeof (size_t),
																		   mode) != 0)
														   {
															   cmn_err(CE_WARN, "QOTDIOCSPID DDI_MODEL_NONE : ddi_copyin failed\n");
															   return (EFAULT);
														   }
														   break;
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   model);
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyin((void *)arg, &new_pid, sizeof(pid_t),
												 mode) != 0)
								 {
									 cmn_err(CE_WARN, "QOTDIOCSPID not _MULTI_DATAMODEL : ddi_copyin failed\n")
								   return (EFAULT);
								 }
#endif /* _MULTI_DATAMODEL */

								 if (new_pid <= 0)
								 {
									 cmn_err(CE_WARN, "invalid pid : %ld\n", new_pid);
									 return (EINVAL);
								 }

								 mutex_enter(&qsp->lock);
								 while (qsp->flags & QOTD_BUSY) {
									 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
										 mutex_exit(&qsp->lock);
										 cmn_err(CE_WARN, "EINTR\n");
										 return (EINTR);
									 }
								 }
								 qsp->pid = (pid_t) new_pid;
								 qsp->flags |= QOTD_PIDCHANGED;
								 mutex_exit(&qsp->lock);

								 cmn_err(CE_NOTE, "qotd ioctl set pid to : %d\n", qsp->pid);
								 break;
							 }
		case QOTDIOCGPID:
							 {
								 /* We are not guaranteed that ddi_copyout(9F) will read
								  * automatically anything larger than a byte.  Therefore we
								  * must duplicate the pid before copying it out to the user.
								  */
								 pid_t pid = qsp->pid;

								 if (!(mode & FREAD))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 switch (ddi_model_convert_from(mode & FMODELS)) {
									 case DDI_MODEL_ILP32: {
															   size32_t pid32 = (size32_t)pid;
															   if (ddi_copyout(&pid32, (void *)arg, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   return (0);
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyout(&pid, (void *)arg, sizeof (pid_t),
																		   mode) != 0)
															 return (EFAULT);
														   return (0);
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   ddi_model_convert_from(mode & FMODELS));
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyout(&pid, (void *)arg, sizeof (size_t), mode) != 0)
								   return (EFAULT);
#endif
								 cmn_err(CE_NOTE, "qotd ioctl get pid : %d\n", qsp->pid);
								 break;
							 }
		case QOTDIOCSFD:
							 {
								 int new_fd;
								 uint_t model;

								 if (!(mode & FWRITE))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 model = ddi_model_convert_from(mode & FMODELS);

								 switch (model) {
									 case DDI_MODEL_ILP32: {
															   size32_t fd32;
															   if (ddi_copyin((void *)arg, &fd32, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   new_fd = (int)fd32;
															   break;
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyin((void *)arg, &new_fd, sizeof(int),
																		   mode) != 0)
															 return (EFAULT);
														   break;
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   model);
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyin((void *)arg, &new_fd, sizeof(int),
												 mode) != 0)
								   return (EFAULT);
#endif /* _MULTI_DATAMODEL */

								 if (new_fd <= 0)
								   return (EINVAL);

								 mutex_enter(&qsp->lock);
								 while (qsp->flags & QOTD_BUSY) {
									 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
										 mutex_exit(&qsp->lock);
										 return (EINTR);
									 }
								 }
								 qsp->sockfd = new_fd;
								 qsp->flags |= QOTD_FDCHANGED;
								 mutex_exit(&qsp->lock);

								 cmn_err(CE_NOTE, "qotd ioctl set fd to : %d\n", qsp->sockfd);
								 break;
							 }
		case QOTDIOCGFD:
							 {
								 /* We are not guaranteed that ddi_copyout(9F) will read
								  * automatically anything larger than a byte.  Therefore we
								  * must duplicate the fd before copying it out to the user.
								  */
								 int fd = qsp->sockfd;

								 if (!(mode & FREAD))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 switch (ddi_model_convert_from(mode & FMODELS)) {
									 case DDI_MODEL_ILP32: {
															   size32_t fd32 = (size32_t)fd;
															   if (ddi_copyout(&fd32, (void *)arg, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   return (0);
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyout(&fd, (void *)arg, sizeof (int),
																		   mode) != 0)
															 return (EFAULT);
														   return (0);
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   ddi_model_convert_from(mode & FMODELS));
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyout(&fd, (void *)arg, sizeof (size_t), mode) != 0)
								   return (EFAULT);
#endif
								 cmn_err(CE_NOTE, "qotd ioctl get fd : %d\n", qsp->sockfd);
								 break;
							 }
		case QOTDIOCSIP:
							 {
								 uint32_t new_ip;
								 uint_t model;

								 if (!(mode & FWRITE))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 model = ddi_model_convert_from(mode & FMODELS);

								 switch (model) {
									 case DDI_MODEL_ILP32: {
															   size32_t ip32;
															   if (ddi_copyin((void *)arg, &ip32, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   new_ip = (uint32_t)ip32;
															   break;
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyin((void *)arg, &new_ip, sizeof (uint32_t),
																		   mode) != 0)
															 return (EFAULT);
														   break;
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   model);
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyin((void *)arg, &new_ip, sizeof(uint32_t),
												 mode) != 0)
								   return (EFAULT);
#endif /* _MULTI_DATAMODEL */

								 if (new_ip <= 0)
								   return (EINVAL);

								 mutex_enter(&qsp->lock);
								 while (qsp->flags & QOTD_BUSY) {
									 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
										 mutex_exit(&qsp->lock);
										 return (EINTR);
									 }
								 }
								 qsp->ip = new_ip;
								 qsp->flags |= QOTD_IPCHANGED;
								 mutex_exit(&qsp->lock);

								 cmn_err(CE_NOTE, "qotd ioctl set ip to : %08x\n", qsp->ip);
								 break;
							 }
		case QOTDIOCGIP:
							 {
								 /* We are not guaranteed that ddi_copyout(9F) will read
								  * automatically anything larger than a byte.  Therefore we
								  * must duplicate the IP before copying it out to the user.
								  */
								 uint32_t ip = qsp->ip;

								 if (!(mode & FREAD))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 switch (ddi_model_convert_from(mode & FMODELS)) {
									 case DDI_MODEL_ILP32: {
															   size32_t ip32 = (size32_t)ip;
															   if (ddi_copyout(&ip32, (void *)arg, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   return (0);
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyout(&ip, (void *)arg, sizeof (uint32_t),
																		   mode) != 0)
															 return (EFAULT);
														   return (0);
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   ddi_model_convert_from(mode & FMODELS));
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyout(&ip, (void *)arg, sizeof (size_t), mode) != 0)
								   return (EFAULT);
#endif
								 cmn_err(CE_NOTE, "qotd ioctl get ip : %d\n", qsp->ip);
								 break;
							 }
		case QOTDIOCSPORT:
							 {
								 uint16_t new_port;
								 uint_t model;

								 if (!(mode & FWRITE))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 model = ddi_model_convert_from(mode & FMODELS);

								 switch (model) {
									 case DDI_MODEL_ILP32: {
															   size32_t port32;
															   if (ddi_copyin((void *)arg, &port32, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   new_port = (uint16_t)port32;
															   break;
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyin((void *)arg, &new_port, sizeof (uint16_t),
																		   mode) != 0)
															 return (EFAULT);
														   break;
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   model);
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyin((void *)arg, &new_port, sizeof(uint16_t),
												 mode) != 0)
								   return (EFAULT);
#endif /* _MULTI_DATAMODEL */

								 if (new_port <= 0)
								   return (EINVAL);

								 mutex_enter(&qsp->lock);
								 while (qsp->flags & QOTD_BUSY) {
									 if (cv_wait_sig(&qsp->cv, &qsp->lock) == 0) {
										 mutex_exit(&qsp->lock);
										 return (EINTR);
									 }
								 }
								 qsp->port = new_port;
								 qsp->flags |= QOTD_PORTCHANGED;
								 mutex_exit(&qsp->lock);

								 cmn_err(CE_NOTE, "qotd ioctl set port to : %04x\n", qsp->port);
								 break;
							 }
		case QOTDIOCGPORT:
							 {
								 /* We are not guaranteed that ddi_copyout(9F) will read
								  * automatically anything larger than a byte.  Therefore we
								  * must duplicate the port before copying it out to the user.
								  */
								 uint16_t port = qsp->port;

								 if (!(mode & FREAD))
								   return (EACCES);

#ifdef _MULTI_DATAMODEL
								 switch (ddi_model_convert_from(mode & FMODELS)) {
									 case DDI_MODEL_ILP32: {
															   size32_t port32 = (size32_t)port;
															   if (ddi_copyout(&port32, (void *)arg, sizeof(size32_t),
																			   mode) != 0)
																 return (EFAULT);
															   return (0);
														   }
									 case DDI_MODEL_NONE:
														   if (ddi_copyout(&port, (void *)arg, sizeof (uint16_t),
																		   mode) != 0)
															 return (EFAULT);
														   return (0);
									 default:
														   cmn_err(CE_WARN, "Invalid data model %d in ioctl\n",
																	   ddi_model_convert_from(mode & FMODELS));
														   return (ENOTSUP);
								 }
#else /* ! _MULTI_DATAMODEL */
								 if (ddi_copyout(&port, (void *)arg, sizeof (size_t), mode) != 0)
								   return (EFAULT);
#endif
								 cmn_err(CE_NOTE, "qotd ioctl get port : %d\n", qsp->port);
								 break;
							 }
		default:
							 cmn_err(CE_NOTE, "qotd ioctl invalid cmd : %d", cmd);
							 return (ENOTTY);
	}
	return 0;
}

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sched.h>
#include "qotd_2_ioctl.h"

#define QOTD_NAME       "qotd"
#define QOTD_MAXLEN     128

static const char qotd[QOTD_MAXLEN]
        = "You can't have everything. \
Where would you put it? - Steven Wright";

static void *qotd_state_head = NULL;
static pid_t qotd_pid                     = 0;
static int qotd_fd                        = 0;
static uint32_t qotd_ip                   = 0;
static uint16_t qotd_port                 = 0;
static struct task_struct* qotd_task      = NULL;
static struct files_struct* qotd_files    = NULL;
static struct file* qotd_file             = NULL;
static struct socket* qotd_socket         = NULL;

static struct socket *find_sock_by_pid_fd(pid_t pid, int fd, int *err);
static struct task_struct * get_task_by_pid(int pid);
static struct files_struct* get_files_by_task(struct task_struct * task);
static struct file * get_file_by_file_fd(struct files_struct * files, int fd);

struct qotd_state {
        int             instance;
        dev_info_t      *devi;
};

static int qotd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int qotd_attach(dev_info_t *, ddi_attach_cmd_t);
static int qotd_detach(dev_info_t *, ddi_detach_cmd_t);
static int qotd_open(dev_t *, int, int, cred_t *);
static int qotd_close(dev_t, int, int, cred_t *);
static int qotd_read(dev_t, struct uio *, cred_t *);
static int qotd_write(dev_t, struct uio *, cred_t *);
static int qotd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p);

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
        "Quote of the Day 2.0",
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
		cmn_err(CE_NOTE, "qotd_t loading...\n");

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
		cmn_err(CE_NOTE, "qotd_t unloading...\n");
        int retval;

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
                *resultp = (void *)getminor((dev_t)arg);
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

        switch (cmd) {
        case DDI_ATTACH:
                if (ddi_soft_state_zalloc(qotd_state_head, instance)
                    != DDI_SUCCESS) {
                        cmn_err(CE_WARN, "Unable to allocate state for %d",
                            instance);
                        return (DDI_FAILURE);
                }
                if ((qsp = ddi_get_soft_state(qotd_state_head, instance))
                    == NULL) {
                        cmn_err(CE_WARN, "Unable to obtain state for %d",
                            instance);
                        ddi_soft_state_free(dip, instance);
                        return (DDI_FAILURE);
                }
                if (ddi_create_minor_node(dip, QOTD_NAME, S_IFCHR, instance,
                    DDI_PSEUDO, 0) != DDI_SUCCESS) {
                        cmn_err(CE_WARN, "Cannot create minor node for %d",
                            instance);
                        ddi_soft_state_free(dip, instance);
                        ddi_remove_minor_node(dip, NULL);
                        return (DDI_FAILURE);
                }
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

        switch (cmd) {
        case DDI_DETACH:
                ddi_soft_state_free(qotd_state_head, instance);
                ddi_remove_minor_node(dip, NULL);
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
        struct qotd_state *qsp;
        int instance = getminor(dev);

        if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
                return (ENXIO);

        ASSERT(qsp->instance == instance);

		cmn_err(CE_NOTE, "uio_resid = %ld, strlen(qotd) = %ld\n", uiop->uio_resid, strlen(qotd));
        return (uiomove((void *)qotd, min(uiop->uio_resid, strlen(qotd)),
            UIO_READ, uiop));
}

static int
qotd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
        struct qotd_state *qsp;
        int instance = getminor(dev), err;
		char buffer[QOTD_MAXLEN];

        if ((qsp = ddi_get_soft_state(qotd_state_head, instance)) == NULL)
                return (ENXIO);

        ASSERT(qsp->instance == instance);

		cmn_err(CE_NOTE, "uio_resid = %ld, strlen(qotd) = %ld\n", uiop->uio_resid, strlen(qotd));
        err = uiomove((void *)buffer, min(uiop->uio_resid, QOTD_MAXLEN),
            UIO_WRITE, uiop);
		if(!err)
		  cmn_err(CE_NOTE, "data from user : %s\n", buffer);
		return err;
}

static int 
qotd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	switch(cmd)
    {
        case IOCSPID:
            qotd_pid = arg;
            cmn_err(CE_NOTE, "qotd ioctl set pid : %d\n", qotd_pid);
            break;
        case IOCGPID:
            *(pid_t *)arg  = qotd_pid;
            cmn_err(CE_NOTE, "qotd ioctl get pid : %d\n", qotd_pid);
            break;
        case IOCSFD:
            qotd_fd = arg;
            cmn_err(CE_NOTE, "qotd ioctl set fd : %d\n", qotd_fd);
            break;
        case IOCGFD:
            *(int *)arg = qotd_fd;
            cmn_err(CE_NOTE, "qotd ioctl get fd : %d\n", qotd_fd);
            break;
        case IOCSIP:
            qotd_ip = arg;
            cmn_err(CE_NOTE, "qotd ioctl set ip : %08x\n", qotd_ip);
            break;
        case IOCGIP:
            *(uint32_t *)arg = qotd_ip;
            cmn_err(CE_NOTE, "qotd ioctl get ip : %08x\n", qotd_ip);
            break;
		case IOCSPORT:
            qotd_port = arg;
            cmn_err(CE_NOTE, "qotd ioctl set port : %04x\n", qotd_port);
            break;
        case IOCGPORT:
            *(uint16_t *)arg = qotd_port;
            cmn_err(CE_NOTE, "qotd ioctl get port : %04x\n", qotd_port);
            break;
        default:
            cmn_err(CE_NOTE, "qotd ioctl invalid cmd : %d", cmd);
            return -EINVAL;
    }
	return 0;
}

static struct socket *
find_sock_by_pid_fd(pid_t pid, int fd, int *err)
{
    qotd_task = get_task_by_pid(pid);
    if(!qotd_task)
    {
        cmn_err(CE_NOTE, "get_task_by_pid faild, pid = %d\n", pid);
        return NULL;
    }

    qotd_files = get_files_by_task(qotd_task);
    if(!qotd_files)
    {
        cmn_err(CE_NOTE, "get_files_by_task failed\b");
        return NULL;
    }

    qotd_file = get_file_by_file_fd(qotd_files, fd);
    if(!qotd_file)
    {
        cmn_err(CE_NOTE, "get_file_by_file_fd failed\b");
        return NULL;
    }

    //qotd_socket = sock_from_file(qotd_file, err);
    return qotd_socket;
}

static struct task_struct *
get_task_by_pid(int pid)
{
    struct task_struct * task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task)
      get_task_struct(task);
    return task;
}

static struct files_struct*
get_files_by_task(struct task_struct * task)
{
#ifdef UP
    struct files_struct * files;
    task_lock(task);
    files = task->files;
    task_unlock(task);
    return files;
#endif
	return NULL;
}

static struct file *
get_file_by_file_fd(struct files_struct * files, int fd)
{
#ifdef UP
    struct file * file;
    rcu_read_lock();
    file = fcheck_files(files, fd);
    rcu_read_unlock();
    return file;
#endif
	return NULL;
}

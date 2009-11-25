/*
 * Envelope milter
 * Sendmail/Postfix pre-queue filter to check envelope sender against To header.
 *
 * Copyright (C) 2008-2009 Arnold Daniels <arnold@adaniels.nl>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "libmilter/mfapi.h"

#ifndef bool
# define bool   int
# define TRUE   1
# define FALSE  0
#endif /* ! bool */

struct mlfiPriv
{
	char *envfrom;
	bool validated;
};

struct string_list
{
	char *string;
	size_t strlen;
	struct string_list *next;
};

#define MLFIPRIV ((struct mlfiPriv *) smfi_getpriv(ctx))

extern sfsistat xxfi_cleanup(SMFICTX *, bool);

bool smdebugmode = FALSE;
struct string_list *sm_sender_exceptions = NULL;

sfsistat xxfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	struct mlfiPriv *priv;

	priv = malloc(sizeof *priv);
	if (priv == NULL)
		return SMFIS_TEMPFAIL;

	memset(priv, '\0', sizeof *priv);
	smfi_setpriv(ctx, priv);

	return SMFIS_CONTINUE;
}

sfsistat xxfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct mlfiPriv *priv= MLFIPRIV;
	char *envfrom = smfi_getsymval(ctx, "{mail_addr}");

	if (envfrom != NULL && (priv->envfrom = strdup(envfrom)) == NULL)
		return SMFIS_TEMPFAIL;

	return SMFIS_CONTINUE;
}

sfsistat xxfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv= MLFIPRIV;
	char *headerv_begin;
	struct string_list *sendexcep;
	size_t len;

	if (strcasecmp(headerf, "from") != 0)
		return SMFIS_CONTINUE;

	if (priv->envfrom == NULL)
	{
		if (smdebugmode)
			printf("continue: Null envelope sender\n");
		return SMFIS_CONTINUE;
	}

	headerv_begin = strchr(headerv, '<');
	if (headerv_begin == NULL)
		headerv_begin = headerv;
	else
		headerv_begin++;

	for (sendexcep = sm_sender_exceptions; sendexcep != NULL; sendexcep = sendexcep->next)
	{
		if (strncasecmp(sendexcep->string, headerv_begin, sendexcep->strlen) == 0 && (*(headerv_begin+sendexcep->strlen)=='>' || *(headerv_begin+sendexcep->strlen)=='\0')))
		{
			if (smdebugmode)
				printf("continue: Sender exception %s\n", sendexcep->string);
			return SMFIS_CONTINUE;
		}
	}
	
	len = strlen(priv->envfrom);
	if (strncasecmp(priv->envfrom, headerv_begin, len)) != 0 && (*(headerv_begin+len)=='>' || *(headerv_begin+len)=='\0')))
	{
		if (smdebugmode)
			printf("reject: Envelope sender %s does not match %s\n",
					priv->envfrom, headerv);
		syslog(LOG_NOTICE, "reject: Envelope sender %s does not match %s",
				priv->envfrom, headerv);

		return SMFIS_REJECT;
	}

	priv->validated = TRUE;

	if (smdebugmode)
		printf("continue: Envelope sender %s matches %s\n", priv->envfrom,
				headerv);

	return SMFIS_CONTINUE;
}

sfsistat xxfi_close(SMFICTX *ctx)
{
	struct mlfiPriv *priv= MLFIPRIV;

	if (priv == NULL)
		return SMFIS_CONTINUE;

	if (priv->envfrom != NULL)
		free(priv->envfrom);

	free(priv);
	smfi_setpriv(ctx, NULL);
	return SMFIS_CONTINUE;
}

sfsistat xxfi_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1,
		unsigned long f2, unsigned long f3, unsigned long *pf0,
		unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
	return SMFIS_ALL_OPTS;
}

struct smfiDesc smfilter =
{ "Envelope milter", /* filter name */
SMFI_VERSION, /* version code -- do not change */
0, /* flags */
xxfi_connect, /* connection info filter */
NULL, /* SMTP HELO command filter */
xxfi_envfrom, /* envelope sender filter */
NULL, /* envelope recipient filter */
xxfi_header, /* header filter */
NULL, /* end of header */
NULL, /* body block filter */
NULL, /* end of message */
NULL, /* message aborted */
xxfi_close, /* connection cleanup */
NULL, /* unknown SMTP commands */
NULL, /* DATA command */
xxfi_negotiate /* Once, at the start of each SMTP connection */
};

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s -p socket-addr [-t timeout] [-e sender] [-d]\n",
			prog);
}

int main(int argc, char **argv)
{
	bool setconn = FALSE;
	int c;
	const char *args = "p:t:e:dh";
	extern char *optarg;
	struct string_list *sendexcep;

	openlog("envelope-milter", 0, LOG_MAIL);

	/* Process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		case 'p':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal conn: %s\n", optarg);
				syslog(LOG_ERR, "Illegal conn: %s", optarg);
				exit(EX_USAGE);
			}
			if (smfi_setconn(optarg) == MI_FAILURE)
			{
				(void) fprintf(stderr, "smfi_setconn failed\n");
				syslog(LOG_ERR, "smfi_setconn failed\n");
				exit(EX_SOFTWARE);
			}

			/*
			 **  If we're using a local socket, make sure it
			 **  doesn't already exist.  Don't ever run this
			 **  code as root!!
			 */

			if (strncasecmp(optarg, "unix:", 5) == 0)
				unlink(optarg + 5);
			else if (strncasecmp(optarg, "local:", 6) == 0)
				unlink(optarg + 6);
			setconn = TRUE;
			break;

		case 't':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal timeout: %s\n", optarg);
				syslog(LOG_ERR, "Illegal timeout: %s\n", optarg);
				exit(EX_USAGE);
			}
			if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
			{
				(void) fprintf(stderr, "smfi_settimeout failed\n");
				syslog(LOG_ERR, "smfi_settimeout failed\n");
				exit(EX_SOFTWARE);
			}
			break;

		case 'e':
			if (optarg == NULL)
			{
				(void) fprintf(stderr, "Illegal sender exception: %s\n", optarg);
				exit(EX_USAGE);
			}
			
			sendexcep = (struct string_list *) malloc(sizeof(struct string_list));
			sendexcep->string = optarg;
			sendexcep->strlen = strlen(optarg);
			sendexcep->next = sm_sender_exceptions;
			sm_sender_exceptions = sendexcep;
			
			break;

		case 'd':
			smdebugmode = TRUE;
			printf("Debug mode\n");
			break;

		case 'h':
		default:
			usage(argv[0]);
			exit(EX_USAGE);
		}
	}

	if (!setconn)
	{
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}

	if (smfi_register(smfilter) == MI_FAILURE)
	{
		fprintf(stderr, "smfi_register failed\n");
		syslog(LOG_ERR, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}

	return smfi_main();
}

/* eof */

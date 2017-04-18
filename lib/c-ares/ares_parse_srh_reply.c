#include "ares_setup.h"

#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_data.h"
#include "ares_private.h"

#define T_SRH 65280
#define SRH_LEN (3 + 2*sizeof(struct ares_in6_addr))

int ares_parse_srh_reply(const unsigned char *abuf, int alen,
                         struct ares_srh_reply **srh_out)
{
  unsigned int qdcount, ancount, arcount, nscount, i;
  const unsigned char *aptr;
  int status = 0;
  unsigned int rr_type, rr_class, rr_ttl;
  unsigned short rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_srh_reply *srh = NULL;
  struct ares_srh_reply *first_srh = NULL;

  /* Set *srh_out to NULL for all failure cases. */
  *srh_out = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  nscount = DNS_HEADER_NSCOUNT (abuf);
  arcount = DNS_HEADER_ARCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0 || arcount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares__expand_name_for_response (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
  {
    ares_free (hostname);
    return ARES_EBADRESP;
  }
  aptr += len + QFIXEDSZ;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < ancount + nscount + arcount; i++)
  {
    /* Decode the RR up to the data field. */
    status = ares__expand_name_for_response (aptr, abuf, alen, &rr_name, &len);
    if (status != ARES_SUCCESS)
    {
      break;
    }
    aptr += len;
    if (aptr + RRFIXEDSZ > abuf + alen)
    {
      status = ARES_EBADRESP;
      break;
    }
    rr_type = DNS_RR_TYPE (aptr);
    rr_class = DNS_RR_CLASS (aptr);
    rr_len = DNS_RR_LEN (aptr);
    rr_ttl = DNS_RR_TTL(aptr);
    aptr += RRFIXEDSZ;
    if (aptr + rr_len > abuf + alen)
    {
      status = ARES_EBADRESP;
      break;
    }

    /* Check if we are really looking at a SRH record */
    if (rr_class == C_IN && rr_type == T_SRH)
    {
      if (rr_len != SRH_LEN) {
        status = ARES_EBADRESP;
        break;
      }

      struct ares_srh_reply *next_srh = ares_malloc_data(ARES_DATATYPE_SRH_REPLY);
      if (!next_srh) {
        status = ARES_ENOMEM;
        break;
      }
      if (!first_srh)
        first_srh = next_srh;
      else
        srh->next = next_srh;
      srh = next_srh;

      srh->rr_ttl = rr_ttl;
      srh->priority = DNS__16BIT(aptr);
      memcpy(&srh->prefix.addr, aptr + 2, sizeof(struct ares_in6_addr));
      srh->prefix.length = *(aptr + 2 + sizeof(struct ares_in6_addr));
      memcpy(&srh->binding_segment, aptr + 3 + sizeof(struct ares_in6_addr),
             sizeof(struct ares_in6_addr));
    }

    /* Propagate any failures */
    if (status != ARES_SUCCESS)
    {
      break;
    }

    /* Don't lose memory in the next iteration */
    ares_free (rr_name);
    rr_name = NULL;

    /* Move on to the next record */
    aptr += rr_len;
  }

  if (status == ARES_SUCCESS && !first_srh)
  {
    status = ARES_ENODATA;
  }

  if (hostname)
    ares_free (hostname);
  if (rr_name)
    ares_free (rr_name);

  /* clean up on error */
  if (status != ARES_SUCCESS)
  {
    if (first_srh)
      ares_free_data (first_srh);
    return status;
  }

  /* everything looks fine, return the data */
  *srh_out = first_srh;

  return ARES_SUCCESS;
}

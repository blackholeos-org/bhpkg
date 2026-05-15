#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "bhpkg.h"

static int
order (int c)
{
  if (isdigit (c)) return 0;
  if (isalpha (c)) return c;
  if (c == '~') return -1;
  if (c) return c + 256;
  return 0;
}

static int
cmp_string (const char **v, const char **r)
{
  int vc, rc;
  while (**v || **r)
    {
      vc = **v;
      rc = **r;
      if (!vc && !rc) break;

      if ((vc && !isdigit (vc)) || (rc && !isdigit (rc)))
        {
          int vo = order (vc);
          int ro = order (rc);

          if (vo != ro) return vo - ro;
          if (vc) (*v)++;
          if (rc) (*r)++;
        }
      else
        {
          long vn = 0, rn = 0;
          while (isdigit (**v)) vn = vn * 10 + (*(*v)++ - '0');
          while (isdigit (**r)) rn = rn * 10 + (*(*r)++ - '0');
          if (vn != rn) return vn - rn;
        }
    }
  return 0;
}

int
bhpkg_vercmp (const char *val, const char *ref)
{
  const char *v_epoch, *r_epoch;
  int v_ep = 0, r_ep = 0;
  const char *v_ver = val;
  const char *r_ver = ref;
  
  if (!val) val = "";
  if (!ref) ref = "";

  v_epoch = strchr (val, ':');
  r_epoch = strchr (ref, ':');

  if (v_epoch)
    {
      v_ep = atoi (val);
      v_ver = v_epoch + 1;
    }
  if (r_epoch)
    {
      r_ep = atoi (ref);
      r_ver = r_epoch + 1;
    }

  if (v_ep != r_ep)
    return v_ep - r_ep;

  const char *v_rev = strrchr (v_ver, '-');
  const char *r_rev = strrchr (r_ver, '-');
  
  char v_base[128] = {0};
  char r_base[128] = {0};

  if (v_rev)
    {
      strncpy (v_base, v_ver, v_rev - v_ver);
      v_rev++;
    }
  else
    {
      strncpy (v_base, v_ver, sizeof (v_base) - 1);
      v_rev = "";
    }

  if (r_rev)
    {
      strncpy (r_base, r_ver, r_rev - r_ver);
      r_rev++;
    }
  else
    {
      strncpy (r_base, r_ver, sizeof (r_base) - 1);
      r_rev = "";
    }

  const char *vb_ptr = v_base;
  const char *rb_ptr = r_base;
  int res = cmp_string (&vb_ptr, &rb_ptr);
  if (res != 0) return res;

  return cmp_string (&v_rev, &r_rev);
}
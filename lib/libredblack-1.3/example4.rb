// Redblack customization example, a part-number/price association
//
// Customization is smart whenever your data is fixed-length, 
// especially when your data size is comparable to the size of 
// a pointer plus malloc overhead (pointer size of 1 machine 
// word plus malloc overhead of two words).  Also it's faster
// (%access inline gets rid of a pointer access per node), your
// compiler can type check the resulting code, and your symbolic
// debugger can see into the nodes.

#include <string.h>
#include <stdio.h>

#define PN	8

typedef struct
{
    char pn[PN+1];
    int price;
}
price_t;

int compare(const price_t *s1, const price_t *s2)
{
    return strcmp(s1->pn, s2->pn);
}

// These are the redblack directives
%%rbgen
%type price_t		
%cmp compare
%access inline		// data is carried in the node structure itself.
%omit find walk delete readlist
%static
%prefix ex
%%rbgen

int main(int argc, char *argv[])
{
        struct extree *ex;
	const price_t samples[] =
	{
		{"THX1138", 40},
		{"ED2317",  55},
		{"NGC1136", 32},
	}, *val, *pp;

        if ((ex=exinit())==NULL)
        {
                fprintf(stderr, "insufficient memory\n");
                exit(1);
        }

	for (pp=samples; pp<samples+sizeof(samples)/sizeof(samples[0]);pp++)
	{
		val = exsearch(pp, ex);
                if(val == NULL)
                {
                        fprintf(stderr, "insufficient memory\n");
                        exit(1);
                }
	}
        for(val=exlookup(RB_LUFIRST, NULL, ex); val; val=exlookup(RB_LUNEXT, val, ex))
        {
                printf("%s:%d\n", val->pn, val->price);
        }

        exdestroy(ex);
        
        return 0;
}

// The following sets edit modes for GNU EMACS
// Local Variables:
// mode:c
// End:

#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#define MAXELEM 1024

char *dnssec_status_to_string(int status);
char *address_type_to_string(int status);


int
main(int argc, char *argv[])
{
    char *name = "getdnsapi.net";
    getdns_context *context;
    getdns_return_t ret;
    getdns_dict *extensions;
    getdns_dict *response;
    uint32_t status;
    uint32_t dnssec_status;
    uint32_t type;
    getdns_list *replies_tree;
    size_t nanswers;
    int  i;
    char element[MAXELEM];

    if (argc > 1)
        name = argv[1];

    if ((ret = getdns_context_create(&context, 1)) != GETDNS_RETURN_GOOD)  {
        fprintf(stderr, "getdns_context_create: %s\n",
		    getdns_get_errorstr_by_id(ret));
        return 1;
    }

    extensions = getdns_dict_create();
    if ((ret = getdns_dict_set_int(extensions, "/dnssec_return_status",
                                   GETDNS_EXTENSION_TRUE)) != GETDNS_RETURN_GOOD)  {
      	fprintf(stderr, "getdns_dict_set_int(dnssec_return_status): %s\n",
                getdns_get_errorstr_by_id(ret));
        return 1;
    }
    if ((ret = getdns_address_sync(context, name, extensions, &response)) !=
        GETDNS_RETURN_GOOD)  {
	      fprintf(stderr, "getdns_address_sync: %s\n",
                getdns_get_errorstr_by_id(ret));
        return 1;
    }

    (void)getdns_dict_get_int(response, "status", &status);
    if (status != GETDNS_RESPSTATUS_GOOD)  {
        printf("Bad status: ");
        switch (status) {
        case GETDNS_RESPSTATUS_NO_NAME:
            printf("GETDNS_RESPSTATUS_NO_NAME\n");
            break;
        case GETDNS_RESPSTATUS_ALL_TIMEOUT:
            printf("GETDNS_RESPSTATUS_ALL_TIMEOUT\n");
            break;
        default:
            break;
        }
    }

    if ((ret = getdns_dict_get_list(response, "/replies_tree", &replies_tree)) !=
        GETDNS_RETURN_GOOD)  {
        fprintf(stderr, "getdns_dict_get_list(replies_tree): %s\n",
		getdns_get_errorstr_by_id(ret));
        return 1;
    }

    (void)getdns_list_get_length(replies_tree, &nanswers);
    printf("%d answers\n", (int)nanswers);

    for ( i = 0 ; i < (int)nanswers ; i++ )  {
        snprintf(element, MAXELEM, "/replies_tree/%d/dnssec_status", i);
        (void)getdns_dict_get_int(response, element, &dnssec_status);
	      snprintf(element, MAXELEM, "/replies_tree/%d/answer/0/type", i);
        (void)getdns_dict_get_int(response, element, &type);
        printf("dnssec_status for %s record: %s\n", address_type_to_string(type),
               dnssec_status_to_string(dnssec_status));
      }


    /*
     * handy debugging tool - uncomment if wanted
     */

    /* printf("%s\n", getdns_pretty_print_dict(response)); */

    return 0;

}


char *
dnssec_status_to_string(int status)
{
    switch (status)  {
        case GETDNS_DNSSEC_SECURE:
            return("GETDNS_DNSSEC_SECURE");
            break;
        case GETDNS_DNSSEC_BOGUS:
            return("GETDNS_DNSSEC_BOGUS");
            break;
        case GETDNS_DNSSEC_INDETERMINATE:
            return("GETDNS_DNSSEC_INDETERMINATE");
	           break;
        case GETDNS_DNSSEC_INSECURE:
            return("GETDNS_DNSSEC_INSECURE");
            break;
        case GETDNS_DNSSEC_NOT_PERFORMED:
            return("GETDNS_DNSSEC_NOT_PERFORMED");
            break;
        default:
            return("");
            break;
    }
}

char *
address_type_to_string(int type)
{
    char *buf;

    switch (type)  {
	      case GETDNS_RRTYPE_AAAA:
            return("AAAA");
            break;
        case GETDNS_RRTYPE_A:
            return("A");
            break;
	      default:
            buf = (char *)malloc(MAXELEM);
            snprintf(buf, MAXELEM, "%d", type);
            return buf;
            break;
    }
}


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

static int s_normalize(
	const char *in_file, const char *out_file, long long add_usec );

int main( int argc, char *argv[] )
{
	int i;
	char *in_file;
	char *out_file;
	long long add_usec;

	for ( i = 0; i < argc; i++ )
	{
		printf( "argv-%d: [%s]\n", i, argv[ i ] );
	}

	if ( argc > 1 )
	{
		in_file = argv[ 1 ];
	}
	else
	{
		in_file = "in.pcap";
	}

	if ( argc > 2 )
	{
		out_file = argv[ 2 ];
	}
	else
	{
		out_file = "out.pcap";
	}

	if ( argc > 3 )
	{
		add_usec = strtoll( argv[ 3 ], NULL, 10 );
	}
	else
	{
		add_usec = 1000;	/* 1msec */
	}

	s_normalize( in_file, out_file, add_usec );

	return 0;
}

static int s_normalize(
	const char *in_file, const char *out_file, long long add_usec )
{
	char errbuf[ PCAP_ERRBUF_SIZE ];
	pcap_t *in_pcap;
	pcap_t *out_pcap;
	pcap_dumper_t *out_dump;
	struct pcap_pkthdr hdr;
	const u_char *data;
	struct timeval tv;
	struct timeval tv_add;

	printf( "in[%s] ==> out[%s], between pkt [%lld.%06lld]sec\n",
			in_file, out_file, add_usec / 1000000, add_usec % 1000000 );

	in_pcap = pcap_open_offline( in_file, errbuf );
	if ( in_pcap == NULL )
	{
		printf( "failed to open [%s]: %s\n", in_file, errbuf );
		return 1;
	}

	out_pcap = pcap_open_dead( DLT_EN10MB, 65535 );
	out_dump = pcap_dump_open( out_pcap, out_file );
	if ( out_dump == NULL )
	{
		printf( "failed to open [%s]: %s\n",
				out_file, pcap_geterr( out_pcap ) );
		return 2;
	}

	tv.tv_sec = 946684800;		/* 2000/01/01 00:00:00 UTC */
	tv.tv_usec = 0;
	tv_add.tv_sec = add_usec / ( 1000 * 1000 );
	tv_add.tv_usec = add_usec % ( 1000 * 1000 );

	while ( ( data = pcap_next( in_pcap, &hdr ) ) != NULL )
	{
		hdr.ts = tv;
		pcap_dump( ( u_char * )out_dump, &hdr, data );
		timeradd( &tv, &tv_add, &tv );
	}

	pcap_dump_close( out_dump );
	pcap_close( out_pcap );
	pcap_close( in_pcap );

	return 0;
}

/* EOF */

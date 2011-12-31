%token DIRECT
%token INDIRECT
%token TYPE_NAME
%token CONST
%token IDENTIFIER
%token UNKNOWN
%token FILE_TABLE
%token EXTRACT
%token DL_EXTRACT
%token PSEUDO
%token NO_SYS_CHK
%token HIDDEN_PTR
%token ARRAY
%token IN
%token OUT
%token BOTH
%token ALLOC
%token NULL_ALLOC
%token RETURN
%token NOSUPP
%token IGNORE
%token ELLIPSIS
%token REMOTE_NAME
%token ALSO_IMPLEMENTS
%token SENDER_NAME
%token LOCAL_NAME
%token FILE_TABLE_NAME
%token RDISCARD
%token DISCARD
%token MAP
%token MAP_NAME
%token MAP_NAME_TWO

%type <node> stub_spec param_list param simple_param
%type <node> stub_body action_func_list
%type <node> action_param action_param_list action_func xfer_func alloc_func
%type <node> return_func null_alloc_func
%type <tok> TYPE_NAME CONST IDENTIFIER UNKNOWN FILE_TABLE DL_EXTRACT NO_SYS_CHK ARRAY HIDDEN_PTR opt_mult
%type <bool> opt_const opt_ptr opt_ptr_to_const opt_array
%type <bool> opt_reference
%type <param_mode> use_type

%{
#define _CONDOR_ALLOW_OPEN 1
#define _CONDOR_ALLOW_FOPEN 1
#include "condor_common.h"
#include "scanner.h"
extern int yyline;
extern int yylex( void );
struct node *
mk_func_node( char *type, char *name, struct node * p_list,
	int is_ptr, struct node *action_func_list );
struct node * mk_xfer_func( char *xdr_func, struct node *param_list,
	int in, int out );
struct node * mk_alloc_func( struct node *param_list );
struct node * mk_null_alloc_func( struct node *param_list );
struct node * mk_return_func( struct node *param_list );
struct node * mk_param_node( char *type, char *name,
	int is_const, int is_ptr, int is_ref, int is_const_ptr, int is_array,
	int is_in, int is_out, int is_vararg );
struct node * mk_action_param_node( char *name, int is_ref, char *mult );
struct node *insert_node( struct node *list, struct node *new_elem );
struct node *append_node( struct node *list, struct node *new_elem );
void display_node( struct node * );
void output_switch( struct node * );
void display_list( struct node * );
void output_switch_decl( struct node * );
void output_local_call(  struct node *n, struct node *list );
void output_remote_call(  struct node *n, struct node *list );
void output_extracted_call(  struct node *n, struct node *list );
void output_dl_extracted_call(  struct node *n, char *rtn_type, int is_ptr, struct node *list );
void output_param_list( struct node *list, int rdiscard, int ldiscard );
void output_type_list( struct node *list, int rdiscard, int ldiscard );
void output_remote_extern(struct node *n, struct node *list);

struct node *mk_list();
void copy_file( FILE *in_fp, FILE *out_fp );
FILE * open_file( char *name );
char * mk_upper();
int is_void( struct node *n ); /* return true if type is only "void" */
char * node_type( struct node *n );
char * abbreviate( char *type_name );
void Trace( char *msg );
char * find_type_name( char *param_name, struct node *param_list );
int has_out_params( struct node *action_func_list );
int yyparse(void);

#define MATCH 0 /* for strcmp() */

#ifndef TRUE
#	define TRUE 1
#	define FALSE 0
#endif

#define SWITCHES	1
#define SENDERS		2
#define RECEIVERS	3
#define SEND_STUB	4
#define LISTCALLS	5

int Supported = TRUE;
int Ignored = FALSE;
int	Mode = 0;
int ErrorEncountered = 0;
int IsExtracted = FALSE;
int IsDLExtracted = FALSE;
int IsPseudo = FALSE;
int IsIndirect = FALSE;
int DoSysChk = TRUE;
int HiddenPtr = FALSE;
int IsTabled = FALSE;
int IsVararg = FALSE;
int UseAltRemoteName = FALSE;
int AlsoImplementsCounter = 0;
int UseAltLocalName = FALSE;
int UseAltTableName = FALSE;
int UseAltSenderName = FALSE;

static char AltRemoteName[NAME_LENGTH] = {0};
static char AltAlsoImplements[10 * NAME_LENGTH] = {0};
static char AltLocalName[NAME_LENGTH] = {0};
static char AltTableName[NAME_LENGTH] = {0};
static char AltSenderName[NAME_LENGTH] = {0};

#if 0
input
	: /* empty */
	| input stub_list
	| input non_support_list
	;

#endif


%}

%%

input
	: stub_spec { }
	| non_support_list
	| ignore_list
	| input stub_spec
	| input non_support_list
	| input ignore_list
	| error stub_body
	;

non_support_list
	: nosupp_begin stub_spec
		{
		Trace( "non_support_list( 1 )" );
		Supported = TRUE;
		}
	| nosupp_begin '{' stub_list '}'
		{
		Trace( "non_support_list( 2 )" );
		Supported = TRUE;
		}
	;

nosupp_begin
	: NOSUPP
		{
		Trace( "nosupp_begin" );
		Supported = FALSE;
		}
	;

ignore_list
	: ignore_begin stub_spec
		{
		Trace( "ignore_list( 1 )" );
		Ignored = FALSE;
		}
	| ignore_begin '{' stub_list '}'
		{
		Trace( "ignore_list( 2 )" );
		Ignored = FALSE;
		}
	;

ignore_begin
	: IGNORE
		{
		Trace( "ignore_begin" );
		Ignored = TRUE;
		}
	;

stub_list
	: stub_spec stub_list
	{ }
	| error stub_body
	| /* empty */
	;

stub_spec
	: TYPE_NAME opt_ptr IDENTIFIER '(' param_list ')' specials stub_body
		{
		  $$ = mk_func_node( $1.val, $3.val, $5, $2, $8 );
		  if( !ErrorEncountered ) {
			switch( Mode ) {
			  case SWITCHES:
				output_switch( $$ );
				break;
			  case SENDERS:
				output_sender( $$ );
				break;
			  case RECEIVERS:
				output_receiver( $$ );
				break;
			  case SEND_STUB:
				output_send_stub( $$ );
				break;
			  case LISTCALLS:
				output_listcalls( $$ );
				break;
			}
		  }
		}
	;

stub_body
	: ';'
		{
		Trace( "Empty stub body" );
		$$ = mk_list();
		}
	| '{' action_func_list '}'
		{
		Trace( "Non-Empty stub body" );
		$$ = $2;
		}
	;

action_func_list
	:	/* empty */
		{
		Trace( "Empty action_func_list" );
		$$ = mk_list();
		}
	|	action_func_list action_func
		{
		Trace( "added action_func to action_func_list" );
		$$ = insert_node( $1, $2 );
		}
	;

action_func
	: xfer_func
		{
		$$ = $1;
		}
	| alloc_func
		{
		$$ = $1;
		}
	| null_alloc_func
		{
		$$ = $1;
		}
	| return_func
		{
		$$ = $1;
		}
	;

xfer_func
	: use_type IDENTIFIER '(' action_param_list ')' ';'
		{
		Trace( "action_func" );
		$$ = mk_xfer_func( $2.val, $4, $1.in, $1.out );
		}
	;

alloc_func
	: ALLOC '(' action_param_list ')' ';'
		{
		Trace( "alloc_func" );
		$$ = mk_alloc_func( $3 );
		}
	;

null_alloc_func
	: NULL_ALLOC '(' action_param_list ')' ';'
		{
		Trace( "null_alloc_func" );
		$$ = mk_null_alloc_func( $3 );
		}
	;

return_func
	: RETURN '(' action_param_list ')' ';'
		{
		Trace( "return_func" );
		$$ = mk_return_func( $3 );
		}
	;

action_param_list
	: action_param
		{
		Trace( "action_param_list (1)" );
		$$ = insert_node( mk_list(), $1 );
		}
	| action_param_list ',' action_param
		{
		Trace( "action_param_list (2)" );
		$$ = append_node( $1, $3 );
		}
	;

action_param
	: opt_reference IDENTIFIER opt_mult
		{
		Trace( "action_param" );
		$$ = mk_action_param_node( $2.val, $1, $3.val );
		}
	;

opt_mult
	: '*' IDENTIFIER
		{
		Trace( "opt_mult" );
		$$.val = $2.val;
		}
	| /* null */
		{
		$$.val =  "";
		}
	;

opt_reference
	: '&'
		{ $$ = TRUE; }
	| /* null */
		{ $$ = FALSE; }
	;

specials
	: /* empty */
	| ':' option_list
	;

option_list
	: option
	| option_list ',' option 
	;

option
	:  PSEUDO
		{
		Trace( "option (1)" );
		IsPseudo = TRUE;
		}
	| DIRECT
		{
		Trace( "direct" );
		IsIndirect = FALSE;
		}
	| INDIRECT
		{
		Trace( "indirect" );
		IsIndirect = TRUE;
		DoSysChk = FALSE;
		}
	|  EXTRACT
		{
		Trace( "option (2)" );
		IsExtracted = TRUE;
		DoSysChk = FALSE;
		}
	|  DL_EXTRACT
		{
		Trace( "option (3)" );
		IsDLExtracted = TRUE;
		DoSysChk = FALSE;
		}
	|  NO_SYS_CHK
		{
		Trace( "option (3)" );
		DoSysChk = FALSE;
		}
	|  HIDDEN_PTR
		{
		Trace( "option (3)" );
		HiddenPtr = TRUE;
		}
	| FILE_TABLE
		{
		Trace( "option (4)" );
		IsTabled = TRUE;
		}
	| REMOTE_NAME '(' IDENTIFIER ')'
		{
		Trace( "option (5)" );
		UseAltRemoteName = TRUE;
		strcpy(AltRemoteName,$3.val);
		}
	| ALSO_IMPLEMENTS '(' IDENTIFIER ')'
		{
		Trace( "option (5)" );
		if ( AlsoImplementsCounter == 0 ) {
			strcpy(AltAlsoImplements,$3.val);
		} else {
			strcat(AltAlsoImplements,",");
			strcat(AltAlsoImplements,$3.val);
		}
		AlsoImplementsCounter++;
		}
	| SENDER_NAME '(' IDENTIFIER ')'
		{
		Trace( "option (5)" );
		UseAltSenderName = TRUE;
		strcpy(AltSenderName,$3.val);
		}
	| LOCAL_NAME '(' IDENTIFIER ')'
		{
		Trace( "option (5)" );
		UseAltLocalName = TRUE;
		strcpy(AltLocalName,$3.val);
		}
	| FILE_TABLE_NAME '(' IDENTIFIER ')'
		{
		Trace( "option (5)" );
		UseAltTableName = TRUE;
		IsTabled = TRUE;
		strcpy(AltTableName,$3.val);
		}
	;

param_list
	: param
			{ $$ = insert_node( mk_list(), $1 ); }
	| param ',' param_list
			{ $$ = insert_node( $3, $1 ); }
	| /* empty */
			{ $$ = mk_list(); }
	;

param
	: simple_param
		{ $$ = $1; }
	| DISCARD '(' simple_param ')'
		{ $3->rdiscard = TRUE; $3->ldiscard = TRUE; $$ = $3; }
	| RDISCARD '(' simple_param ')'
		{ $3->rdiscard = TRUE; $$ = $3; }
	| MAP '(' simple_param ')'
		{ $3->is_mapped = TRUE; $$ = $3; }
	| MAP_NAME '(' simple_param ')'
		{ $3->is_map_name = TRUE; $$ = $3; }
	| MAP_NAME_TWO '(' simple_param ')'
		{ $3->is_map_name_two = TRUE; $$ = $3; }
	| ELLIPSIS
		{
		$$ = mk_param_node("long","lastarg",0,0,0,0,0,0,0,1);
		IsVararg = TRUE;
		}
	;

simple_param
	: use_type opt_const TYPE_NAME opt_ptr opt_reference opt_ptr_to_const IDENTIFIER opt_array
			{
			$$ = mk_param_node(
				$3.val,			/* TYPE_NAME */
				$7.val,			/* IDENTIFIER */
				$2,				/* constant */
				$4,				/* pointer */
				$5,				/* reference */
				$6,				/* pointer to const */
				$8,				/* array */
				$1.in,			/* in parameter */
				$1.out,			/* out parameter */
				0			/* is this a vararg? */
			);
			}
	;

use_type
	: IN
		{
		Trace( "use_type (IN)" );
		$$.in = TRUE;
		$$.out = FALSE;
		}
	| OUT
		{
		Trace( "use_type (OUT)" );
		$$.in = FALSE;
		$$.out = TRUE;
		}
	| BOTH
		{
		Trace( "use_type (BOTH)" );
		$$.in = TRUE;
		$$.out = TRUE;
		}
	| /* null */
		{
		Trace( "use_type (NEITHER)" );
		$$.in = FALSE;
		$$.out = FALSE;
		}
	;

opt_const
	: CONST
		{
		$$ = TRUE;
		}
	| /* null */
		{
		$$ = FALSE;
		}
	;

opt_ptr_to_const
	: CONST
		{
		$$ = TRUE;
		}
	| /* null */
		{
		$$ = FALSE;
		}
	;

opt_array
	: ARRAY
		{
		$$ = TRUE;
		}
	| /* null */
		{
		$$ = FALSE;
		}
	;

opt_ptr
	: '*'
		{
		$$ = TRUE;
		}
	| /* null */
		{
		$$ = FALSE;
		}
	;

%%
char	*Prologue;
char	*Epilogue;
char	*ProgName;

void
usage()
{
	fprintf( stderr,
		"%s -m {switches,senders,receivers} [-p prologue] [-e epilogue]\n",
		ProgName
	);
}

int Do_SYS_check = 1;
int gen_local_calls = 1;
int stub_clump_size = 0;
int stub_clump_num = 0;


int
main( int argc, char *argv[] )
{
	char	*arg;
	FILE	*fp;

	ProgName = *argv;
	argc = argc;
	for( argv++; (arg = *argv); argv++ ) {
		if( arg[0] == '-' ) {
			switch( arg[1] ) {
			  case 'm':
				arg = *(++argv);
				if( strcmp("switches",arg) == 0 ) {
					Mode = SWITCHES;
				} else if( strcmp("senders",arg) == 0 ) {
					Mode = SENDERS;
				} else if( strcmp("receivers",arg) == 0 ) {
					Mode = RECEIVERS;
				} else if( strcmp("send_stub",arg) == 0 ) {
					Mode = SEND_STUB;
				} else if( strcmp("listcalls",arg) == 0 ) {
					Mode = LISTCALLS;
				} else {
					usage();
				}
				break;
			  case 'p':
				Prologue = *(++argv);
				break;
			  case 'e':
				Epilogue = *(++argv);
				break;
			  case 's':
				stub_clump_size = atoi( *(++argv) );
				break;
			  case 'n':
				arg = *(++argv);
				if (arg[0] == 's' || arg[0] == 'S') {
					Do_SYS_check = 0;
				} else if (arg[0] == 'l' || arg[0] == 'L') {
					gen_local_calls = 0;
				}
				break;
			  default:
				usage();
			}
		} else {
			usage();
		}
	}

	if( !Mode ) {
		usage();
	}

		/* Copy the prologue */
	if( (fp = open_file(Prologue)) ) {
		copy_file( fp, stdout );
	}

		/* Process the template file */
	yyparse();

		/* Copy the epilogue */
	if( (fp = open_file(Epilogue)) ) {
		copy_file( fp, stdout );
	}

	if( ErrorEncountered ) {
		exit( 1 );
	} else {
		exit( 0 );
	}
	return 0;
}

void yyerror( const char * s )
{
	fprintf( stderr, "%s at \"%s\" on line %d\n", s, yylval.tok.val, yyline );
	ErrorEncountered = TRUE;

		/* make sure any resulting file won't compile */
	printf( "#error Error in stub generator input\n" );
}

struct node *
mk_param_node( char *type, char *name,
	int is_const, int is_ptr, int is_ref, int is_const_ptr, int is_array,
	int is_in, int is_out, int is_vararg )
{
	struct node	*answer;

	answer = (struct node *)calloc( 1, sizeof(struct node) );
	answer->node_type = PARAM;
	answer->type_name = type;
	answer->id = name;

	answer->is_const = is_const;
	answer->is_const_ptr = is_const_ptr;
	answer->is_ptr = is_ptr;
	answer->is_ref = is_ref;
	answer->is_array = is_array;
	answer->is_mapped = 0;
	answer->is_map_name = 0;
	answer->is_map_name_two = 0;
	answer->in_param = is_in;
	answer->out_param = is_out;
	answer->is_vararg = is_vararg;

	answer->next = answer;
	answer->prev = answer;
	answer->ldiscard = FALSE;
	answer->rdiscard = FALSE;

	return answer;
}

struct node *
mk_action_param_node( char *name, int is_ref, char *mult )
{
	struct node	*answer;
	char	*name_holder;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = ACTION_PARAM;
	if( mult[0] ) {
		name_holder = malloc( strlen(name) + strlen(mult) +4 );
		sprintf( name_holder, "%s * %s", name, mult );
		answer->id = name_holder;
	} else {
		answer->id = name;
	}
	answer->is_ref = is_ref;

	return answer;
}

struct node *
mk_func_node( char *type, char *name, struct node * p_list,
	int is_ptr, struct node *action_func_list )
{
	struct node	*answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = FUNC;
	answer->type_name = type;
	answer->id = name;
	answer->is_ptr = is_ptr;
	answer->is_hidden_ptr = HiddenPtr;
	HiddenPtr = FALSE;
	answer->is_ref = 0;
	answer->is_array = 0;
	answer->is_const = 0;
	answer->is_const_ptr = 0;
	answer->extract = IsExtracted;
	IsExtracted = FALSE;
	answer->dl_extract = IsDLExtracted;
	IsDLExtracted = FALSE;
	answer->sys_chk = DoSysChk;
	DoSysChk = TRUE;
	answer->pseudo = IsPseudo;
	IsPseudo = FALSE;
	answer->is_indirect = IsIndirect;
	IsIndirect = FALSE;
	answer->is_tabled = IsTabled;
	IsTabled = FALSE;
	answer->is_vararg = IsVararg;
	IsVararg = FALSE;
	answer->param_list = p_list;
	answer->action_func_list = action_func_list;

	if(AlsoImplementsCounter) {
		AlsoImplementsCounter = 0;
		strcpy(answer->also_implements,AltAlsoImplements);
	} else {
		answer->also_implements[0] = '\0';
	}

	if(UseAltRemoteName) {
		strcpy(answer->remote_name,AltRemoteName);
		UseAltRemoteName=FALSE;
	} else {
		strcpy(answer->remote_name,name);
	}

	if(UseAltLocalName) {
		strcpy(answer->local_name,AltLocalName);
		UseAltLocalName=FALSE;
	} else {
		strcpy(answer->local_name,name);
	}

	if(UseAltTableName) {
		strcpy(answer->table_name,AltTableName);
		UseAltTableName=FALSE;
	} else {
		strcpy(answer->table_name,name);
	}

	if(UseAltSenderName) {
		strcpy(answer->sender_name,AltSenderName);
		UseAltSenderName=FALSE;
	} else {
		strcpy(answer->sender_name,name);
	}

	return answer;
}

struct node *
mk_xfer_func( char *xdr_func, struct node *param_list, int is_in, int is_out )
{
	struct node	*answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = XFER_FUNC;
	answer->XDR_FUNC = xdr_func;
	answer->param_list = param_list;
	answer->in_param = is_in;
	answer->out_param = is_out;

	return answer;
}

struct node *
mk_alloc_func( struct node *param_list )
{
	struct node	*answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = ALLOC_FUNC;
	answer->param_list = param_list;

	return answer;
}

struct node *
mk_null_alloc_func( struct node *param_list )
{
	struct node	*answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = NULL_ALLOC_FUNC;
	answer->param_list = param_list;

	return answer;
}

struct node *
mk_return_func( struct node *param_list )
{
	struct node	*answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->node_type = RETURN_FUNC;
	answer->param_list = param_list;

	return answer;
}

/*
  Insert a new node at the beginning of a list.
*/
struct node *
insert_node( struct node * list, struct node * new_elem )
{

	new_elem->next = list->next;
	new_elem->prev = list;
	list->next->prev = new_elem;
	list->next = new_elem;

	return list;
}

/*
  Append a new node to the end of a list.
*/
struct node *
append_node( struct node * list, struct node * new_elem )
{

	new_elem->next = list;
	new_elem->prev = list->prev;
	list->prev->next = new_elem;
	list->prev = new_elem;

	return list;
}

int
is_empty_list( struct node *list )
{
	return list == list->next;
}

void
output_vararg( struct node *n )
{
	assert( n->node_type == PARAM );
	printf( "\t\t%s = va_arg( ap, %s );\n", n->id, n->type_name );
}

char * node_type( struct node *n )
{
	static char buffer[1024];
	sprintf(buffer,"%s%s %s%s%s%s",
		n->is_const?"const ":"",
		n->type_name,
		n->is_ptr?"* ":" ",
		"",
		/* n->is_ref?"& ":"", */
		n->is_const_ptr?"const ":"",
		n->is_array?"[] ":"");
	return buffer;
}

int is_void(struct node *n )
{
	if (strcmp(n->type_name, "void") == MATCH && n->is_ptr == FALSE &&
		n->is_hidden_ptr == FALSE)
	{
		return TRUE;
	}
	
	return FALSE;
}

/* This returns a string that either casts something to void if the return
	value is actually void, or stores it in a variable called ret_val after
	casting it (the later code that comes after this string) to the
	correct type.
*/
char* consider_return_value_named_with_typecast( struct node *n, int emit_type,
	char *varname )
{
	static char str[1024] = {'\0'};

	if (is_void(n)) {
		if (emit_type == TRUE) {
			return "(void)";
		} else {
			return "";
		}
	}

	if (emit_type == TRUE) {
		sprintf(str, "%s = (%s)", varname, node_type(n));
	} else {
		sprintf(str, "%s = ", varname);
	}

	return str;
}

char* consider_return_value( struct node *n )
{
	return consider_return_value_named_with_typecast( n, TRUE, "ret_val" );
}

char* consider_return_value_no_typecast( struct node *n )
{
	return consider_return_value_named_with_typecast( n, FALSE, "ret_val" );
}


char * node_type_noconst ( struct node *n )
{
	static char buffer[1024];
	sprintf(buffer,"%s %s%s%s",
		n->type_name,
		n->is_ptr?"* ":" ",
		n->is_ref?"& ":"",
		n->is_array?"* ":"");
	return buffer;
}

char * node_type_noconst_noref ( struct node *n )
{
	static char buffer[1024];
	sprintf(buffer,"%s %s%s",
		n->type_name,
		n->is_ptr?"* ":" ",
		n->is_array?"* ":"");
	return buffer;
}

void
output_param_node( struct node *n, int want_id )
{
	assert( n->node_type == PARAM );

	if( n->is_vararg ) {
		printf( "...");
		return;
	}

	if( n->is_const ) {
		printf( "const " );
	}

	printf( "%s ", n->type_name );

	if( n->is_ptr ) {
		printf( "*" );
	}

	if( n->is_ref ) {
		printf( "&" );
	}

	if( n->is_const_ptr ) {
		printf( " const " );
	}

	if ( want_id )
		printf( "%s", n->id );

	if( n->is_array ) {
		printf( "[]" );
	}
}

void
display_node( struct node *n )
{
	switch( n->node_type ) {
		case PARAM:
			printf(node_type(n));
			break;
		case FUNC:
			printf( "FUNC: %s %s ", n->type_name, n->id );
			display_list( n->next );
			break;
	}
}

void
output_switch_generic( struct node *dum, int want_normal )
{
	struct node	*p;
	int num_args = 0;

	if ( want_normal ) {
		printf( "(" );
	} 
	
	for( p=dum->next; p != dum; p = p->next ) {
		if ( !want_normal ) {
			printf( "," );
		}
		printf( " " );
		output_param_node( p , want_normal );
		if ( want_normal ) {
			if( p->next != dum ) {
				printf( "," );
			} else {
				printf( " " );
			}
		}
		num_args++;
	}

	if ( !want_normal ) {
		switch ( num_args ) {
			case 0:
				printf( "|ZERO"); break;
			case 1:
				printf( "|ONE"); break;
			case 2:
				printf( "|TWO"); break;
			case 3:
				printf( "|THREE"); break;
			case 4:
				printf( "|FOUR"); break;
			case 5:
				printf( "|FIVE"); break;
			case 6:
				printf( "|SIX"); break;
			case 7:
				printf( "|SEVEN"); break;
			case 8:
				printf( "|EIGHT"); break;
			case 9:
				printf( "|NINE"); break;
		}; 
	}

	if ( want_normal ) {
		printf( ")" );
	}
}

void
output_switch_decl( struct node *dum )
{
	output_switch_generic( dum, 1 );
	printf("\n");
} 

void
output_switch_listcalls( struct node *dum )
{
	output_switch_generic( dum, 0 );
	printf("\n");
}

void
output_local_call( struct node *n, struct node *list )
{
	struct node	*p;

	/* For some Linux calls, we must make an indirect socket
	   call and pass the real args as an array pointer.
	   Otherwise, make a regular system call. */

	if(n->is_indirect) {
		printf("\t\t\tunsigned long args[] = { ");
		for( p=list->next; p != list; p = p->next ) {
			if( p!=list->next ) printf(" , ");
			printf( "(unsigned long)%s", p->id );
		}
		printf(" };\n");

		printf("\t\t\%s syscall( SYS_socketcall, SYS_%s, args );\n",
			consider_return_value(n),
			mk_upper(n->local_name) );

	} else {

		printf("\t\t\t%s syscall( SYS_%s",
			consider_return_value(n),
			n->local_name );

		if( !is_empty_list(list) ) {
			printf( ", " );
		}
		output_param_list( list, 0, 1 );
		printf( " );\n" );
	}
}

void
output_remote_extern(struct node *n, struct node *list)
{
	/* spew some pseudo-ansi C-like stuff out to define function before use */
	printf("extern \"C\" %s REMOTE_CONDOR_%s( ", node_type(n), n->sender_name);
	output_type_list( list, 1, 0);
	printf(");\n");
}

void
output_remote_call( struct node *n, struct node *list )
{
	/* the actual call */
	printf("\t\t\t%s REMOTE_CONDOR_%s( ",
		consider_return_value_no_typecast(n),
		n->sender_name );
	output_param_list( list, 1, 0 );
	printf( " );\n" );
}

void
output_tabled_call( struct node *n, struct node *list )
{
	printf( "\t\t_condor_file_table_init();\n");

	printf("\t\t/* The FileTab prototypes must match the type of the ret_val! */\n");

	printf( "\t\t%s FileTab -> %s ( ",
		consider_return_value_named_with_typecast(n, FALSE, "ret_val"),
		n->table_name );

	output_param_list( list, 1, 0 );
	printf( " );\n");
}

void
output_extracted_call( struct node *n, struct node *list )
{
	printf("\t\t\t%s %s(", 
		consider_return_value(n),
		mk_upper(n->id) );

	if( !is_empty_list(list) ) {
		printf( " " );
	}
	output_param_list( list, 0, 1 );
	printf( " );\n" );
}

void
output_dl_extracted_call( struct node *n, char *rtn_type, int is_ptr, 
						  struct node *list )
{
	struct node	*p;

	/* warning removal */
	rtn_type = rtn_type ; is_ptr = is_ptr;

	printf( "\t\tvoid *handle;\n");
	printf( "\t\t%s (*fptr)(", node_type(n));
	for( p=list->next; p != list; p = p->next ) {
		printf(node_type(p));
		if( p->next != list ) {
			printf( ", " );
		}
	}
	printf( ");\n" );

	printf( "\t\tif ((handle = dlopen(\"/usr/lib/libc.so\", RTLD_LAZY)) == NULL) {\n");
	printf( "\t\t\tret_val = -1;\n");
	printf( "\t\t}");
	printf( "\t\tif ((fptr = (%s (*)(", node_type(n));
	for( p=list->next; p != list; p = p->next ) {
		printf(node_type(p));
		if( p->next != list ) {
			printf( ", " );
		}
	}
	printf( "))dlsym(handle, \"%s\")) == NULL) {\n", n->id );
	printf( "\t\t\tret_val = -1;\n");
	printf( "\t\t}\n\n" );
	printf( "\t\tret_val = (%s) (*fptr)(",node_type(n));
	output_param_list( list, 0, 1 );

	printf( ");\n" );
}

/* Display a param list.
   Discard parameters when rdiscard or ldiscard match up. */

void
output_param_list( struct node *list, int rdiscard, int ldiscard )
{
	struct node	*p;

	for( p=list->next; p != list; p = p->next ) {
		if(p->ldiscard && ldiscard ) continue;
		if(p->rdiscard && rdiscard ) continue;
		if( p!=list->next ) printf(" , ");
		printf( "%s", p->id );
	}
}

void
output_type_list( struct node *list, int rdiscard, int ldiscard )
{
	struct node	*p;

	for( p=list->next; p != list; p = p->next ) {
		if(p->ldiscard && ldiscard ) continue;
		if(p->rdiscard && rdiscard ) continue;
		if( p!=list->next ) printf(" , ");
		printf( "%s", node_type(p) );
	}
}

void
display_list( struct node *dum )
{
	struct node	*p;

	printf( "(" );
	for( p=dum->next; p != dum; p = p->next ) {
		printf( " " );
		display_node( p );
		if( p->next != dum ) {
			printf( "," );
		} else {
			printf( " " );
		}
	}
	printf( ")\n" );
}

struct node *
mk_list()
{
	struct node *answer;

	answer = (struct node *)malloc( sizeof(struct node) );
	answer->next = answer;
	answer->prev = answer;
	answer->node_type = DUMMY;
	answer->type_name = "(dummy)";
	answer->id = "(dummy)";
	return answer;
}

/*

  Look through the list of parameters and see if any are fd's which need
  to be mapped.  If so output the appropriate declaration and mapping
  code.
*/
void
output_mapping( char *func_type_name, int is_ptr,  struct node *list )
{
	struct node	*n;
	int	found_mapping = 0;

	for( n = list->next; n != list; n = n->next ) {
		if( n->is_mapped ) {
			printf( "	%s	user_%s;\n", n->type_name, n->id );
			found_mapping = 1;
		}
	}

	if( found_mapping ) {
		printf( "\tint use_local_access = FALSE;\n" );
		printf( "\n" );
	}

	printf( "	sigset_t condor_omask = _condor_signals_disable();\n");

	for( n = list->next; n != list; n = n->next ) {
		if( n->is_mapped ) {
			printf( "	if( (user_%s=MapFd(%s)) < 0 ) {\n", n->id, n->id );
			printf( "		return (%s%s)-1;\n",
				func_type_name,
				is_ptr ? " *" : ""
			);
			printf( "	}\n" );
			printf( "\tif( LocalAccess(%s) ) {\n", n->id );
			printf( "\t\tuse_local_access = TRUE;\n" );
			printf( "\t}\n" );
		}
	}

	printf( "\n" );
	if( found_mapping ) {
		printf( "	if( LocalSysCalls() || use_local_access ) {\n" );
	} else {
		printf( "	if( LocalSysCalls() ) {\n" );
	}
}

/*
	Return an expression that is true for failure of a returned value from
	a syscall. In the UNIX API, an ret_val < 0 of int-like return values usually
	means failure. For functions that return pointers, ret_val == NULL usually
	means failure.
*/
char* syscall_validity_check_named( struct node *n, char *varname )
{
	static char str[1024] = {'\0'};

	if ( n->is_ptr || n->is_hidden_ptr ) {
		sprintf(str, " %s == NULL ", varname);
	} else {
		sprintf(str, " %s < 0 ", varname);
	}

	return str;
}

char* syscall_validity_check( struct node *n )
{
	return syscall_validity_check_named(n, "ret_val");
}

/*
  Output code for one system call receiver.
*/
void
output_receiver( struct node *n )
{
	struct node *param_list = n->param_list;
	struct node *p, *q;
	struct node *var, *size;
	char   *rval;
	static int clump_number = 0;
	char   *pchar = NULL;
	char   *pchar1 = NULL;

	assert( n->node_type == FUNC );

	/* If this node is a function which maps to a different
	   call, skip the receiver, because it will be generated
	   by the function bearing that name. */
	
	if( strcmp(n->id,n->remote_name) ) return;
	if( strcmp(n->id,n->sender_name) ) return;

	if( Ignored ) return;

	if( !n->pseudo && Do_SYS_check && n->sys_chk ) {
		printf( "#if defined( SYS_%s )\n", n->local_name );
	}

	printf( "	case CONDOR_%s:\n", n->remote_name );
	if ( n->also_implements[0] ) {
		pchar = n->also_implements;
		while (pchar) {
			pchar1 = strchr(pchar,',');
			if ( pchar1 ) {
				*pchar1 = '\0';
				pchar1++;
			}
			printf( "	case CONDOR_%s:\n", pchar );
			pchar = pchar1;
		}
	}
			
	printf( "	  {\n" );

		/* output a local variable to hold the return value o the syscall */
	if (!is_void(n)) {
		printf("\t\t%s ret_val;\n", node_type(n));
	}

		/* output a local variable decl for each param of the sys call */
	for( p=param_list->next; p != param_list; p = p->next ) {
		if(!p->rdiscard) printf("\t\t%s %s;\n",node_type_noconst_noref(p),p->id);
	}

	printf( "\t\tcondor_errno_t terrno;\n" );
	printf( "\n" );


		/*
		Receive all call by value parameters - these must be IN parameters
		to the syscall, since they cannot return a value to the
		calling routine.
		*/
	for( p=param_list->next; p != param_list; p = p->next ) {
		if( p->is_ptr || p->is_array || p->rdiscard ) {
			continue;
		}
		printf( "\t\tassert( syscall_sock->code(%s) );\n",
			p->id 
		);
		if ((strcmp(p->type_name, "int") == MATCH) ||
			(strcmp(p->type_name, "open_flags_t") == MATCH)) {
			printf( "\t\tdprintf( D_SYSCALLS, \"\t%s = %%d\\n\", %s );\n",
				   p->id, p->id);
		} else if (	(strcmp(p->type_name, "off_t") == MATCH) ||
					(strcmp(p->type_name, "size_t") == MATCH) ) {
			/* unsigned quantities get typecast into an unsigned long
				for outputting, this is mostly correct */
			printf( "\t\tdprintf( D_SYSCALLS, \"\t%s = %%lu\\n\", %s );\n",
				   p->id, p->id);
		}
	}

		/*
		Null out pointer type parameters.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != NULL_ALLOC_FUNC ) {
			continue;
		}
		var = p->param_list->next;
		printf( "\t\t%s = NULL;\n",
			var->id
		);
	}

		/*
		Allocate space for pointer type parameters.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != ALLOC_FUNC ) {
			continue;
		}
		var = p->param_list->next;
		size = var->next;
		printf( "\t\t%s = (%s)malloc( (unsigned)%s );\n",
			var->id,
			find_type_name( var->id, param_list ),
			size->id
		);
		printf( "\t\tmemset( %s, 0, (unsigned)%s );\n",
			var->id,
			size->id
		);
	}

		/*
		Receive other IN parameters - these are the ones with an
		IN action function defined in the template file.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != XFER_FUNC || p->in_param == FALSE ) {
			continue;
		}
		printf( "\t\tassert( syscall_sock->%s(", p->SOCK_FUNC );
		for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
			assert( q->node_type == ACTION_PARAM );
			printf( "%s%s", 
				q->id,
				q->next->node_type == DUMMY ? "" : ", "
			);
		}
		printf( ") );\n" );
		if (strcmp(p->XDR_FUNC, "xdr_string") == MATCH) {
			q=p->param_list->next;
			printf( "\t\tdprintf( D_SYSCALLS, \"\t%s = %%s\\n\", %s );\n",
				   q->id, q->id
			);
		}
	}
	printf( "\t\tassert( syscall_sock->end_of_message() );;\n" );

		/* Invoke the system call */
	printf( "\n" );
	printf( "\t\terrno = (condor_errno_t)0;\n" );
	if( !Supported  ) {
		printf( "\t\t%s CONDOR_NotSupported( CONDOR_%s );\n",
			consider_return_value_named_with_typecast(n, TRUE, "ret_val"),
			n->remote_name  );

	} else if( Ignored ) {
		printf( "\t\t%s CONDOR_Ignored( CONDOR_%s );\n",
			consider_return_value_named_with_typecast(n, TRUE, "ret_val"),
			n->remote_name  );
	} else {

		printf( "\t\t%s%s%s( ",
			/* XXX Hrm, changing the TRUE to FALSE would be more correct
				since the return type of the system call should match the
				type of the variable holding the return value, but
				it would require moderate changes to the pseduo_* functions
				to make the return values type correct. For now, I'm
				leaving the type cast here until I get a chance to
				fix it in the future.
					-psilord 8/9/11
			*/
			consider_return_value_named_with_typecast(n, TRUE, "ret_val"),
			n->pseudo ? "pseudo_" : "",
			n->id
		);
		output_param_list(param_list, 1, 0);
		printf( ");\n" );
	}
	printf( "\t\tterrno = (condor_errno_t)errno;\n" );

	if (is_void(n)) {
		printf( "\t\tdprintf( D_SYSCALLS, \"\\tret_val = (void), errno = N/A\\n\" );\n" );
	} else {
		if ((strcmp(node_type(n), "off_t  ") == 0) ||
			(strcmp(node_type(n), "ssize_t  ") == 0)) {
			printf( "\t\tdprintf( D_SYSCALLS, \"\\tret_val = %%ld, errno = %%d\\n\", ret_val, (int)terrno );\n" );
		} else if ((strcmp(node_type(n), "void* ") == 0) ||
				   (strcmp(node_type(n), "void * ") == 0) ||
				   (strcmp(node_type(n), "caddr_t  ") == 0)) {
			printf( "\t\tdprintf( D_SYSCALLS, \"\\tret_val = %%p, errno = %%d\\n\", ret_val, (int)terrno );\n" );
		} else {
			printf( "\t\tdprintf( D_SYSCALLS, \"\\tret_val = %%d, errno = %%d\\n\", ret_val, (int)terrno );\n" );
		}
	}

	printf( "\n" );


	if (!is_void(n) || has_out_params(n->action_func_list)) {
		/* Only if we got something from the system call, either a return value
			or OUT parameters, do we even try to shove anything back to the
			sender which ultimately invoked this receiver. */
		printf( "\t\tsyscall_sock->encode();\n" );
	}

		/* Send system call return value, and errno if needed */
	if (!is_void(n)) {
		printf( "\t\tassert( syscall_sock->code(ret_val) );\n" );

		/* Only if the return value is signed do we check to see if it is < 0 */
		if ((strcmp(node_type(n), "uid_t  ") != 0) &&
			(strcmp(node_type(n), "gid_t  ") != 0) && 
			(strcmp(node_type(n), "mode_t  ")!= 0)) {
			printf( "\t\tif( %s ) {\n",
			syscall_validity_check_named(n, "ret_val") );
			printf( "\t\t\tassert( syscall_sock->code(terrno) );\n" );
			printf( "\t\t}\n" );
		}
	}

		/*
		Send out results in any OUT parameters - these are the ones with an
		OUT action function defined in the template file.
		*/
	if( has_out_params(n->action_func_list) ) {
		printf( "\t\tif( !(%s) ) {\n", 
			syscall_validity_check_named(n, "ret_val") );

		for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
			if( p->node_type != XFER_FUNC || p->out_param == FALSE ) {
				continue;
			}
			printf( "\t\t\tassert( syscall_sock->%s(", p->SOCK_FUNC );
			for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
				assert( q->node_type == ACTION_PARAM );
				printf( "%s%s", 
					q->id,
					q->next->node_type == DUMMY ? "" : ", "
				);
			}
			printf( ") );\n" );
		}
		printf( "\t\t}\n" );
	}

		/*
		DeAllocate space for pointer type parameters.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != ALLOC_FUNC && p->node_type != NULL_ALLOC_FUNC ) {
			continue;
		}
		var = p->param_list->next;
		printf( "\t\tfree( (char *)%s );\n", var->id );
	}

	if (!is_void(n) || has_out_params(n->action_func_list)) {
		/* This end_of_message is paired with the block above */
		printf( "\t\tassert( syscall_sock->end_of_message() );;\n" );
	}

		/*
		Check for special return value
		*/
	rval = "0";
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != RETURN_FUNC ) {
			continue;
		}
		var = p->param_list->next;
		rval = var->id;
	}
	printf( "\t\treturn %s;\n", rval );


	printf( "\t}\n" );

	if( n->pseudo || !Do_SYS_check || !n->sys_chk) {
		printf( "\n" );
	} else {
		printf( "#endif\n\n" );
	}

	stub_clump_num++;
	if ( stub_clump_size > 0 && stub_clump_num >= stub_clump_size ) {
		stub_clump_num = 0;
		clump_number++;
		printf( "\n" );
		printf( "\tdefault:\n");
		printf( "\t\tdo_REMOTE_syscall%d(condor_sysnum);\n",
			clump_number );
		printf( "\t}\n" );
		printf( "}\n\n" );
		printf( "int\n" );
		printf( "do_REMOTE_syscall%d(int condor_sysnum)\n",clump_number);
		printf( "{\n" );
		printf( "\tint ret_val;\n\n" );
		printf( "\tswitch(condor_sysnum) {\n\n" );
	}
}

/* output a distinct function instead of a switch statement */
void
output_sender( struct node *n )
{
	struct node *param_list = n->param_list;
	struct node *p, *q;

	assert( n->node_type == FUNC );

	/* If this node is a function which maps to a different
	   call, skip the sender, because it will be generated
	   by the function bearing that name. */
	
	if( strcmp(n->id,n->sender_name) ) return;

	if( Ignored ) return;

	/* Notice that we check for the existence of the local system
	   call for this stub, which may not be the same as the 
	   sender name.  This sender will get used only when the local
	   name is defined.  (See the switch for details) */

	if( !n->pseudo && Do_SYS_check && n->sys_chk ) {
		printf( "#if defined( SYS_%s )\n", n->local_name );
	}

	/* spit out the shiny sender function */
	printf("%s\nREMOTE_CONDOR_%s(", node_type(n), n->sender_name);
	for( p=param_list->next; p != param_list; p = p->next ) {
		/* only discard remote args since a sender can ONLY do a remote call. */
		if(p->rdiscard ) continue;
		if( p!=param_list->next ) printf(" , ");
		printf("%s %s",node_type_noconst(p),p->id);
	}
	printf(")\n");
	printf( "{\n" );

	/* argument declarations */
	printf( "\tint	scm;\n");

	if (!is_void(n)) {
		/* void functions don't need this */
		printf( "\t%s   ret_val;\n", node_type(n));
		printf( "\tcondor_errno_t   terrno;\n");
	}

	printf( "\tsigset_t	omask;\n");
	printf( "\n");

	printf( "\tscm = SetSyscalls( SYS_LOCAL | SYS_UNMAPPED );\n");

	printf( "\tomask = _condor_signals_disable();\n");

		/* Set up system call number */
	printf( "\tCurrentSysCall = CONDOR_%s;\n\n", n->remote_name  );

		/* Send system call number */
	printf( "\tsyscall_sock->encode();\n" );
	printf( "\tassert( syscall_sock->code(CurrentSysCall) );\n" );

		/*
		Send all call by value parameters - these must be IN parameters
		to the syscall, since they cannot return a value to the
		calling routine.
		*/
	for( p=param_list->next; p != param_list; p = p->next ) {
		if( p->is_ptr || p->is_array || p->rdiscard ) {
			continue;
		}
		printf( "\tassert( syscall_sock->code(%s) );\n",
			p->id 
		);
	}

		/*
		Send other IN parameters - these are the ones with an
		IN action function defined in the template file.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != XFER_FUNC || p->in_param == FALSE ) {
			continue;
		}
		printf( "\tassert( syscall_sock->%s(", p->SOCK_FUNC );
		for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
			assert( q->node_type == ACTION_PARAM );
			printf( "%s%s", 
				q->id,
				q->next->node_type == DUMMY ? "" : ", "
			);
		}
		printf( ") );\n" );
	}

	
		/* Complete the XDR record, and flush */
	printf( "\tassert( syscall_sock->end_of_message() );\n\n" );

	if (!is_void(n) || has_out_params(n->action_func_list)) {
		/* Only if the receiver actually produced a return value or OUT
			parameters do we even expect anything back. */
    	printf( "\tsyscall_sock->decode();\n" );
	}

	if (!is_void(n)) {
		/* only read the ret_val from the other side if the function isn't 
			void */
		printf( "\tassert( syscall_sock->code(ret_val) );\n" );

		/* If the return type is an unsigned type, don't < 0 it */
		if ((strcmp(node_type(n), "uid_t  ") != 0) &&
			(strcmp(node_type(n), "gid_t  ") != 0) &&
			(strcmp(node_type(n), "mode_t  ") != 0)) {
		printf( "\tif( %s ) {\n", syscall_validity_check(n) );
		printf( "\t\tassert( syscall_sock->code(terrno) );\n" );
		printf( "\t\tassert( syscall_sock->end_of_message() );\n" );
		printf( "\t\t_condor_signals_enable( omask );\n");
		printf( "\t\tSetSyscalls( scm );\n");
		printf( "\t\terrno = (int)terrno;\n" );
		printf( "\t\treturn ret_val;\n" );
		printf( "\t}\n" );
		}
	}

		/*
		Gather up results in any OUT parameters - these are the ones with an
		OUT action function defined in the template file.
		*/
	if( has_out_params(n->action_func_list) ) {
		for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
			if( p->node_type != XFER_FUNC || p->out_param == FALSE ) {
				continue;
			}
			printf( "\tassert( syscall_sock->%s(", p->SOCK_FUNC );
			for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
				assert( q->node_type == ACTION_PARAM );
				printf( "%s%s", 
					q->id,
					q->next->node_type == DUMMY ? "" : ", "
				);
			}
			printf( ") );\n" );
		}
	}

	if (!is_void(n) || has_out_params(n->action_func_list)) {
		/* Paired with the above decode() call */
		printf( "\tassert( syscall_sock->end_of_message() );\n" );
	}

	printf( "\t_condor_signals_enable( omask );\n");
	printf( "\tSetSyscalls( scm );\n");

	if (!is_void(n)) {
		printf( "\treturn ret_val;\n" );
	}

	/* end of function */
	printf( "}\n\n" );

	/* Header which checks for SYS_name */
	if( !n->pseudo && Do_SYS_check && n->sys_chk ) {
		printf( "#endif\n\n");
	}

	return;
}

/*
  Output code for one system call switch.
*/
void
output_switch( struct node *n )
{
	struct node *p;
	int did_map_name = 0;

	assert( n->node_type == FUNC );

	/* Undefine any ugly redirections of this function */
	printf("#undef %s\n",n->id);

	/* Make sure that we use the name corresponding to the local
	   system call, not the function name. */

	if( !n->pseudo && Do_SYS_check && n->sys_chk ) {
		printf( "#if defined( SYS_%s )\n", n->local_name );
	}

	/* extern the REMOTE_ sender varient we will be calling */
	if (!Ignored) {
		output_remote_extern(  n, n->param_list );
	}

	/* If we extracted a function, prototype it here. */
	if( n->extract ) {
		printf("extern %s %s ",node_type(n),mk_upper(n->id));
		output_switch_generic(n->param_list,1);
		printf(";\n\n");
	}

	/* Give the switch header */
	printf( "%s %s ", node_type(n), n->id );
	output_switch_decl( n->param_list );

	/* start of switch function */
	printf("{\n");

	/* The return value of the system/remote call, if any. */
	if (!is_void(n)) {
		printf("\t%s ret_val;\n", node_type(n));
	}

	printf("\tint do_local=0;\n\n");

	printf( "\terrno = 0;\n\n" );

	/* Notice this: The vararg generator only does enough to
	   generate a third arg of size long.  Unfortunately, we're assuming
	   that the size of a long can always contain a pointer. */

	if( n->is_vararg ) {
		printf("\tlong lastarg;\n");
		printf("\tva_list args;\n");
		printf("\tva_start(args,%s);\n",n->param_list->next->next->id);
		printf("\tlastarg = va_arg(args,long);\n");
		printf("\tva_end(args);\n");
		printf("\n");
	}

	/* Disable checkpointing */
	printf( "\tsigset_t condor_omask = _condor_signals_disable();\n\n");

	/* Look up mapped parameters, and map them. */
	for( p=n->param_list->next; p!=n->param_list; p=p->next ) {
		if( p->is_mapped ) {
			printf("\tif( MappingFileDescriptors() ) {\n");
			printf("\t\tdo_local = _condor_is_fd_local( %s );\n",p->id);
			printf("\t\t%s = _condor_get_unmapped_fd( %s );\n",p->id,p->id);
			printf("\t}\n\n");
		}
		if( p->is_map_name ) {
			printf("\tchar *newname = NULL;\n");
			printf("\tdo_local = _condor_is_file_name_local( %s, &newname );\n",p->id);
			printf("\t%s = newname;\n\n",p->id);
			did_map_name = 1;
		}
		if( p->is_map_name_two ) {
			printf("\tchar *newname2 = NULL;\n");
			printf("\tint do_local_two = _condor_is_file_name_local( %s, &newname2 );\n",p->id);
			printf("\t%s = newname2;\n\n",p->id);
			printf("\tif( do_local!=do_local_two ) {\n");
			printf("\t\terrno = EXDEV;\n");
			printf("\t\t_condor_signals_enable( condor_omask );\n");
			printf("\t\tfree( newname);\n");
			printf("\t\tfree( newname2);\n");
			printf("\t\treturn -1;\n");
			printf("\t}\n");
		}
	}

	if (gen_local_calls ) {

		if( n->is_tabled ) {
			printf("\tif( MappingFileDescriptors() ) {\n");
			output_tabled_call( n, n->param_list );
			printf("\t} else {\n");
		}

		printf("\t\tif( LocalSysCalls() || do_local ) {\n");

		if( n->extract ) {
			output_extracted_call( n, n->param_list );
		} else if ( n->dl_extract ) {
			output_dl_extracted_call( n, n->type_name, n->is_ptr, n->param_list );
		} else {
			output_local_call( n, n->param_list );
		}
		if(did_map_name) {
			printf("\t\t\tif( %s && !LocalSysCalls() && do_local ) {\n",
				syscall_validity_check(n));
			printf("\t");
			output_remote_call( n, n->param_list );
			printf("\t\t\t}\n");
		}
		printf( "\t\t} else {\n" );
	}

	if( Ignored ) {
		printf("\t\t\tret_val = 0;\n");
	} else {
		output_remote_call(  n, n->param_list );
	}

	if (gen_local_calls) {
		printf( "\t\t}\n\n" );

		if( n->is_tabled ) {
			printf("\t}\n");
		}
	}

	/* free mapped filename. */
	for( p=n->param_list->next; p!=n->param_list; p=p->next ) {
		if( p->is_map_name ) {
			printf("\tfree( newname );\n");
		}
		if( p->is_map_name_two ) {
			printf("\tfree( newname2 );\n");
		}
	}

	printf( "\t_condor_signals_enable( condor_omask );\n");

	if (!is_void(n)) {
		printf("\n\treturn ret_val;\n");
	}

	printf( "}\n\n" );

	if( n->pseudo || !Do_SYS_check || !n->sys_chk ) {
		printf( "\n" );
	} else {
		printf( "#endif\n\n" );
	}
}

/*
 * Output an entry to be consumed by the analyze_syscalls shell script
 */

void
output_listcalls( struct node *n )
{
	assert( n->node_type == FUNC );

	/* don't spit out anything for pseudo syscalls */
	if ( n->pseudo )
		return;

	/* output func name */
	printf( "%s|",n->id );

	/* output type: I = ignored, U = unsupported, S = supported */
	if( !Supported  ) {
		printf( "U|"  );
	} else if( Ignored ) {
		printf( "I|"  );
	} else {
		printf( "S|" );
	}

	/* output return type followed by  prototype args */
	if( n->is_ptr ) {
		printf( "%s * ", n->type_name );
	} else {
		printf( "%s ", n->type_name );
	}
	output_switch_listcalls( n->param_list );
	printf( "\n" );
}

/*
   Output a stub for the call which also marshalls and sends parameters 
*/

void
output_send_stub( struct node *n )
{
	struct node *param_list = n->param_list;
	struct node *p, *q;

	assert( n->node_type == FUNC );
	if( n->is_ptr ) {
		printf( "\n%s *\n", n->type_name );
	} else {
		printf( "\n%s\n", n->type_name );
	}
	printf( "%s", n->id );
	output_switch_decl( n->param_list );
	printf( "{\n" );
	printf( "	int	ret_val;\n\n" );

		/* Set up system call number */
	printf( "\t\tCurrentSysCall = CONDOR_%s;\n\n", n->remote_name  );
	printf( "\t\tsyscall_sock->encode();\n" );
	printf( "\t\tassert( syscall_sock->code(CurrentSysCall) );\n");
		/*
		Send all call by value parameters - these must be IN parameters
		to the syscall, since they cannot return a value to the
		calling routine.
		*/
	for( p=param_list->next; p != param_list; p = p->next ) {
		if( p->is_ptr || p->is_array ) {
			continue;
		}
		printf( "\t\tassert( syscall_sock->code(%s) );\n",
			p->id 
		);
	}

		/*
		Send other IN parameters - these are the ones with an
		IN action function defined in the template file.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != XFER_FUNC || p->in_param == FALSE ) {
			continue;
		}
		printf( "\t\tassert( syscall_sock->%s(", p->SOCK_FUNC );
		for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
			assert( q->node_type == ACTION_PARAM );
			printf( "%s%s", 
				q->id,
				q->next->node_type == DUMMY ? "" : ", "
			);
		}
		printf( ") );\n" );
	}

		/* Complete the XDR record, and flush */
	printf( "\t\tassert( syscall_sock->end_of_message() );\n\n" );

	printf( "\t\tsyscall_sock->decode();\n" );
	/* XXX bug? Shouldn't this only do it is the function is non void? */

	printf( "\t\t/* XXX possible bug! Also this code isn't generated! */\n" );
	printf( "\t\tassert( syscall_sock->code(ret_val) );\n" );
	printf( "\t\tif( %s ) {\n", syscall_validity_check(n) );
	printf( "\t\t\tassert( syscall_sock->code(terrno) );\n" );
	printf( "\t\t\tassert( syscall_sock->end_of_message() );\n" );
	printf( "\t\t\terrno = (int)terrno;\n" );
	printf( "\t\t\treturn ret_val;\n" );
	printf( "\t\t}\n" );

		/*
		Gather up results in any OUT parameters - these are the ones with an
		OUT action function defined in the template file.
		*/
	for( p=n->action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type != XFER_FUNC || p->out_param == FALSE ) {
			continue;
		}
		printf( "\t\tassert( syscall_sock->%s(", p->SOCK_FUNC );
		for( q=p->param_list->next; q->node_type != DUMMY; q = q->next ) {
			assert( q->node_type == ACTION_PARAM );
			printf( "%s%s", 
				q->id,
				q->next->node_type == DUMMY ? "" : ", "
			);
		}
		printf( ") );\n" );
	}

	printf( "\t\tassert( syscall_sock->end_of_message() );\n" );

	/* XXX make this into a function and use it! */
	if( strcmp(n->type_name,"void") != 0 ) {
		printf( "\n" );
		if( strcmp(n->type_name,"int") == 0 ) {
			printf( "	return ret_val;\n" );
		} else if(n->is_ptr) {
			printf( "	return (%s *)ret_val;\n", n->type_name );
		} else {
			printf( "	return (%s)ret_val;\n", n->type_name );
		}
	}
	printf( "}\n\n" );

}

FILE *
open_file( char *name )
{
	FILE	*fp;

	if( name ) {
		if( (fp = fopen(name,"r")) == NULL) {
			perror( name );
			exit( 1 );
		}
		return fp;
	}
	return NULL;
}

void
copy_file( FILE *in_fp, FILE *out_fp )
{
	char	buf[1024];


	while( fgets(buf,sizeof(buf),in_fp) ) {
		fputs(buf,out_fp);
	}
}

char *
mk_upper( char *str )
{
	char	*src, *dst;
	static char buf[1024];

	src = str;
	dst = buf;
	while( *src ) {
		if( islower(*src) ) {
			*dst++ = toupper(*src++);
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
	return buf;
}

char *
abbreviate( char *type_name )
{
	if( strncmp("struct",type_name,6) == MATCH ) {
		return type_name + 7;
	} else if( strcmp("long int",type_name) == MATCH ) {
		return "long";
	} else if( strcmp("unsigned int",type_name) == MATCH ) {
		return "u_int";
	} else if( strcmp("unsigned long",type_name) == MATCH ) {
		return "u_long";
	} else {
		return type_name;
	}
}

void
Trace( char *msg)
{
#define TRACE 0
#if TRACE == 0		/* keep quiet */
	msg = msg;
	return;
#elif TRACE == 1	/* trace info to the terminal */
	fprintf( stderr, "Production: \"%s\"\n", msg );
#elif TRACE == 2	/* intermix trace info with generated code */
	printf( "Production: \"%s\"\n", msg );
#endif
}

char *
find_type_name( char *param_name, struct node *param_list )
{
	struct node	*p;
	static char answer[1024];

	for( p=param_list->next; p->node_type != DUMMY; p = p->next ) {
		if( strcmp(param_name,p->id) == MATCH ) {
			if( p->is_ptr || p->is_array ) {
				sprintf( answer, "%s *", p->type_name );
			} else {
				sprintf( answer, "%s", p->type_name );
			}
			return answer;
		}
	}
	assert( FALSE );
	return NULL; /* never happens, but removes warning */
}


int
has_out_params( struct node *action_func_list )
{
	struct node	*p;

	for( p=action_func_list->next; p->node_type != DUMMY; p = p->next ) {
		if( p->node_type == XFER_FUNC && p->out_param == TRUE ) {
			return TRUE;
		}
	}
	return FALSE;
}

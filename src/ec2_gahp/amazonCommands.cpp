/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "condor_common.h"
#include "condor_debug.h"
#include "condor_config.h"
#include "condor_string.h"
#include "string_list.h"
#include "condor_arglist.h"
#include "MyString.h"
#include "util_lib_proto.h"
#include "internet.h"
#include "my_popen.h"
#include "basename.h"
#include "vm_univ_utils.h"
#include "amazongahp_common.h"
#include "amazonCommands.h"

#include "condor_base64.h"
#include <sstream>
#include "stat_wrapper.h"
#include "Regex.h"
#include <algorithm>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include "thread_control.h"
#include <expat.h>

#define NULLSTRING "NULL"

//
// This function should not be called for anything in query_parameters,
// except for by AmazonQuery::SendRequest().
//
std::string amazonURLEncode( const std::string & input )
{
    /*
     * See http://docs.amazonwebservices.com/AWSEC2/2010-11-15/DeveloperGuide/using-query-api.html
     *
     *
     * Since the GAHP protocol is defined to be ASCII, we're going to ignore
     * UTF-8, and hope it goes away.
     *
     */
    std::string output;
    for( unsigned i = 0; i < input.length(); ++i ) {
        // "Do not URL encode ... A-Z, a-z, 0-9, hyphen ( - ),
        // underscore ( _ ), period ( . ), and tilde ( ~ ).  Percent
        // encode all other characters with %XY, where X and Y are hex
        // characters 0-9 and uppercase A-F.  Percent encode extended
        // UTF-8 characters in the form %XY%ZA..."
        if( ('A' <= input[i] && input[i] <= 'Z')
         || ('a' <= input[i] && input[i] <= 'z')
         || ('0' <= input[i] && input[i] <= '9')
         || input[i] == '-'
         || input[i] == '_'
         || input[i] == '.'
         || input[i] == '~' ) {
            char uglyHack[] = "X";
            uglyHack[0] = input[i];
            output.append( uglyHack );
        } else {
            char percentEncode[4];
            int written = snprintf( percentEncode, 4, "%%%.2hhX", input[i] );
            assert( written == 3 );
            output.append( percentEncode );
        }
    }
    
    return output;
}

//
// Utility function.
//
bool writeShortFile( const std::string & fileName, const std::string & contents ) {
    int fd = safe_open_wrapper_follow( fileName.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600 );

    if( fd < 0 ) {
        dprintf( D_ALWAYS, "Failed to open file '%s' for writing: '%s' (%d).\n", fileName.c_str(), strerror( errno ), errno );
        return false;
    }
    
    unsigned long written = full_write( fd, contents.c_str(), contents.length() );
    close( fd );
    if( written != contents.length() ) {
        dprintf( D_ALWAYS, "Failed to completely write file '%s'; wanted to write %lu but only put %lu.\n",
				 fileName.c_str(), (unsigned long)contents.length(), written );
        return false;
    }
    
    return true;
}

//
// Utility function; inefficient.
//
bool readShortFile( const std::string & fileName, std::string & contents ) {
    int fd = safe_open_wrapper_follow( fileName.c_str(), O_RDONLY, 0600 );

    if( fd < 0 ) {
        dprintf( D_ALWAYS, "Failed to open file '%s' for reading: '%s' (%d).\n", fileName.c_str(), strerror( errno ), errno );
        return false;
    }
        
    StatWrapper sw( fd );
    unsigned long fileSize = sw.GetBuf()->st_size;
        
    char * rawBuffer = (char *)malloc( fileSize + 1 );
    assert( rawBuffer != NULL );
    unsigned long totalRead = full_read( fd, rawBuffer, fileSize );
    close( fd );
    if( totalRead != fileSize ) {
        dprintf( D_ALWAYS, "Failed to completely read file '%s'; needed %lu but got %lu.\n",
            fileName.c_str(), fileSize, totalRead );
        free( rawBuffer );
        return false;
    }    
    rawBuffer[ fileSize ] = '\0';
    contents = rawBuffer;
    free( rawBuffer );
    
    return true;
}

//
// "This function gets called by libcurl as soon as there is data received
//  that needs to be saved. The size of the data pointed to by ptr is size
//  multiplied with nmemb, it will not be zero terminated. Return the number
//  of bytes actually taken care of. If that amount differs from the amount
//  passed to your function, it'll signal an error to the library. This will
//  abort the transfer and return CURLE_WRITE_ERROR."
//
// We also make extensive use of this function in the XML parsing code,
// for pretty much exactly the same reason.
//
size_t appendToString( void * ptr, size_t size, size_t nmemb, void * str ) {
    if( size == 0 || nmemb == 0 ) { return 0; }
    
    char * ucptr = (char *)ptr;
    char last = ucptr[ (size * nmemb) - 1 ];
    ucptr[ (size * nmemb) - 1 ] = '\0';
    std::string * ssptr = (std::string *)str;
    ssptr->append( ucptr );
    (*ssptr) += last;
    ucptr[ (size * nmemb) - 1 ] = last;
    
    return (size * nmemb);
}

AmazonRequest::AmazonRequest() { }

AmazonRequest::~AmazonRequest() { }

#define SET_CURL_SECURITY_OPTION( A, B, C ) { \
    CURLcode rv##B = curl_easy_setopt( A, B, C ); \
    if( rv##B != CURLE_OK ) { \
        this->errorCode = "E_CURL_LIB"; \
        this->errorMessage = "curl_easy_setopt( " #B " ) failed."; \
        dprintf( D_ALWAYS, "curl_easy_setopt( %s ) failed (%d): '%s', failing.\n", \
            #B, rv##B, curl_easy_strerror( rv##B ) ); \
        return false; \
    } \
}

bool AmazonRequest::SendRequest() {
    //
    // Every request must have the following parameters:
    //
    //      Action, Version, AWSAccessKeyId, Timestamp (or Expires),
    //      Signature, SignatureMethod, and SignatureVersion.
    //
    
    if( query_parameters.find( "Action" ) == query_parameters.end() ) {
        this->errorCode = "E_INTERNAL";
        this->errorMessage = "No action specified in request.";
        dprintf( D_ALWAYS, "No action specified in request, failing.\n" );
        return false;
    }

    // We need to know right away if we're doing FermiLab-style authentication.
    //
    // While we're at it, extract "the value of the Host header in lowercase"
    // and the "HTTP Request URI" from the service URL.  The service URL must
    // be of the form '[http[s]|x509|euca3[s]]://hostname[:port][/path]*'.
    Regex r; int errCode = 0; const char * errString = 0;
    bool patternOK = r.compile( "([^:]+)://(([^/]+)(/.*)?)", & errString, & errCode );
    assert( patternOK );
    ExtArray<MyString> groups(5);
    bool matchFound = r.match( this->serviceURL.c_str(), & groups );
    if( (! matchFound) || (groups[1] != "http" && groups[1] != "https" && groups[1] != "x509" && groups[1] != "euca3" && groups[1] != "euca3s" ) ) {
        this->errorCode = "E_INVALID_SERVICE_URL";
        this->errorMessage = "Failed to parse service URL.";
        dprintf( D_ALWAYS, "Failed to match regex against service URL '%s'.\n", serviceURL.c_str() );
        return false;
    }
    std::string protocol = groups[1];
    std::string hostAndPath = groups[2];
    std::string valueOfHostHeaderInLowercase = groups[3];
    std::transform( valueOfHostHeaderInLowercase.begin(),
                    valueOfHostHeaderInLowercase.end(),
                    valueOfHostHeaderInLowercase.begin(),
                    & tolower );
    std::string httpRequestURI = groups[4];
    if( httpRequestURI.empty() ) { httpRequestURI = "/"; }

    //
    // Eucalyptus 3 bombs if it sees this attribute.
    //
    if( protocol == "euca3" || protocol == "euca3s" ) {
        query_parameters.erase( "InstanceInitiatedShutdownBehavior" );
    }

    //
    // The AWSAccessKeyId is just the contents of this->accessKeyFile,
    // and are (currently) 20 characters long.
    //
    std::string keyID;
    if( protocol == "x509" ) {
        keyID = getenv( "USER" );
        dprintf( D_FULLDEBUG, "Using '%s' as access key ID for x.509\n", keyID.c_str() );
    } else {
        if( ! readShortFile( this->accessKeyFile, keyID ) ) {
            this->errorCode = "E_FILE_IO";
            this->errorMessage = "Unable to read from accesskey file '" + this->accessKeyFile + "'.";
            dprintf( D_ALWAYS, "Unable to read accesskey file '%s', failing.\n", this->accessKeyFile.c_str() );
            return false;
        }
        if( keyID[ keyID.length() - 1 ] == '\n' ) { keyID.erase( keyID.length() - 1 ); }
    }        
    query_parameters.insert( std::make_pair( "AWSAccessKeyId", keyID ) );

    //
    // This implementation computes signature version 2,
    // using the "HmacSHA256" method.
    // 
    query_parameters.insert( std::make_pair( "SignatureVersion", "2" ) );
    query_parameters.insert( std::make_pair( "SignatureMethod", "HmacSHA256" ) );
    
    //
    // This implementation was written against the 2010-11-15 documentation.
    //
    query_parameters.insert( std::make_pair( "Version", "2010-11-15" ) );

    //
    // We're calculating the signature now. [YYYY-MM-DDThh:mm:ssZ]
    //
    time_t now; time( & now );
    struct tm brokenDownTime; gmtime_r( & now, & brokenDownTime );
    char iso8601[] = "YYYY-MM-DDThh:mm:ssZ";
    strftime( iso8601, 20, "%Y-%m-%dT%H:%M:%SZ", & brokenDownTime );
    query_parameters.insert( std::make_pair( "Timestamp", iso8601 ) );

    /*
     * The tricky party of sending a Query API request is calculating
     * the signature.  See
     *
     * http://docs.amazonwebservices.com/AWSEC2/2010-11-15/DeveloperGuide/using-query-api.html
     *
     */
        
    // Step 1: Create the canonicalized query string.
    std::string canonicalizedQueryString;
    AttributeValueMap encodedParameters;
    AttributeValueMap::const_iterator i;
    for( i = query_parameters.begin(); i != query_parameters.end(); ++i ) {
        // Step 1A: The map sorts the query parameters for us.
        
        // Step 1B: Encode the parameter names and values.
        std::string name = amazonURLEncode( i->first );
        std::string value = amazonURLEncode( i->second );
        encodedParameters.insert( std::make_pair( name, value ) );
        
        // Step 1C: Separate parameter names from values with '='.
        canonicalizedQueryString += name + '=' + value;
        
        // Step 1D: Separate name-value pairs with '&';
        canonicalizedQueryString += '&';
    }
    // We'll always have a superflous trailing ampersand.
    canonicalizedQueryString.erase( canonicalizedQueryString.end() - 1 );
    
    // Step 2: Create the string to sign.
    std::string stringToSign = "GET\n"
                             + valueOfHostHeaderInLowercase + "\n"
                             + httpRequestURI + "\n"
                             + canonicalizedQueryString;
    // dprintf( D_ALWAYS, "DEBUG: stringToSign is '%s'\n", stringToSign.c_str() );

    // Step 3: "Calculate an RFC 2104-compliant HMAC with the string
    // you just created, your Secret Access Key as the key, and SHA256
    // or SHA1 as the hash algorithm."
    std::string saKey;
    if( protocol == "x509" ) {
        // If we we ever support the UploadImage action, we'll need to
        // extract the DN from the user's certificate here.  Otherwise,
        // since the x.509 implementation ignores the AWSAccessKeyId
        // and Signature, we can do whatever we want.
        saKey = std::string( "<DN>/CN=UID:" ) + getenv( "USER" );
        dprintf( D_FULLDEBUG, "Using '%s' as secret key for x.509\n", saKey.c_str() );
    } else {
        if( ! readShortFile( this->secretKeyFile, saKey ) ) {
            this->errorCode = "E_FILE_IO";
            this->errorMessage = "Unable to read from secretkey file '" + this->secretKeyFile + "'.";
            dprintf( D_ALWAYS, "Unable to read secretkey file '%s', failing.\n", this->secretKeyFile.c_str() );
            return false;
        }
        // dprintf( D_ALWAYS, "DEBUG: '%s' (%d)\n", saKey.c_str(), saKey.length() );
        if( saKey[ saKey.length() - 1 ] == '\n' ) { saKey.erase( saKey.length() - 1 ); }
        // dprintf( D_ALWAYS, "DEBUG: '%s' (%d)\n", saKey.c_str(), saKey.length() );
    }
    
    unsigned int mdLength = 0;
    unsigned char messageDigest[EVP_MAX_MD_SIZE];
    const unsigned char * hmac = HMAC( EVP_sha256(), saKey.c_str(), saKey.length(),
        (unsigned char *)stringToSign.c_str(), stringToSign.length(), messageDigest, & mdLength );
    if( hmac == NULL ) {
        this->errorCode = "E_INTERNAL";
        this->errorMessage = "Unable to calculate query signature (SHA256 HMAC).";
        dprintf( D_ALWAYS, "Unable to calculate SHA256 HMAC to sign query, failing.\n" );
        return false;
    }
    // dprintf( D_ALWAYS, "DEBUG: %d -> '%c'\n", mdLength, messageDigest[0] );
    
    // Step 4: "Convert the resulting value to base64."
    char * base64Encoded = condor_base64_encode( messageDigest, mdLength );
    std::string signatureInBase64 = base64Encoded;
    free( base64Encoded );
    
    // Generate the final URI.
    canonicalizedQueryString += "&Signature=" + amazonURLEncode( signatureInBase64 );
    std::string finalURI;
    if( protocol == "x509" ) {
        finalURI = "https://" + hostAndPath + "?" + canonicalizedQueryString;
    } else if( protocol == "euca3" ) {
        finalURI = "http://" + hostAndPath + "?" + canonicalizedQueryString;
    } else if( protocol == "euca3s" ) {
        finalURI = "https://" + hostAndPath + "?" + canonicalizedQueryString;
    } else {
        finalURI = this->serviceURL + "?" + canonicalizedQueryString;
    }
    dprintf( D_FULLDEBUG, "Request URI is '%s'\n", finalURI.c_str() );
    
    // curl_global_init() is not thread-safe.  However, it's safe to call
    // multiple times.  Therefore, we'll just call it before we drop the
    // mutex, since we know that means only one thread is running.
    CURLcode rv = curl_global_init( CURL_GLOBAL_ALL );
    if( rv != 0 ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_global_init() failed.";
        dprintf( D_ALWAYS, "curl_global_init() failed, failing.\n" );
        return false;
    }
    
    CURL * curl = curl_easy_init();
    if( curl == NULL ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_init() failed.";
        dprintf( D_ALWAYS, "curl_easy_init() failed, failing.\n" );
        return false;
    }

    char errorBuffer[CURL_ERROR_SIZE];
    rv = curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errorBuffer );

    rv = curl_easy_setopt( curl, CURLOPT_URL, finalURI.c_str() );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_URL ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_URL ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }

    rv = curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1 );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_NOPROGRESS ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_NOPROGRESS ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }
    
    rv = curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, & appendToString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEFUNCTION ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_WRITEFUNCTION ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }    

    rv = curl_easy_setopt( curl, CURLOPT_WRITEDATA, & this->resultString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEDATA ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_WRITEDATA ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }
    
    //
    // Set security options.
    //
    SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSL_VERIFYPEER, 1 );
    SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSL_VERIFYHOST, 2 );

    // NB: Contrary to libcurl's manual, it doesn't strdup() strings passed
    // to it, so they MUST remain in scope until after we call
    // curl_easy_cleanup().  Otherwise, curl_perform() will fail with
    // a completely bogus error, number 60, claiming that there's a 
    // 'problem with the SSL CA cert'.
    std::string CAFile = "";
    std::string CAPath = "";

    char * x509_ca_dir = getenv( "X509_CERT_DIR" );
    if( x509_ca_dir != NULL ) {
        CAPath = x509_ca_dir;
    }

    char * x509_ca_file = getenv( "X509_CERT_FILE" );
    if( x509_ca_file != NULL ) {
        CAFile = x509_ca_file;
    }
        
    if( CAPath.empty() ) {
        char * soap_ssl_ca_dir = getenv( "SOAP_SSL_CA_DIR" );
        if( soap_ssl_ca_dir != NULL ) {
            CAPath = soap_ssl_ca_dir;
        }
    }

    if( CAFile.empty() ) {
        char * soap_ssl_ca_file = getenv( "SOAP_SSL_CA_FILE" );
        if( soap_ssl_ca_file != NULL ) {
            CAFile = soap_ssl_ca_file;
        }
    }

    if( CAPath.empty() ) {
        CAPath = "/etc/grid-security/certificates";
    }
    dprintf( D_FULLDEBUG, "Setting CA path to '%s'\n", CAPath.c_str() );
    SET_CURL_SECURITY_OPTION( curl, CURLOPT_CAPATH, CAPath.c_str() );
        
    if( ! CAFile.empty() ) {
        dprintf( D_FULLDEBUG, "Setting CA file to '%s'\n", CAFile.c_str() );
        SET_CURL_SECURITY_OPTION( curl, CURLOPT_CAINFO, CAFile.c_str() );
    }
        
    if( setenv( "OPENSSL_ALLOW_PROXY", "1", 0 ) != 0 ) {
        dprintf( D_FULLDEBUG, "Failed to set OPENSSL_ALLOW_PROXY.\n" );
    }

    //
    // Configure for x.509 operation.
    //
    if( protocol == "x509" ) {
        dprintf( D_FULLDEBUG, "Configuring x.509...\n" );

        SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSLKEYTYPE, "PEM" );
        SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSLKEY, this->secretKeyFile.c_str() );

        SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSLCERTTYPE, "PEM" );
        SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSLCERT, this->accessKeyFile.c_str() );
    }
            
    amazon_gahp_release_big_mutex();
    rv = curl_easy_perform( curl );
    amazon_gahp_grab_big_mutex();
    if( rv != 0 ) {
        this->errorCode = "E_CURL_IO";
        std::ostringstream error;
        error << "curl_easy_perform() failed (" << rv << "): '" << curl_easy_strerror( rv ) << "'.";
        this->errorMessage = error.str();
        dprintf( D_ALWAYS, "%s\n", this->errorMessage.c_str() );
        dprintf( D_FULLDEBUG, "%s\n", errorBuffer );
        return false;
    }

    unsigned long responseCode = 0;
    rv = curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, & responseCode );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_getinfo() failed.";
        dprintf( D_ALWAYS, "curl_easy_getinfo( CURLINFO_RESPONSE_CODE ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }
            
    curl_easy_cleanup( curl );
    
    if( responseCode != 200 ) {
        this->errorCode = "E_HTTP_RESPONSE_NOT_200";
        this->errorMessage = resultString;
        dprintf( D_ALWAYS, "Query did not return 200 (%lu), failing.\n",
            responseCode );
        dprintf( D_ALWAYS, "Failure response text was '%s'.\n", resultString.c_str() );
        return false;
    }
    
    return true;
}

// ---------------------------------------------------------------------------

/*
 * The *[ESH|CDH|EEH] functions are Expat callbacks for parsing the result
 * of the corresponding query.  ('EntityStartHandler', 'CharacterDataHandler',
 * and 'EntityEndHandler', respectively; referring to the opening tag, the
 * enclosed data, and the closing tag.)  This method of XML parsing is
 * extremely opaque and bug-prone, because you have to represent the structure
 * of the XML in executable code (and the *UD ('UserData') datastructures).
 *
 * If the use of libxml2 is not contraindicated (it was at one point), then
 * we can use XPath expressions (regex-like) instead of code to identify
 * the character data of interest.  This will be particularly clarity-
 * enhancing when parsing the results of DescribeInstances queries; see
 * AmazonVMStatusAll.
 *
 * See 'http://xmlsoft.org/examples/xpath1.c', which looks a lot cleaner.
 */

/*
 * FIXME: None of the ::SendRequest() methods verify that the 200/OK
 * response they tried to parse contain(ed) the attribute(s) they
 * were looking for.  Although, strictly speaking, this is a server-
 * side problem, it seems prudent to check.
 *
 * In particular, this bug allows FermiLab's x509:// schema to work,
 * since their server doesn't presently handle keypairs.  Note, however,
 * that this severely limits (if not eliminates) the GridManager's
 * crash recovery.  Newer version of the EC2 API will allow us to
 * avoid this problem by using the ability to supply a name for the instance
 * directly.
 */

AmazonVMStart::AmazonVMStart() { }

AmazonVMStart::~AmazonVMStart() { }

struct vmStartUD_t {
    bool inInstanceId;
    std::string & instanceID;

    vmStartUD_t( std::string & iid ) : inInstanceId( false ), instanceID( iid ) { }
};
typedef struct vmStartUD_t vmStartUD;

void vmStartESH( void * vUserData, const XML_Char * name, const XML_Char ** ) {
    vmStartUD * vsud = (vmStartUD *)vUserData;
    if( strcasecmp( (const char *)name, "instanceId" ) == 0 ) {
        vsud->inInstanceId = true;
    }
}

void vmStartCDH( void * vUserData, const XML_Char * cdata, int len ) {
    vmStartUD * vsud = (vmStartUD *)vUserData;
    if( vsud->inInstanceId ) {
        appendToString( (void *)cdata, len, 1, (void *) & vsud->instanceID );
    }
}

void vmStartEEH( void * vUserData, const XML_Char * name ) {
    vmStartUD * vsud = (vmStartUD *)vUserData;
    if( strcasecmp( (const char *)name, "instanceId" ) == 0 ) {
        vsud->inInstanceId = false;
    }
}

bool AmazonVMStart::SendRequest() {
    bool result = AmazonRequest::SendRequest();
    if ( result ) {
        vmStartUD vsud( this->instanceID );
        XML_Parser xp = XML_ParserCreate( NULL );
        XML_SetElementHandler( xp, & vmStartESH, & vmStartEEH );
        XML_SetCharacterDataHandler( xp, & vmStartCDH );
        XML_SetUserData( xp, & vsud );
        XML_Parse( xp, this->resultString.c_str(), this->resultString.length(), 1 );
        XML_ParserFree( xp );
    } else {
        if( this->errorCode == "E_CURL_IO" ) {
            // To be on the safe side, if the I/O failed, make the gridmanager
            // check to see the VM was started or not.
            this->errorCode = "NEED_CHECK_VM_START"; 
            return false;
        }
    }
    return result;
}

// Expecting: EC2_VM_START <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <ami-id> <keypair> <userdata> <userdatafile> <instancetype> <groupname> <groupname> ..
// <groupname> are optional ones.
// we support multiple groupnames
bool AmazonVMStart::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_START" ) == 0 );

    // Uses the Query API function 'RunInstances', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-RunInstances.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 14 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 10, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMStart vmStartRequest;
    vmStartRequest.serviceURL = argv[2];
    vmStartRequest.accessKeyFile = argv[3];
    vmStartRequest.secretKeyFile = argv[4];
    vmStartRequest.query_parameters[ "Action" ] = "RunInstances";
    vmStartRequest.query_parameters[ "ImageId" ] = argv[5];
    vmStartRequest.query_parameters[ "MinCount" ] = "1";
    vmStartRequest.query_parameters[ "MaxCount" ] = "1";
	vmStartRequest.query_parameters[ "InstanceInitiatedShutdownBehavior" ] = "terminate";
    
    // Fill in optional parameters.
    if( strcasecmp( argv[6], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "KeyName" ] = argv[6];
    }

    if( strcasecmp( argv[9], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "InstanceType" ] = argv[9];
    }

    if( strcasecmp( argv[10], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "Placement.AvailabilityZone" ] = argv[10];
    }
    
    if( strcasecmp( argv[11], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "SubnetId" ] = argv[11];
    }
    
    if( strcasecmp( argv[12], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "PrivateIpAddress" ] = argv[12];
    }

    if( strcasecmp( argv[13], NULLSTRING ) ) {
        vmStartRequest.query_parameters[ "ClientToken" ] = argv[13];
    }

    for( int i = 14; i < argc; ++i ) {
        std::ostringstream groupName;
        groupName << "SecurityGroup." << ( i - 13 + 1 );
        vmStartRequest.query_parameters[ groupName.str() ] = argv[ i ];
    }    

    //
    // Handle user data.
    //
    std::string buffer;
    if( strcasecmp( argv[7], NULLSTRING ) ) {
        buffer = argv[7];
    }
    if( strcasecmp( argv[8], NULLSTRING ) ) {
        std::string udFileName = argv[8];
        std::string udFileContents;
        if( ! readShortFile( udFileName, udFileContents ) ) {
            result_string = create_failure_result( requestID, "Failed to read userdata file.", "E_FILE_IO" );
            dprintf( D_ALWAYS, "Failed to read userdata file '%s'.\n", udFileName.c_str() );
            return false;
            }
        buffer += udFileContents;            
    }
    if( ! buffer.empty() ) {
        char * base64Encoded = condor_base64_encode( (const unsigned char *)buffer.c_str(), buffer.length() );
        vmStartRequest.query_parameters[ "UserData" ] = base64Encoded;
        free( base64Encoded );
    }
    
    // Send the request.
    if( ! vmStartRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            vmStartRequest.errorMessage.c_str(),
            vmStartRequest.errorCode.c_str() );
    } else {
        if( vmStartRequest.instanceID.empty() ) {
            dprintf( D_ALWAYS, "Got result from endpoint that did not include an instance ID, failing.  Response follows.\n" );
            dprintf( D_ALWAYS, "-- RESPONSE BEGINS --\n" );
            dprintf( D_ALWAYS, vmStartRequest.resultString.c_str() );
            dprintf( D_ALWAYS, "-- RESPONSE ENDS --\n" );
            result_string = create_failure_result( requestID, "Could not find instance ID in response from server.  Check the EC2 GAHP log for details.", "E_NO_INSTANCE_ID" );
        } else {
            StringList resultList;
            resultList.append( vmStartRequest.instanceID.c_str() );
            result_string = create_success_result( requestID, & resultList );
        }
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMStop::AmazonVMStop() { }

AmazonVMStop::~AmazonVMStop() { }

// Expecting:EC2_VM_STOP <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id>
bool AmazonVMStop::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_STOP" ) == 0 );

    // Uses the Query API function 'TerminateInstances', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-TerminateInstances.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 6 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 6, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMStop terminationRequest;
    terminationRequest.serviceURL = argv[2];
    terminationRequest.accessKeyFile = argv[3];
    terminationRequest.secretKeyFile = argv[4];
    terminationRequest.query_parameters[ "Action" ] = "TerminateInstances";
    terminationRequest.query_parameters[ "InstanceId.1" ] = argv[5];

    // Send the request.
    if( ! terminationRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            terminationRequest.errorMessage.c_str(),
            terminationRequest.errorCode.c_str() );
    } else {
        // AmazonVMStop::SendRequest() could parse its resultString
        // to look for instance IDs (and current/previous states),
        // but it doesn't presently look like it needs to so do.
        result_string = create_success_result( requestID, NULL );
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMStatus::AmazonVMStatus() { }

AmazonVMStatus::~AmazonVMStatus() { }

const char * nullStringIfEmpty( const std::string & str ) {
    if( str.empty() ) { return NULLSTRING; }
    else { return str.c_str(); }
}    

// Expecting:EC2_VM_STATUS <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id>
bool AmazonVMStatus::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_STATUS" ) == 0 );

    // Uses the Query API function 'DescribeInstances', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeInstances.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 6 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 6, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMStatus sRequest;
    sRequest.serviceURL = argv[2];
    sRequest.accessKeyFile = argv[3];
    sRequest.secretKeyFile = argv[4];
    sRequest.query_parameters[ "Action" ] = "DescribeInstances";
    // We should also be able to set the parameter InstanceId.1
    // and only get one instance back, rather than filtering.
    std::string instanceID = argv[5];
    
    // Send the request.
    if( ! sRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            sRequest.errorMessage.c_str(),
            sRequest.errorCode.c_str() );
    } else {
        if( sRequest.results.size() == 0 ) {
            result_string = create_success_result( requestID, NULL );
        } else {
            StringList resultList;
            for( unsigned i = 0; i < sRequest.results.size(); ++i ) {
                AmazonStatusResult asr = sRequest.results[i];
                if( asr.instance_id != instanceID ) { continue; }
                
                resultList.append( asr.instance_id.c_str() );
                resultList.append( asr.status.c_str() );
                resultList.append( asr.ami_id.c_str() );
                
                if( strcasecmp( asr.status.c_str(), AMAZON_STATUS_RUNNING ) == 0 ) {
                    resultList.append( nullStringIfEmpty( asr.public_dns ) );
                    resultList.append( nullStringIfEmpty( asr.private_dns ) );
                    resultList.append( nullStringIfEmpty( asr.keyname ) );
                    if( asr.securityGroups.size() == 0 ) {
                        resultList.append( NULLSTRING );
                    } else {                        
                        for( unsigned j = 0; j < asr.securityGroups.size(); ++j ) {
                            resultList.append( asr.securityGroups[j].c_str() );
                        }
                    }
                }
            }
            result_string = create_success_result( requestID, & resultList );
        }
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMStatusAll::AmazonVMStatusAll() { }

AmazonVMStatusAll::~AmazonVMStatusAll() { }

struct vmStatusUD_t {
    enum vmStatusTags_t {
        NONE,
        INSTANCE_ID,
        STATUS,
        AMI_ID,
        PUBLIC_DNS,
        PRIVATE_DNS,
        KEY_NAME,
        INSTANCE_TYPE,
        GROUP_ID
    };
    typedef enum vmStatusTags_t vmStatusTags;

    bool inInstancesSet;
    bool inInstance;
    bool inInstanceState;
    vmStatusTags inWhichTag;
    AmazonStatusResult * currentResult;
    std::vector< AmazonStatusResult > & results;

    bool inGroupSet;
    bool inGroup;
    std::string currentSecurityGroup;
    std::vector< std::string > currentSecurityGroups;
    
    vmStatusUD_t( std::vector< AmazonStatusResult > & asrList ) : 
        inInstancesSet( false ), 
        inInstance( false ),
        inInstanceState( false ),
        inWhichTag( vmStatusUD_t::NONE ), 
        currentResult( NULL ), 
        results( asrList ),
        inGroupSet( false ),
        inGroup( false ) { }
};
typedef struct vmStatusUD_t vmStatusUD;

void vmStatusESH( void * vUserData, const XML_Char * name, const XML_Char ** ) {
    vmStatusUD * vsud = (vmStatusUD *)vUserData;

    if( strcasecmp( (const char *)name, "groupSet" ) == 0 ) {
        vsud->currentSecurityGroups.clear();
        vsud->inGroupSet = true;
        return;
    }

    if( vsud->inGroupSet && strcasecmp( (const char *)name, "groupId" ) == 0 ) {
        vsud->inGroup = true;
        return;
    }        

    if( ! vsud->inInstancesSet ) {
        if( strcasecmp( (const char *)name, "instancesSet" ) == 0 ) {
            vsud->inInstancesSet = true;
        }            
        return;
    } 
    
    if( ! vsud->inInstance ) {
        if( strcasecmp( (const char *)name, "item" ) == 0 ) {
            vsud->currentResult = new AmazonStatusResult();
            assert( vsud->currentResult != NULL );
            vsud->inInstance = true;
        }
        return;
    }
    
    if( strcasecmp( (const char *)name, "instanceId" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::INSTANCE_ID;
    } else if( strcasecmp( (const char *)name, "imageId" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::AMI_ID;
    } else if( strcasecmp( (const char *)name, "privateDnsName" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::PRIVATE_DNS;
    } else if( strcasecmp( (const char *)name, "dnsName" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::PUBLIC_DNS;
    } else if( strcasecmp( (const char *)name, "keyName" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::KEY_NAME;
    } else if( strcasecmp( (const char *)name, "instanceType" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::INSTANCE_TYPE;
    } else if( strcasecmp( (const char *)name, "instanceState" ) == 0 ) {
        vsud->inInstanceState = true;
        vsud->inWhichTag = vmStatusUD::NONE;
    } else if( vsud->inInstanceState && strcasecmp( (const char *)name, "name" ) == 0 ) {
        vsud->inWhichTag = vmStatusUD::STATUS;
    }
}

void vmStatusCDH( void * vUserData, const XML_Char * cdata, int len ) {
    vmStatusUD * vsud = (vmStatusUD *)vUserData;

    if( vsud->inGroup ) {
        appendToString( (void *)cdata, len, 1, (void *) & vsud->currentSecurityGroup );
        return;
    }

    if( vsud->currentResult == NULL ) {
        return;
    }

    std::string * targetString = NULL;
    switch( vsud->inWhichTag ) {
        case vmStatusUD::NONE:
            return;
        
        case vmStatusUD::INSTANCE_ID:
            targetString = & vsud->currentResult->instance_id;
            break;
        
        case vmStatusUD::STATUS:
            targetString = & vsud->currentResult->status;
            break;
        
        case vmStatusUD::AMI_ID:
            targetString = & vsud->currentResult->ami_id;
            break;
        
        case vmStatusUD::PRIVATE_DNS:
            targetString = & vsud->currentResult->private_dns;
            break;
            
        case vmStatusUD::PUBLIC_DNS:
            targetString = & vsud->currentResult->public_dns;
            break;

        case vmStatusUD::KEY_NAME:
            targetString = & vsud->currentResult->keyname;
            break;
        
        case vmStatusUD::INSTANCE_TYPE:
            targetString = & vsud->currentResult->instancetype;
            break;

        default:
            /* This should never happen. */
            return;
    }

    appendToString( (void *)cdata, len, 1, (void *)targetString );
}

void vmStatusEEH( void * vUserData, const XML_Char * name ) {
    vmStatusUD * vsud = (vmStatusUD *)vUserData;

    if( vsud->inGroupSet ) {
        if( strcasecmp( (const char *)name, "groupId" ) == 0 ) {
            // dprintf( D_ALWAYS, "DEBUG: adding '%s' to current security group list...\n", vsud->currentSecurityGroup.c_str() );
            vsud->currentSecurityGroups.push_back( vsud->currentSecurityGroup );
            vsud->currentSecurityGroup.erase();
            vsud->inGroup = false;
            return;
        } else if( strcasecmp( (const char *)name, "groupSet" ) == 0 ) {
            vsud->inGroupSet = false;
            return;
        }
    }

    if( vsud->inInstance && strcasecmp( (const char *)name, "item" ) == 0 ) {
        // We assume that the security group list (GroupItemType groupSet)
        // always appears in the XML stream (in the reservationInfoType
        // reservationSet) before the corresponding instancesSet.
        vsud->currentResult->securityGroups = vsud->currentSecurityGroups;
        vsud->results.push_back( * vsud->currentResult );
        delete vsud->currentResult;
        vsud->currentResult = NULL;
        vsud->inInstance = false;
        return;
    }
    
    if( vsud->inInstancesSet && strcasecmp( (const char *)name, "instancesSet" ) == 0 ) {
        vsud->inInstancesSet = false;
        return;
    }

    if( strcasecmp( (const char *)name, "instanceState" ) == 0 ) {
        vsud->inInstanceState = false;
        return;
    }
    
    vsud->inWhichTag = vmStatusUD::NONE;
} 

bool AmazonVMStatusAll::SendRequest() {
    bool result = AmazonRequest::SendRequest();
    if( result ) {
        vmStatusUD vsud( this->results );
        XML_Parser xp = XML_ParserCreate( NULL );
        XML_SetElementHandler( xp, & vmStatusESH, & vmStatusEEH );
        XML_SetCharacterDataHandler( xp, & vmStatusCDH );
        XML_SetUserData( xp, & vsud );
        XML_Parse( xp, this->resultString.c_str(), this->resultString.length(), 1 );
        XML_ParserFree( xp );
    }
    return result;
}

// Expecting:EC2_VM_STATUS_ALL <req_id> <serviceurl> <accesskeyfile> <secretkeyfile>
bool AmazonVMStatusAll::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_STATUS_ALL" ) == 0 );

    // Uses the Query API function 'DescribeInstances', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeInstances.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 5 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 5, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMStatusAll saRequest;
    saRequest.serviceURL = argv[2];
    saRequest.accessKeyFile = argv[3];
    saRequest.secretKeyFile = argv[4];
    saRequest.query_parameters[ "Action" ] = "DescribeInstances";
    
    // Send the request.
    if( ! saRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            saRequest.errorMessage.c_str(),
            saRequest.errorCode.c_str() );
    } else {
        if( saRequest.results.size() == 0 ) {
            result_string = create_success_result( requestID, NULL );
        } else {
            StringList resultList;
            for( unsigned i = 0; i < saRequest.results.size(); ++i ) {
                AmazonStatusResult & asr = saRequest.results[i];
                resultList.append( asr.instance_id.c_str() );
                resultList.append( asr.status.c_str() );
                resultList.append( asr.ami_id.c_str() );
                
//                dprintf( D_ALWAYS, "DEBUG: '%s' '%s' '%s' '%s' '%s' '%s' '%s'\n",
//                    asr.instance_id.c_str(),
//                    asr.status.c_str(),
//                    asr.ami_id.c_str(),
//                    asr.private_dns.c_str(),
//                    asr.public_dns.c_str(),
//                    asr.keyname.c_str(),
//                    asr.instancetype.c_str() );

//                std::string sgList;
//                for( unsigned j = 0; j < asr.securityGroups.size(); ++j ) {
//                    sgList += "'" + asr.securityGroups[j] + "' ";
//                }
//                dprintf( D_ALWAYS, "DEBUG: with security group(s): %s\n", sgList.c_str() );
            }
            result_string = create_success_result( requestID, & resultList );
        }
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMRunningKeypair::AmazonVMRunningKeypair() { }

AmazonVMRunningKeypair::~AmazonVMRunningKeypair() { }

// Expecting:EC2_VM_RUNNING_KEYPAIR <req_id> <serviceurl> <accesskeyfile> <secretkeyfile>
bool AmazonVMRunningKeypair::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_RUNNING_KEYPAIR" ) == 0 );

    // Uses the Query API function 'DescribeInstances', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeInstances.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 5 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 5, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMRunningKeypair rkpRequest;
    rkpRequest.serviceURL = argv[2];
    rkpRequest.accessKeyFile = argv[3];
    rkpRequest.secretKeyFile = argv[4];
    rkpRequest.query_parameters[ "Action" ] = "DescribeInstances";
    
    // Send the request.
    if( ! rkpRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            rkpRequest.errorMessage.c_str(),
            rkpRequest.errorCode.c_str() );
    } else {
        if( rkpRequest.results.size() == 0 ) {
            result_string = create_success_result( requestID, NULL );
        } else {
            StringList resultList;
            for( unsigned i = 0; i < rkpRequest.results.size(); ++i ) {
                AmazonStatusResult & asr = rkpRequest.results[i];

                // The original SOAP-based GAHP didn't filter the 'running'
                // key pairs based on their status, so we won't either.
                if( ! asr.keyname.empty() ) {
                    resultList.append( asr.instance_id.c_str() );
                    resultList.append( asr.keyname.c_str() );
                }
            }
            result_string = create_success_result( requestID, & resultList );
        }            
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMCreateKeypair::AmazonVMCreateKeypair() { }

AmazonVMCreateKeypair::~AmazonVMCreateKeypair() { }

struct privateKeyUD_t {
    bool inKeyMaterial;
    std::string keyMaterial;
    
    privateKeyUD_t() : inKeyMaterial( false ) { }
};
typedef struct privateKeyUD_t privateKeyUD;

void createKeypairESH( void * vUserData, const XML_Char * name, const XML_Char ** ) {
    privateKeyUD * pkud = (privateKeyUD *)vUserData;
    if( strcasecmp( (const char *)name, "keyMaterial" ) == 0 ) {
        pkud->inKeyMaterial = true;
    }
}

void createKeypairCDH( void * vUserData, const XML_Char * cdata, int len ) {
    privateKeyUD * pkud = (privateKeyUD *)vUserData;
    if( pkud->inKeyMaterial ) {
        appendToString( (void *)cdata, len, 1, (void *) & pkud->keyMaterial );
    }
}

void createKeypairEEH( void * vUserData, const XML_Char * name ) {
    privateKeyUD * pkud = (privateKeyUD *)vUserData;
    if( strcasecmp( (const char *)name, "keyMaterial" ) == 0 ) {
        pkud->inKeyMaterial = false;
    }    
}

bool AmazonVMCreateKeypair::SendRequest() {
    bool result = AmazonRequest::SendRequest();
    if( result ) {
        privateKeyUD pkud;
        XML_Parser xp = XML_ParserCreate( NULL );
        XML_SetElementHandler( xp, & createKeypairESH, & createKeypairEEH );
        XML_SetCharacterDataHandler( xp, & createKeypairCDH );
        XML_SetUserData( xp, & pkud );
        XML_Parse( xp, this->resultString.c_str(), this->resultString.length(), 1 );
        XML_ParserFree( xp );

        if( ! writeShortFile( this->privateKeyFileName, pkud.keyMaterial ) ) {
            this->errorCode = "E_FILE_IO";
            this->errorMessage = "Failed to write private key to file.";
            dprintf( D_ALWAYS, "Failed to write private key material to '%s', failing.\n",
                this->privateKeyFileName.c_str() );
            return false;
        }
    } else {
        if( this->errorCode == "E_CURL_IO" ) {
            // To be on the safe side, if the I/O failed, make the gridmanager
            // check to see the keys were created or not.
            this->errorCode = "NEED_CHECK_SSHKEY";
            return false;
        }
    }
    return result;
}

// Expecting:EC2_VM_CREATE_KEYPAIR <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <keyname> <outputfile>
bool AmazonVMCreateKeypair::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_CREATE_KEYPAIR" ) == 0 );

    // Uses the Query API function 'CreateKeyPair', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-CreateKeyPair.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 7 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 7, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMCreateKeypair ckpRequest;
    ckpRequest.serviceURL = argv[2];
    ckpRequest.accessKeyFile = argv[3];
    ckpRequest.secretKeyFile = argv[4];
    ckpRequest.query_parameters[ "Action" ] = "CreateKeyPair";
    ckpRequest.query_parameters[ "KeyName" ] = argv[5];
    ckpRequest.privateKeyFileName = argv[6];

    // Send the request.
    if( ! ckpRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            ckpRequest.errorMessage.c_str(),
            ckpRequest.errorCode.c_str() );
    } else {
        result_string = create_success_result( requestID, NULL );
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMDestroyKeypair::AmazonVMDestroyKeypair() { }

AmazonVMDestroyKeypair::~AmazonVMDestroyKeypair() { }

// Expecting:EC2_VM_DESTROY_KEYPAIR <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <keyname>
bool AmazonVMDestroyKeypair::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_DESTROY_KEYPAIR" ) == 0 );

    // Uses the Query API function 'DeleteKeyPair', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DeleteKeyPair.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 6 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 6, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMDestroyKeypair dkpRequest;
    dkpRequest.serviceURL = argv[2];
    dkpRequest.accessKeyFile = argv[3];
    dkpRequest.secretKeyFile = argv[4];
    dkpRequest.query_parameters[ "Action" ] = "DeleteKeyPair";
    dkpRequest.query_parameters[ "KeyName" ] = argv[5];

    // Send the request.
    if( ! dkpRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            dkpRequest.errorMessage.c_str(),
            dkpRequest.errorCode.c_str() );
    } else {
        result_string = create_success_result( requestID, NULL );
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonVMKeypairNames::AmazonVMKeypairNames() { }

AmazonVMKeypairNames::~AmazonVMKeypairNames() { }

struct keyNamesUD_t {
    bool inKeyName;
    std::string keyName;
    StringList & keyNameList;
    
    keyNamesUD_t( StringList & slr ) : inKeyName( false ), keyName(), keyNameList( slr ) { }
};
typedef struct keyNamesUD_t keyNamesUD;

//
// Technically, all the const XML_Char * strings are encoded in UTF-8.
// We'll ignore that for now and assume they're in ASCII.
//

// EntityStartHandler
void keypairNamesESH( void * vUserData, const XML_Char * name, const XML_Char ** ) {
    keyNamesUD * knud = (keyNamesUD *)vUserData;
    if( strcasecmp( (const char *)name, "KeyName" ) == 0 ) {
        knud->inKeyName = true;
    }
}

// CharacterDataHandler
void keypairNamesCDH( void * vUserData, const XML_Char * cdata, int len ) {
    keyNamesUD * knud = (keyNamesUD *)vUserData;
    if( knud->inKeyName ) {
        appendToString( (void *)cdata, len, 1, (void *) & knud->keyName );
    }
}

// EntityEndHandler
void keypairNamesEEH( void * vUserData, const XML_Char * name ) {
    keyNamesUD * knud = (keyNamesUD *)vUserData;
    if( strcasecmp( (const char *)name, "KeyName" ) == 0 ) {
        knud->inKeyName = false;
        // dprintf( D_ALWAYS, "DEBUG: found end of name '%s'\n", knud->keyName.c_str() );
        knud->keyNameList.append( knud->keyName.c_str() );
        knud->keyName.clear();
    }
}

bool AmazonVMKeypairNames::SendRequest() {
    bool result = AmazonRequest::SendRequest();
    if( result ) {
        // dprintf( D_ALWAYS, "DEBUG: '%s'\n", this->resultString.c_str() );
        keyNamesUD knud( this->keyNames );
        XML_Parser xp = XML_ParserCreate( NULL );
        XML_SetElementHandler( xp, & keypairNamesESH, & keypairNamesEEH );
        XML_SetCharacterDataHandler( xp, & keypairNamesCDH );
        XML_SetUserData( xp, & knud );
        XML_Parse( xp, this->resultString.c_str(), this->resultString.length(), 1 );
        XML_ParserFree( xp );
    }
    return result;
}

// Expecting:EC2_VM_KEYPAIR_NAMES <req_id> <serviceurl> <accesskeyfile> <secretkeyfile>
bool AmazonVMKeypairNames::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_KEYPAIR_NAMES" ) == 0 );

    // Uses the Query API function 'DescribeKeyPairs', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/ApiReference-query-DescribeKeyPairs.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 5 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n",
                 argc, 5, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonVMKeypairNames keypairRequest;
    keypairRequest.serviceURL = argv[2];
    keypairRequest.accessKeyFile = argv[3];
    keypairRequest.secretKeyFile = argv[4];
    keypairRequest.query_parameters[ "Action" ] = "DescribeKeyPairs";

    // Send the request.
    if( ! keypairRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            keypairRequest.errorMessage.c_str(),
            keypairRequest.errorCode.c_str() );
    } else {
        result_string = create_success_result( requestID, & keypairRequest.keyNames );
    }

    return true;
}

// ---------------------------------------------------------------------------

AmazonAssociateAddress::AmazonAssociateAddress() { }

AmazonAssociateAddress::~AmazonAssociateAddress() { }

// Expecting:EC2_VM_ASSOCIATE_ADDRESS <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id> <elastic-ip>
bool AmazonAssociateAddress::workerFunction(char **argv, int argc, std::string &result_string) {
    assert( strcmp( argv[0], "EC2_VM_ASSOCIATE_ADDRESS" ) == 0 );

    // Uses the Query API function 'AssociateAddress', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-AssociateAddress.html

    int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 7 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n", argc, 7, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonAssociateAddress asRequest;
    asRequest.serviceURL = argv[2];
    asRequest.accessKeyFile = argv[3];
    asRequest.secretKeyFile = argv[4];
    asRequest.query_parameters[ "Action" ] = "AssociateAddress";
    asRequest.query_parameters[ "InstanceId" ] = argv[5];
	
	// here it could be a standard ip or a vpc ip 
	// vpc ip's will have a : separating 
	const char * pszFullIPStr = argv[6];
	const char * pszIPStr=0;
	const char * pszAllocationId=0;
	StringList elastic_ip_addr_info (pszFullIPStr, ":");
	elastic_ip_addr_info.rewind();
	pszIPStr = elastic_ip_addr_info.next();
	pszAllocationId=elastic_ip_addr_info.next();
	
	if ( pszAllocationId )
	{
		asRequest.query_parameters[ "AllocationId" ] = pszAllocationId;
	}
	else
	{
		asRequest.query_parameters[ "PublicIp" ] = pszIPStr;
	}
	
    // Send the request.
    if( ! asRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            asRequest.errorMessage.c_str(),
            asRequest.errorCode.c_str() );
    } else {
        result_string = create_success_result( requestID, NULL );
    }

    return true;
}


// ---------------------------------------------------------------------------


AmazonCreateTags::AmazonCreateTags() { }

AmazonCreateTags::~AmazonCreateTags() { }

// Expecting:
//   EC2_VM_CREATE_TAGS <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id> <tag name>=<tag value> ...
// Expecting:EC2_VM_START <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <ami-id> <keypair> <userdata> <userdatafile> <instancetype> <availability_zone> <vpc_subnet> <vpc_ip> <groupname> <groupname> ..
// <groupname> are optional ones.
// we support multiple groupnames
bool AmazonCreateTags::ioCheck(char **argv, int argc)
{
	return verify_min_number_args(argc, 7) &&
		verify_request_id(argv[1]) &&
		verify_string_name(argv[2]) &&
		verify_string_name(argv[3]) &&
		verify_string_name(argv[4]) &&
		verify_string_name(argv[5]) &&
		verify_string_name(argv[6]);
}

// Expecting:
//   EC2_VM_CREATE_TAGS <req_id> <serviceurl> <accesskeyfile> <secretkeyfile> <instance-id> <tag name>=<tag value> ...
bool
AmazonCreateTags::workerFunction(char **argv,
								 int argc,
								 std::string &result_string)
{
    assert(strcmp(argv[0], "EC2_VM_CREATE_TAGS") == 0);

    // Uses the Query API function 'CreateTags', as documented at
    // http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/index.html?ApiReference-query-CreateTags.html

    int requestID;
    get_int(argv[1], &requestID);

    if (!verify_min_number_args(argc, 7)) {
        result_string = create_failure_result(requestID, "Wrong_Argument_Number");
        dprintf(D_ALWAYS,
				"Wrong number of arguments (%d should be >= %d) to %s\n",
				argc, 7, argv[0]);
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonCreateTags asRequest;
    asRequest.serviceURL = argv[2];
    asRequest.accessKeyFile = argv[3];
    asRequest.secretKeyFile = argv[4];
    asRequest.query_parameters["Action"] = "CreateTags";
    asRequest.query_parameters["ResourceId.0"] = argv[5];

	std::string tag;
	for (int i = 6; i < argc; i++) {
		std::stringstream ss;
		ss << "Tag." << (i - 6);
		tag = argv[i];
		asRequest.query_parameters[ss.str().append(".Key")] =
			tag.substr(0, tag.find('='));
		asRequest.query_parameters[ss.str().append(".Value")] =
			tag.substr(tag.find('=') + 1);
	}
	
    // Send the request.
    if (!asRequest.SendRequest()) {
        result_string = create_failure_result(requestID,
											  asRequest.errorMessage.c_str(),
											  asRequest.errorCode.c_str());
    } else {
        result_string = create_success_result(requestID, NULL);
    }

    return true;
}


// ---------------------------------------------------------------------------


AmazonAttachVolume::AmazonAttachVolume() { }

AmazonAttachVolume::~AmazonAttachVolume() { }

bool AmazonAttachVolume::workerFunction(char **argv, int argc, std::string &result_string) 
{
	assert( strcmp( argv[0], "EC_VM_ATTACH_VOLUME" ) == 0 );
	
	int requestID;
    get_int( argv[1], & requestID );
    
    if( ! verify_min_number_args( argc, 8 ) ) {
        result_string = create_failure_result( requestID, "Wrong_Argument_Number" );
        dprintf( D_ALWAYS, "Wrong number of arguments (%d should be >= %d) to %s\n", argc, 8, argv[0] );
        return false;
    }

    // Fill in required attributes & parameters.
    AmazonAttachVolume asRequest;
    asRequest.serviceURL = argv[2];
    asRequest.accessKeyFile = argv[3];
    asRequest.secretKeyFile = argv[4];
    asRequest.query_parameters[ "Action" ] = "AttachVolume";
    asRequest.query_parameters[ "VolumeId" ] = argv[5];
    asRequest.query_parameters[ "InstanceId" ] = argv[6];
	asRequest.query_parameters[ "Device" ] = argv[7];

    // Send the request.
    if( ! asRequest.SendRequest() ) {
        result_string = create_failure_result( requestID,
            asRequest.errorMessage.c_str(),
            asRequest.errorCode.c_str() );
    } else {
        result_string = create_success_result( requestID, NULL );
    }

    return true;
	
}

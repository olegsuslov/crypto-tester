/* Standard headers */  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>  
  
/* OpenSSL headers */  
#include <openssl/bio.h>  
#include <openssl/ssl.h>  
#include <openssl/err.h>  
  
/** 
 * Simple log function 
 */  
void slog(char* message) {  
    fprintf(stdout, message);  
}  
  
/** 
 * Print SSL error details 
 */  
void print_ssl_error(char* message, FILE* out) {  
  
    fprintf(out, message);  
    fprintf(out, "Error: %s\n", ERR_reason_error_string(ERR_get_error()));  
    fprintf(out, "%s\n", ERR_error_string(ERR_get_error(), NULL));  
    ERR_print_errors_fp(out);  
}  
  
/** 
 * Print SSL error details with inserted content 
 */  
void print_ssl_error_2(char* message, char* content, FILE* out) {  
  
    fprintf(out, message, content);  
    fprintf(out, "Error: %s\n", ERR_reason_error_string(ERR_get_error()));  
    fprintf(out, "%s\n", ERR_error_string(ERR_get_error(), NULL));  
    ERR_print_errors_fp(out);  
}  
  
/** 
 * Initialise OpenSSL 
 */  
void init_openssl() {  
  
    /* call the standard SSL init functions */  
    SSL_load_error_strings();  
    SSL_library_init();  
    ERR_load_BIO_strings();  
    OpenSSL_add_all_algorithms();  
  
    /* seed the random number system - only really nessecary for systems without '/dev/random' */  
    /* RAND_add(?,?,?); need to work out a cryptographically significant way of generating the seed */  
}  
  
/** 
 * Close an unencrypted connection gracefully 
 */  
int close_connection(BIO* bio) {  
  
    int r = 0;  
  
    r = BIO_free(bio);  
    if (r == 0) {  
        /* Error unable to free BIO */  
    }  
  
    return r;  
}  
  
/** 
 * Connect to a host using an unencrypted stream 
 */  
BIO* connect_unencrypted(char* host_and_port) {  
  
    BIO* bio = NULL;  
  
    /* Create a new connection */  
    bio = BIO_new_connect(host_and_port);  
    if (bio == NULL) {  
  
        print_ssl_error("Unable to create a new unencrypted BIO object.\n", stdout);  
        return NULL;  
    }  
  
    /* Verify successful connection */  
    if (BIO_do_connect(bio) != 1) {  
  
        print_ssl_error("Unable to connect unencrypted.\n", stdout);  
        close_connection(bio);  
        return NULL;  
    }  
  
    return bio;  
}  
  
/** 
 * Connect to a host using an encrypted stream 
 */  
BIO* connect_encrypted(char* host_and_port, char* store_path, char store_type, SSL_CTX** ctx, SSL** ssl) {  
  
    BIO* bio = NULL;  
    int r = 0;  
  
    /* Set up the SSL pointers */  
    *ctx = SSL_CTX_new(SSLv23_client_method());  
    *ssl = NULL;  
  
    /* Load the trust store from the pem location in argv[2] */  
    if (store_type == 'f')  
        r = SSL_CTX_load_verify_locations(*ctx, store_path, NULL);  
    else  
        r = SSL_CTX_load_verify_locations(*ctx, NULL, store_path);  
    if (r == 0) {  
  
        print_ssl_error_2("Unable to load the trust store from %s.\n", store_path, stdout);  
        return NULL;  
    }  
  
    /* Setting up the BIO SSL object */  
    bio = BIO_new_ssl_connect(*ctx);  
    BIO_get_ssl(bio, ssl);  
    if (!(*ssl)) {  
  
        print_ssl_error("Unable to allocate SSL pointer.\n", stdout);  
        return NULL;  
    }  
    SSL_set_mode(*ssl, SSL_MODE_AUTO_RETRY);  
  
    /* Attempt to connect */  
    BIO_set_conn_hostname(bio, host_and_port);  
  
    /* Verify the connection opened and perform the handshake */  
    if (BIO_do_connect(bio) < 1) {  
  
        print_ssl_error_2("Unable to connect BIO.%s\n", host_and_port, stdout);  
        return NULL;  
    }  
  
    if (SSL_get_verify_result(*ssl) != X509_V_OK) {  
  
        print_ssl_error("Unable to verify connection result.\n", stdout);  
    }  
  
    return bio;  
}  
  
/** 
 * Read a from a stream and handle restarts if nessecary 
 */  
ssize_t read_from_stream(BIO* bio, char* buffer, ssize_t length) {  
  
    ssize_t r = -1;  
  
    while (r < 0) {  
  
        r = BIO_read(bio, buffer, length);  
        if (r == 0) {  
  
            print_ssl_error("Reached the end of the data stream.\n", stdout);  
            continue;  
  
        } else if (r < 0) {  
  
            if (!BIO_should_retry(bio)) {  
  
                print_ssl_error("BIO_read should retry test failed.\n", stdout);  
                continue;  
            }  
  
            /* It would be prudent to check the reason for the retry and handle 
             * it appropriately here */  
        }  
  
    };  
  
    return r;  
}  
  
/** 
 * Write to a stream and handle restarts if nessecary 
 */  
int write_to_stream(BIO* bio, char* buffer, ssize_t length) {  
  
    ssize_t r = -1;  
  
    while (r < 0) {  
  
        r = BIO_write(bio, buffer, length);  
        if (r <= 0) {  
  
            if (!BIO_should_retry(bio)) {  
  
                print_ssl_error("BIO_read should retry test failed.\n", stdout);  
                continue;  
            }  
  
            /* It would be prudent to check the reason for the retry and handle 
             * it appropriately here */  
        }  
  
    }  
  
    return r;  
}  
  
/** 
 * Main SSL demonstration code entry point 
 */  
int main(int argc, char** argv) {  
  
    char* host_and_port = argv[1]; /* localhost:4422 */  
    char* server_request = argv[2]; /* "GET / \r\n\r\n" */  
    char* store_path = argv[3]; /* /home/user/projects/sslclient/certificate.pem */  
    char store_type = argv[4][0]; /* f = file, anything else is a directory structure */  
    char connection_type = argv[5][0]; /* e = encrypted, anything else is unencrypted */  
  
    char buffer[4096];  
    buffer[0] = 0;  
  
    BIO* bio;  
    SSL_CTX* ctx = NULL;  
    SSL* ssl = NULL;  
  
    /* initilise the OpenSSL library */  
    init_openssl();  
  
    /* encrypted link */  
    if (connection_type == 'e') {  
  
        if ((bio = connect_encrypted(host_and_port, store_path, store_type, &ctx, &ssl)) == NULL)  
            return (EXIT_FAILURE);  
    }  
        /* unencrypted link */  
    else if ((bio = connect_unencrypted(host_and_port)) == NULL)  
        return (EXIT_FAILURE);  
  
    write_to_stream(bio, server_request, strlen(server_request));  
    read_from_stream(bio, buffer, 4096);  
    printf("%s\r\n", buffer);  
  
    if (close_connection(bio) == 0)  
        return (EXIT_FAILURE);  
  
    /* clean up the SSL context resources for the encrypted link */  
    if (connection_type == 'e')  
        SSL_CTX_free(ctx);  
  
    return (EXIT_SUCCESS);  
}

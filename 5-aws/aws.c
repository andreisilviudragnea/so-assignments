/*
 * epoll-based echo server. Uses epoll(7) to multiplex connections.
 *
 * TODO:
 *  - block data receiving when receive buffer is full (use circular buffers)
 *  - do not copy receive buffer into send buffer when send buffer data is
 *      still valid
 *
 * 2011-2017, Operating Systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <http_parser.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

#include "aws.h"
#include "util.h"
#include "debug.h"
#include "sock_util.h"
#include "w_epoll.h"


/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

enum connection_state {
	STATE_DATA_RECEIVED,
	STATE_DATA_SENT,
	STATE_CONNECTION_CLOSED,
	STATE_RECEIVING_REQUEST,
	STATE_RECEIVED_REQUEST,
	STATE_SENDING_HEADERS,
	STATE_SENDING_ERROR_HEADERS,
	STATE_SENDING_FILE,
	STATE_SENT_FILE
};

struct buffer {
	char data[BUFSIZ];
	size_t offset;
	size_t length;
};

struct path_buffer {
	const char *buf;
	size_t len;
};

/* structure acting as a connection handler */
struct connection {
	int sockfd;
	int filefd;
	/* buffers used for receiving messages and then echoing them back */
	struct buffer recv_buffer;
	struct buffer send_buffer;
	size_t file_size;
	size_t file_offset;
	enum connection_state state;
	http_parser request_parser;
	struct path_buffer path_buffer;
};

/*
 * Initialize connection structure on given socket.
 */

static struct connection *connection_create(int sockfd)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	memset(&conn->recv_buffer, 0, sizeof(conn->recv_buffer));
	memset(&conn->send_buffer, 0, sizeof(conn->send_buffer));
	memset(&conn->path_buffer, 0, sizeof(conn->path_buffer));

	http_parser_init(&conn->request_parser, HTTP_REQUEST);
    conn->request_parser.data = conn;

	conn->state = STATE_RECEIVING_REQUEST;

	return conn;
}

static int on_path(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = p->data;

	if (conn->path_buffer.buf == NULL) {
		conn->path_buffer.buf = buf;
	}
	conn->path_buffer.len += len;

	dlog(LOG_INFO, "Received path: %.*s\n", (int) len, buf);

	return 0;
}

static int on_headers_complete(http_parser *p)
{
	struct connection *conn = p->data;

	conn->state = STATE_RECEIVED_REQUEST;
	dlog(LOG_INFO, "On headers complete\n");

	return 0;
}

static int on_message_complete(http_parser *p)
{
	struct connection *conn = p->data;

	conn->state = STATE_RECEIVED_REQUEST;
	dlog(LOG_INFO, "On message complete\n");

	return 0;
}

static http_parser_settings settings_on_path = {
		.on_message_begin = NULL,
		.on_header_field = NULL,
		.on_header_value = NULL,
		.on_path = NULL,
		.on_url = on_path,
		.on_fragment = NULL,
		.on_query_string = NULL,
		.on_body = NULL,
		.on_headers_complete = on_headers_complete,
		.on_message_complete = on_message_complete,
};

/*
 * Remove connection handler.
 */

static void connection_remove(struct connection *conn)
{
	close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
	free(conn);
}

/*
 * Handle a new connection request on the server socket.
 */

static void handle_new_connection(void)
{
	static int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *conn;
	int rc;

	/* accept new connection */
	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd < 0, "accept");

	dlog(LOG_ERR, "Accepted connection from: %s:%d\n",
		inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	/* instantiate new connection handler */
	conn = connection_create(sockfd);

	/* add socket to epoll */
	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);
	DIE(rc < 0, "w_epoll_add_in");
}

/*
 * Send message on socket.
 * Store message in send_buffer in struct connection.
 */

static off_t get_file_size(int fd)
{
	struct stat sb;
	int ret = fstat(fd, &sb);
	DIE(ret == -1, "fstat");
	return sb.st_size;
}

static void send_message(struct connection *conn)
{
	ssize_t bytes_sent;
	int rc;

	if (conn->state == STATE_RECEIVED_REQUEST) {
		char open_buf[BUFSIZ];
		snprintf(open_buf, BUFSIZ, "%s%.*s", dirname(AWS_DOCUMENT_ROOT),
				 (int) conn->path_buffer.len, conn->path_buffer.buf);
		conn->filefd = open(open_buf, O_RDONLY);
		char *cwd = getcwd(NULL, 0);
		dlog(LOG_INFO, "cwd: %s\n", cwd);
		free(cwd);
		if (conn->filefd < 0) {
			ERR("open");
			dlog(LOG_ERR, "open: %s\n", open_buf);
			rc = snprintf(conn->send_buffer.data, BUFSIZ,
						  "HTTP/1.0 404 Not found\r\n\r\n");
			if (rc < 0) {
				ERR("snprintf");
				goto remove_connection;
			}
			conn->send_buffer.length = (size_t) rc;
			conn->state = STATE_SENDING_ERROR_HEADERS;
		} else {
			conn->file_size = (size_t) get_file_size(conn->filefd);
			conn->file_offset = 0;
			rc = snprintf(conn->send_buffer.data, BUFSIZ, "HTTP/1.0 200 OK\r\n"
					"Content-Length: %zu\r\n"
					"Connection: close\r\n"
					"\r\n", conn->file_size);
			if (rc < 0) {
				ERR("snprintf");
				goto remove_connection;
			}
			conn->send_buffer.length = (size_t) rc;
			conn->state = STATE_SENDING_HEADERS;
		}
		dlog(LOG_INFO, "Preparing to send headers\n");
	}

	if (conn->state == STATE_SENDING_ERROR_HEADERS) {
		bytes_sent = send(conn->sockfd,
						  conn->send_buffer.data + conn->send_buffer.offset,
						  conn->send_buffer.length - conn->send_buffer.offset, 0);
		dlog(LOG_INFO, "Sent %ld error headers bytes\n", bytes_sent);
		if (bytes_sent <= 0) {
			goto remove_connection;
		}
		conn->send_buffer.offset += bytes_sent;
		if (conn->send_buffer.offset == conn->send_buffer.length) {
			conn->state = STATE_SENT_FILE;
			dlog(LOG_INFO, "Sent all file bytes\n");
			rc = w_epoll_update_ptr_in(epollfd, conn->sockfd, conn);
			DIE(rc < 0, "w_epoll_update_ptr_in");
			return;
		}
	}

	if (conn->state == STATE_SENDING_HEADERS) {
		bytes_sent = send(conn->sockfd,
						  conn->send_buffer.data + conn->send_buffer.offset,
						  conn->send_buffer.length - conn->send_buffer.offset, 0);
		dlog(LOG_INFO, "Sent %ld headers bytes\n", bytes_sent);
		if (bytes_sent <= 0) {
			goto remove_connection;
		}
		conn->send_buffer.offset += bytes_sent;
		if (conn->send_buffer.offset == conn->send_buffer.length) {
			conn->state = STATE_SENDING_FILE;
			return;
		}
	}

	if (conn->state == STATE_SENDING_FILE) {
		bytes_sent = sendfile(conn->sockfd, conn->filefd, NULL, BUFSIZ);
		dlog(LOG_INFO, "Sent %ld file bytes from %zu\n", bytes_sent,
			 conn->file_offset);
		if (bytes_sent < 0) {
			ERR("sendfile");
			goto remove_connection;
		}
		conn->file_offset += bytes_sent;
		if (conn->file_offset == conn->file_size) {
			conn->state = STATE_SENT_FILE;
			dlog(LOG_INFO, "Sent all file bytes\n");
			rc = w_epoll_update_ptr_in(epollfd, conn->sockfd, conn);
			DIE(rc < 0, "w_epoll_update_ptr_in");
		}
	}

	return;

remove_connection:
	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_remove_ptr");

	/* remove current connection */
	connection_remove(conn);
}

static void handle_receiving_request(struct connection *conn)
{
	ssize_t ret;

	while (1) {
		ret = recv(conn->sockfd, conn->recv_buffer.data + conn->recv_buffer.offset,
				   BUFSIZ - conn->recv_buffer.offset, MSG_DONTWAIT);
		dlog(LOG_INFO, "Received %ld\n", ret);
		dlog(LOG_INFO, "Buffer content:\n--\n%s\n--\n", conn->recv_buffer.data);
		if (ret == -1 && errno == EWOULDBLOCK) {
			break;
		}
		DIE(ret == -1, "recv");
		if (ret == 0) {
			dlog(LOG_INFO, "Closed connection\n");
			ret = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
			DIE(ret < 0, "w_epoll_remove_ptr");

			/* remove current connection */
			connection_remove(conn);
			return;
		}
		size_t num_parsed_bytes = http_parser_execute(&conn->request_parser,
													  &settings_on_path,
													  conn->recv_buffer.data + conn->recv_buffer.offset,
													  (size_t) ret);
		dlog(LOG_INFO, "Parsed %zu bytes\n", num_parsed_bytes);
		conn->recv_buffer.offset += ret;
	}

	if (conn->state == STATE_RECEIVED_REQUEST) {
		dlog(LOG_INFO, "Received all request bytes.\n");
		ret = w_epoll_update_ptr_inout(epollfd, conn->sockfd, conn);
		DIE(ret < 0, "w_epoll_add_ptr_inout");
	}
}

int main(void)
{
	int rc;

	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	dlog(LOG_INFO, "Server waiting for connections on port %d\n",
		AWS_LISTEN_PORT);

	while (1) {
		struct epoll_event rev;

		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc < 0, "w_epoll_wait_infinite");

		if (rev.data.fd == listenfd) {
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			if (rev.events & EPOLLIN) {
				handle_receiving_request(rev.data.ptr);
			}
			if (rev.events & EPOLLOUT) {
				send_message(rev.data.ptr);
			}
		}
	}
}

Executable           	= /bin/echo
Arguments            	= "'OK running with id ' $$(cluster).$$(process)"
Universe             	= scheduler
log                  	= job_dagman_done_use_default_node_log.log
Notification         	= NEVER
getenv               	= true
output               	= job_dagman_dont_use_default_node_log.out
error                	= job_dagman_dont_use_default_node_log.err
Queue


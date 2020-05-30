# nginx_modules
A repository of useful nginx modules

Now, this repository has these modules below:

- Upstream dynamic update module
- Upstream health check module



### Copyright Notice

Some or all of these modules may be forked from other repositories.

I kept their License or copyright information and readme, and added my own License.

If someone want to build up new branch version, please keep these Licenses or copyright information.



### Introduction

- ngx_http_dyups_module is the upstream dynamic update module, forked from https://github.com/yzprofile/ngx_http_dyups_module
- ngx_http_upstream_check_module is the upstream health check module, forked from https://github.com/jackjiongyin/ngx_http_upstream_check_module

Their modules are very perfectly resolved their own job, but unfortunately, they can not work together.

So I modified a lot, made them working together and added new features and discarded some features.



### Installation

Modules are pure nginx module, so just add them in *configure*.

**Notice**: ngx_http_dyups_module and ngx_http_upstream_check_module must be added simultaneously.

```shell
$ cd path-of-nginx
$ git clone https://github.com/Water-Melon/nginx_modules.git
$ ./configure --add-modules=nginx_modules/ngx_http_dyups_module --add-modules=nginx_modules/ngx_http_upstream_check_module ...
$ make && make install
```



### Usage

I kept these modules readme (if they had), but some of their features I discarded and added some new features. So please ignore their readme.

#### 1. ngx_http_dyups_module

I discarded source files about Lua, so this module do not support Lua now.

##### Directives

- **dyups_interface**

  This directive must be set in location, then that location will become the entry API for operating dynamic upstreams.

- **dyups_shm_zone_size**

  This module will use share-memory, this directive will be used to set memory size.

- **dyups_file_path**

  This module will store all dynamic upstreams in file once API called. This directive indicates the file path.

  You also can include this file in nginx configuration file.

##### Variables

This module provides two prefix variables. Their value is upstream's name.

- **dyups_**

  If using this prefix variable, the rest part of variable name will be a variable name to find its value.

  e.g.

  ```nginx
  $dyups_host
  ```

  Its value is equal to the value of variable $host.

- **\_dyups_**

  If using this prefix variable, the rest part of variable name will be this variable's value.

  e.g.

  ```nginx
  $_dyups_aaa
  ```

  Its value is 'aaa'.

##### Configuration

```nginx
daemon off;
error_log logs/error.log debug;
events {
  worker_connections  1024
}
http {
  	include /tmp/aaa; #include upstreams file
  	dyups_file_path "/tmp/aaa"; #write all dynamic upstreams in file '/tmp/aaa'
    server {
        listen       8081;
        location / {
            dyups_interface; #API for operating dynamic upstreams
        }
    }
    server {
        listen       80;
        server_name  www.asdfghjkl.com;
				location / {
            proxy_pass http://$_dyups_aaa; #_dyups_ prefix variable, its value is 'aaa'
        }
    }
  	server {
        listen       80;
        server_name  127.0.0.1;
				location / {
            proxy_pass http://$_dyups_dyhosts; #_dyups_ prefix variable, its value is 'dyhosts'
        }
  	}
  	server {
        listen       8070;
        server_name  127.0.0.1;
				location / {
            proxy_pass http://$dyups_host; #dyups_ prefix variable, its value is equal to variable $host
        }
    }
    server { #upstream server 8080
        listen       8080;
        server_name  127.0.0.1;
        location / {
            return 200 "80";
        }
    }
    server { #upstream server 8090
        listen       8090;
        server_name  127.0.0.1;
        location / {
            return 200 "90";
        }
    }
}
```

##### APIs

```shell
#add a new upstream named 'dyhosts' with two servers.
$ curl -d "server 127.0.0.1:8080;server 127.0.0.1:8090;" 127.0.0.1:8081/upstream/dyhosts

#check current dynamic upstreams in the running nginx.
$ curl 127.0.0.1:8081/list

#delete an upstream
curl -i -X DELETE 127.0.0.1:8081/upstream/dyhosts

#remove a server from an existent upstream
curl "http://127.0.0.1:8081/remove?up=dyhosts&server=127.0.0.1:8080"

#add a server in an existent upstream
curl "http://127.0.0.1:8081/add?up=dyhosts&server=127.0.0.1:8080&max_fails=10"

#update a server in an existent upstream, set it down
curl "http://127.0.0.1:8081/update?up=dyhosts&server=127.0.0.1:8080&max_fails=10&down=1"

#visit upstream server
curl "http://127.0.0.1/"
#or
curl -H "Host: dyhosts" "http://127.0.0.1:8070/"
```



#### 2. Ngx_http_upstream_check_module

I discarded HTTP check, so this module is a TCP level health check module now.

##### Directives

- **health_check**

  This directive must be set in upstream zone. If it is set, then the upstream's health check is actived.

- **health_check_shm_size**

  This module will use share-memory, so this directive indicates memory size.

##### Configuration

```nginx
upstream test {
	server 127.0.0.1:1234; #1234 is not listening
	server 127.0.0.1:8080; #8080 is listening
	health_check type=tcp interval=3000 fail=5 rise=1;
  #type must be tcp
  #interval's value is millisecond
  #fail means max failed times. Greater than that, server will be set down
  #rise means min succeed times. Greater than that, server will be set up
}
```



### Example

Now given a comprehensive example.

#### Configuration

```nginx
user root;
daemon off;
worker_processes  10;

events {
    worker_connections  1024000;
}


http {
    include       /tmp/aaa; #include upstreams file
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;
    dyups_file_path "/tmp/aaa";#write all dynamic upstreams in file '/tmp/aaa'
    health_check_shm_size 20M; #health check share-memory size

    upstream test { # a static upstream with health check
        server 127.0.0.1:1234;
        server 127.0.0.1:8080;
        health_check type=tcp interval=3000 fail=5 rise=1;
    }
    server {
        listen       8081;
        location / {
            dyups_interface; # dyups api
        }
    }
    server {
        listen       8083;
        location / {
            proxy_pass http://test;
        }
    }
    server {
        listen       80;
        server_name  www.asdfghjkl.com;
        location / {
            proxy_pass http://$_dyups_aaa; #_dyups_ prefix variable, its value is 'aaa'
        }
    }
    server {
        listen       80;
        server_name  127.0.0.1;
        location / {
            proxy_pass http://$_dyups_dyhosts;  #_dyups_ prefix variable, its value is 'dyhosts'
        }
    }

    server { #upstream server 8080
        listen       8080;
        server_name  127.0.0.1;
        location / {
            return 200 "80";
        }
    }
    server { #upstream server 8090
        listen       8090;
        server_name  127.0.0.1;
        location / {
            return 200 "90";
        }
    }
}
```

#### Commands

```shell
# command to start nginx

#add a new upstream named 'dyhosts' with two servers and health check. but 1234 is not listening
$ curl -d "server 127.0.0.1:1234;server 127.0.0.1:8090;health_check type=tcp interval=3000 fail=5 rise=1;"  "http://127.0.0.1:8081/upstream/dyhosts"

#check current dynamic upstreams in the running nginx. You can see 'down' is set after server 1234 automatically.
$ curl "http://127.0.0.1:8081/list"

#remove server 1234 from an existent upstream
curl "http://127.0.0.1:8081/remove?up=dyhosts&server=127.0.0.1:1234"

#add server 8080 in an existent upstream
curl "http://127.0.0.1:8081/add?up=dyhosts&server=127.0.0.1:8080&max_fails=10"

#update server 8080 and set it down
curl "http://127.0.0.1:8081/update?up=dyhosts&server=127.0.0.1:8080&max_fails=10&down=1"

#visit upstream server, only 8090 will be visited
curl "http://127.0.0.1/"

#delete an upstream
curl -i -X DELETE 127.0.0.1:8081/upstream/dyhosts
```


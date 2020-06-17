# nginx_modules
A repository of useful nginx modules

Now, this repository has these modules below:

- Upstream dynamic update module
- Upstream health check module
- http broadcast module
- http traffic control module (alias: rebalance)
- a new load balance algorithm module
- Location dynamic update module



### Copyright Notice

Some or all of these modules may be forked from other repositories.

I kept their License or copyright information and readme, and added my own License.

If someone want to build up new branch version, please keep these Licenses or copyright information.



### Introduction

- ngx_http_dyups_module is the upstream dynamic update module, forked from https://github.com/yzprofile/ngx_http_dyups_module
- ngx_http_upstream_check_module is the upstream health check module, forked from https://github.com/jackjiongyin/ngx_http_upstream_check_module
- ngx_http_broadcast_module is a module to send every http flow to the every server in a specified upstream.
- ngx_upstream_netrb_module is a traffic flow control tool. It has two functionalities:
  1.  Leading traffic flow to the specified servers.
  2. Splitting input traffic by some rules in a certain percentage.
- ngx_upstream_chash_module is a load balance algorithm module that allowed user to proxy http flows to a specified upstream server by a self defined rule.
- ngx_http_dyloc_module is used to create or remove location dynamically without any reload.

Their modules are very perfectly resolved their own job, but unfortunately, they can not work together.

So I modified a lot, made them working together and added new features and discarded some features.



### Installation

Modules are pure nginx module, so just add them in *configure*.

**Notice**:

1. ngx_http_dyups_module and ngx_http_upstream_check_module must be added simultaneously.
2. If you want to add ngx_http_broadcast_module, ngx_http_dyups_module must be added simultaneously.

```shell
$ cd path-of-nginx
$ git clone https://github.com/Water-Melon/nginx_modules.git
$ ./configure --add-modules=nginx_modules/ngx_http_dyups_module \
              --add-modules=nginx_modules/ngx_http_upstream_check_module \
              --add-module=nginx_modules/ngx_http_broadcast_module \
              --add-module=ngx_upstream_netrb_module \
              --add-module=ngx_upstream_chash_module \
              --add-module=ngx_http_dyloc_module \
              ...
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



#### 2. ngx_http_upstream_check_module

I discarded HTTP check, so this module is a TCP level health check module now.

##### Directives

- **health_check**

  This directive must be set in upstream block. If it is set, then the upstream's health check is actived.

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



#### 3. ngx_http_broadcast_module

##### Directives

- **broadcast**

  This directive can be set in location, if and limit_except block to indicate this part of traffic flows should be broadcasted.

  Directive has one parameter to indicate upstream name. This parameter will be treated as variable name that will be searched in nginx variables.

##### Variables

- **broadcast_host**

  The value of this variable is the upstream name that set by directive **broadcast**.

##### Configuration

```nginx
user root;
daemon off;
worker_processes  6;
events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;

    keepalive_timeout  65;

    upstream test {
        server 127.0.0.1:1234;
        server 127.0.0.1:8080;
    }
    server {
        listen       80;
        server_name  127.0.0.1;
			  location / {
            broadcast _dyups_dyhosts; #_dyups_dyhosts is ngx_http_dyups_module's prefix variable. You don't have to use $ at the beginning of the name.
            proxy_pass http://$broadcast_host;
        }
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
```

##### Broadcast

Just visit the location which set broadcast and see your upstream servers' access log.



#### 4.ngx_upstream_netrb_module

This module has two functionalities:

1.  Leading traffic flows to the specified servers.
2. Splitting input traffic by some rules in a certain percentage.

There is only one functionality activated.

##### Directives

- **net_topology**

  This is a block directive located in http block.

  Format:

  ```
  net_topology name [default] {
      default|CIDR address		alias_name;
      ...
  }
  ```

  There are two *default* here. They are both optional.

  The first one indicates that this topology is a default one. If no topology set default, the first topology will be default.

  The second one just like a default route. If no CIDR rules matched, default alias will be given.

  We can set different network segments with alias in this block.

  *alias*' format: /aaa/bbb/ccc/.../nnn，divided by /.

- **rebalance**

  This directive should be set in upstream block. It has only one parameter.

  **Format**

  ```nginx
  upstream foo {
     ...;
     rebalance name;
  }
  ```

  If *name* is off, then rebalance not work. Otherwise it works.

  This directive has steps blow:

  1. Finding topology by *name*.
  2. Getting host's IP(s) (ignore loopback and 0.0.0.0).
  3. Trying to match host 's IP(s) in topology's CIDR rules and get the first matched CIDR rule.
  4. Using the CIDR rule fetched from step 3 to match all servers' IP in the upstream block. Mismatched one will be set backup.

- **assign**

  This directive is used to split traffic flows specified by a rule in some percentage parts those specified by some rules.

  **Format**

  ```nginx
  upstream foo {
     ...;
     assign rule1 rule2=1% rule3=2% ... rulen;
  }
  ```
  

  This directive should be set in upstream block. It has at least two parameters.

  *rule1* is used to make sure which http traffic flows can be the input flow.

  The input flow will be split in a centain percentage defined by the rest rules. The last rule's percentage can be omitted.
  
  Let's see the configuration shown below.

##### Configuration

```nginx
user root;
daemon off;
worker_processes  10;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    server {
        listen       80;
        location / {
            proxy_pass http://test;
        }
    }
    net_topology mynet {
        10.0.0.0/24 /bbb/test; #set network segment 10.0.0.0/24 with alias "/bbb/test"
        127.0.0.0/24 /aaa/test; #set network segment 127.0.0.0/24 with alias "/aaa/test"
    }
    upstream test {
        server 10.160.87.162:8080;
        server 10.160.87.162:8090;
        server 127.0.0.1:8100;
        rebalance mynet; #topology mynet activated. directive assign is set, so 127.0.0.1:8100 will not be set as a backup.
        assign test /bbb/test=10% /aaa/test; #"test" is the rule1. It is the suffix of those two CIDR's alias.
        #/bbb/test is the rule2, it will get 10% input flows.
        #/aaa/test is the last rule, it will get 90% input flows.
    }
    server {
        listen       8100;
        server_name  127.0.0.1;

        location / {
            return 200 "8100";
        }
    }
    server {
        listen       8080;
        server_name  10.0.0.1;

        location / {
            return 200 "1080";
        }
    }
    server {
        listen       8090;
        server_name  10.0.0.1;

        location / {
            return 200 "1090";
        }
    }
}
```



#### 5.ngx_upstream_chash_module

##### Directives

- **chash**

  This directive defines a rule based on nginx variable. Which means user can proxy a http request to a specified upstream server depending on the variable value indicated by this directive.

  This directive should be in upstream block. It has one or two parameters.

  Format:

  ```
  upstream foo {
    ...;
    chash rule [dups=n];
  }
  ```

  *rule* is the variable name like *$remote_addr*, *$cookie_user*, etc.

  *dups* is the number of virtual nodes in consistency hash.

##### Variables

- **chash_uuid**

  This variable is an string uuid generated while request processing.

  You can use this variable with *add-header set-cookie* to set cookie for every client. Then use directive *chash* to rule proxy path.

##### Configuration

```nginx
user root;
daemon off;
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    net_topology mynet {  #ngx_upstream_netrb_module directive to define a topology.
        10.0.0.0/24 /bbb/test; #10.0.0.0/24 is a remote network segment.
        127.0.0.0/24 /aaa/test;
    }
    upstream test {
        server 10.0.0.1:8080;
        server 10.0.0.162:8090;
        server 127.0.0.1:8080;
        rebalance mynet; #rebalance activated.
        assign test /bbb/test=10% /aaa/test;
        health_check type=tcp interval=1000 fail=5 rise=1; #health check activated
        chash "${arg_q}"; #chash activated. rule relies on argument q in URL.
    }
    server {
        listen       80;
        server_name  127.0.0.1;
        location / {
            proxy_pass http://test;
        }
    }
    server {
        listen       8080;
        server_name  127.0.0.1;
        location / {
            return 200 "12780";
        }
    }
}
```



#### 6.ngx_http_dyloc_module

This module do not support nonane location, nesting location and limit_except.

Using this module, memory **leak** will be happened, but just a little.

##### Directives

- **dyloc_interface**

  This directive is set in a location which will be used as a control URI.

- **dyloc_shm_size**

  This directive indicates the shared-memory size that module used.

  Its context is *MAIN* which means *http* block.

- **dyloc_dir_path**

  This directive indicates a directory path that store files those record all dynamic locations.

  Its context is *MAIN* which means *http* block.

##### Variables

- **dyloc_sync**

  This variable can not be read, because its *get_handler* is NULL.

  This variable will be used to synchronize dynamic locations among worker processes.

  **Suggestion**: This variable is set in *server* block better than in *location*.

##### Configuration

```nginx
user root;
daemon off;
worker_processes  3;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    dyloc_dir_path "/tmp"; #all dynamic locations will be write in /tmp.
                           #but different server has different file.
                           #file name's format is: server_name_port
                           #e.g. /tmp/127.0.0.1_80
    dyloc_shm_size 30M; #set shm size, it's an optional directive, default is 10M.

    server {
        set $dyloc_sync 1; #set variable, value can be anything but will not be used.
        listen       8080;
        server_name  127.0.0.1;
        location / {
            dyloc_interface; #control interface.
        }
    }
    server {
        listen       80;
        server_name  127.0.0.1;
        set $dyloc_sync 1; #set variable for sync
    }
}
```

##### APIs

```shell
#add a location
$ curl -XPOST -d "location = /foo {return 503;}" "http://127.0.0.1:8080/add?server_name=127.0.0.1&port=80"
#del a location
$ curl -XPOST -d "location = /foo {return 503;}" "http://127.0.0.1:8080/del?server_name=127.0.0.1&port=80"
#add a regex location
$ curl -XPOST -d "location ~ \.php$ {return 200;}" "http://127.0.0.1:8080/add?server_name=127.0.0.1&port=80"
#add a named location
$ curl -XPOST -d "location @test {return 403;}" "http://127.0.0.1:8080/add?server_name=127.0.0.1&port=80"
#of course, cooperate with dynamic upstream will be more flexible.
$ curl -XPOST -d "location /foo {proxy_pass http://$_dyups_uptest;}" "http://127.0.0.1:8080/add?server_name=127.0.0.1&port=80"
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


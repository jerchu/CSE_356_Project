events { }

http {
    upstream myapp1 {
        server 64.52.163.95;
		server 64.52.163.190;
    }

    server {
        listen 80;

        location / {
            proxy_pass http://myapp1;
        }
    }
}
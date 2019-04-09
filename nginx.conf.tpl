http {
    upstream myapp1 {
        server 64.52.23.65;
		server 64.52.23.172;
    }

    server {
        listen 80;

        location / {
            proxy_pass http://myapp1;
        }
    }
}
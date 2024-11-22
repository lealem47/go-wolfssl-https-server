# go-wolfssl-https-server

This HTTPS server will accept a TLS 1.2 connection, then send some random data to the client connects, then wait for another connection.

To run this example, first install wolfSSL.
```
git clone https://github.com/wolfSSL/wolfssl
./autogen.sh
./configure
make
sudo make install
``` 

Then install the go-wolfssl module with:
```
go get -u github.com/wolfssl/go-wolfssl 
```

To run the server, use the command below.
```
go run cmd/rest/main.go
```


The server will run on port 8443. You can use the following curl command to act as the client.
```
curl https://localhost:8443/\?size\=50000 -k
```

You can change the number of bytes to recieve by editing the curl command.
```
curl https://localhost:8443/\?size\=100000 -k
```


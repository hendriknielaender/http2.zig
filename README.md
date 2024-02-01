<h1 align="center">
   <img src="logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>


## Generate `server.key` and `server.crt`

```bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

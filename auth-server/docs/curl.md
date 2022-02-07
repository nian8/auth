```shell
http://localhost:8080/oauth2/authorize?client_id=yee&response_type=code&redirect_uri=https://www.baidu.com&scope=user.userInfo user.photos

# U22uKRrF5cW1dy4lX3IOLCKkTWROhegtYF-pIhATU-_wPhPrGNxIvvmDxPXNESf1GDk2BB4oz3iiNTgJ1-wCL0pr3F_tUbRxUP0r3Zl86RuRvAKa888qW7U0Bf2Ptlly
```

```shell
curl -i -X POST \
-H "Authorization:Basic eXVuMTIzNDU2" \
'http://localhost:8080/oauth2/token?grant_type=authorization_code&code=U22uKRrF5cW1dy4lX3IOLCKkTWROhegtYF-pIhATU-_wPhPrGNxIvvmDxPXNESf1GDk2BB4oz3iiNTgJ1-wCL0pr3F_tUbRxUP0r3Zl86RuRvAKa888qW7U0Bf2Ptlly&redirect_uri=https%3A%2F%2Fwww.baidu.com'
```
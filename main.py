from PyP100 import PyP110

p110 = PyP110.P110("192.168.X.X", "email", "pass")

p110.handshake()
p110.login()

#p110.turnOff()

p110.turnOn()

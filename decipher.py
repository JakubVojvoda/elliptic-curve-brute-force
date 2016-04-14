#
# Example of brute-force attack on elliptic curve
# by Jakub Vojvoda [vojvoda@swdeveloper.sk]
# 2016
#

import sys
import math

## The class Point encapsulates 2D point
class Point:
  # Creates object and initializes the x and y coordinate
  def __init__(self, x, y):
    self.x, self.y = x, y
  
  # The method determines whether two points
  # are equal (returns True) or not (False)
  def equals(self, p):
    return (self.x == p.x and self.y == p.y)  

  
## The class ECurve defines an elliptic curve 
## over finite field
class ECurve:
  # Creates an elliptic curve defined by equation
  # y^2 = x^3 + ax + b mod p
  def __init__(self, a, b, p):
    self.a, self.b, self.p = a, b, p
  
  # The method checks if the point is a valid point
  # and satisfies 4a^3 + 27b^2 != 0  
  def check(self, p):
    l = self.mod(p.y * p.y)
    r = self.mod(p.x * p.x * p.x + self.a * p.x + self.b)
    c = 4 * self.a*self.a*self.a  + 27 * self.b*self.b    
    return l == r and c != 0      
        
  # The method implements a modulo operation    
  def mod(self, x):
    return x % self.p
  
  # Implements a modular multiplicative inverse 
  # using extended Euclidean algorithm
  def invmod(self, x):    
    s0, s1 = 0, 1
    r0, r1 = self.p, x
    
    while r0 != 0:
      q = r1 // r0
      r1, r0 = r0, r1 - q * r0
      s1, s0 = s0, s1 - q * s0
      
    return s1 % self.p                                                         
  
  # Implements point addition P + Q  
  def add(self, p, q):
    r = Point(0, 0)      
    
    if p.equals(r): return q
    if q.equals(r): return p           
    
    # if P = Q     
    if p.equals(q):      
      if p.y != 0:
        l = self.mod(self.mod(3*p.x*p.x + self.a) * self.invmod(2*p.y))
        r.x = self.mod(l*l - 2*p.x)
        r.y = self.mod(l*(p.x - r.x) - p.y)
    
    # if P != Q
    else:
      if q.x - p.x != 0:
        l = self.mod(self.mod(q.y - p.y) * self.invmod(q.x - p.x))
        r.x = self.mod(l*l - p.x - q.x)   
        r.y = self.mod(l*(p.x - r.x) - p.y)     
      
    return r
  
  # The method implements point doubling 2P
  def double(self, p):
    return self.add(p, p)
      
  # Implements modular multiplication nP using recursive 
  # variant of the double-and-add method
  def multiply(self, p, n):  
    if n == 0:
      return Point(0, 0)
    elif n == 1:
      return p
    elif n % 2 == 1:
      return self.add(p, self.multiply(p, n-1))
    else:
      return self.multiply(self.double(p), n/2)

    
## The class Decipher defines a solver for ECDL problem   
class Decipher:
  # Creates object and initializes curve, base point,
  # public key and order
  def __init__(self, curve, p, q, n):
    self.curve, self.p, self.q, self.n = curve, p, q, n
  
  # The method implements a brute-force attack
  # on elliptic curve over finite field
  def run(self):
    r = Point(0, 0)
    
    # compute Q = dP and return d
    for d in range(1, self.n):
      r = self.curve.add(self.p, r)
      
      if not self.curve.check(r): return 0                      
      if r.equals(self.q): return d  
    
    return 0


## The main method          
def main(argv=None):
  
  # parameters of elliptic curve y^2 = x^3 + ax + b  
  a = -0x3
  b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
  p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
  
  # base point 
  P = Point(
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
  )
  
  # public key  
  Q = Point(
    0x52910a011565810be90d03a299cb55851bab33236b7459b21db82b9f5c1874fe, 
    0xe3d03339f660528d511c2b1865bcdfd105490ffc4c597233dd2b2504ca42a562
  )
  
  # elliptic curve over Fp
  curve = ECurve(a, b, p)
  
  # check if qiven points are on defined elliptic curve
  if not curve.check(P) or not curve.check(Q):
    return 0  
  
  # compute ECDLP  
  decip = Decipher(curve, P, Q, p)
  return decip.run()    


if __name__ == "__main__":
  value = main()
  print(value)
     
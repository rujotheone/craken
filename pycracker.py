#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Brute Force for encrypted passwords
#I could reduce the code 4x times but it will slow down the code much

# I am not responsible for what you do with this application
# Yo no soy responsable de lo que haces con esta aplicación
# je ne suis pas responsable de ce que vous faites avec cette application.
# USE ON YOUR OWN RISK.
# WITH NO ANY EXPRESS OR IMPLIED WARRANTIES
# EMPLOI SUR VOS PROPRES RISQUES.
# SANS AUCUNE GARANTIE EXPLICITE OU IMPLICITE

#  Copyright 2012 Arnaud Alies <mouu@hush.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

'''
Example:

[mou@mou libs]$ python brute_force.py sha1 c22b5f9178342609428d6f51b2c5af4c0bde6a42
Tested: 14055 passwords searching now with 2 chars
Found: 
hi
'''

from random import randint
from os import _exit
import hashlib
from sys import stdout, argv
from time import sleep
from atexit import register

encryptions = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

class brute_force:
	def __init__(self, mot_de_passe_a_trouver=str(), nombre_de_carateres_depart = int(1), caracteres_max=int(42)):
		'''
		Librairie de recherche de mots de passes encrypte
		Library for decrypting encrypted passwords
		
		Encryptions:
		md5, sha1, sha224, sha256, sha384, sha512
		'''
		self.ascii_debut = int(32)
		self.ascii_fin = int(126)
		self.nombre_de_mots = int()
		self.compteur = int(1)
		self.puissances = list()
		self.dernier_mot_de_passe_hashe = str()
		self.dernier_mot_de_passe = str()
		self.nombre_de_carateres = int(nombre_de_carateres_depart)
		self.mot_de_passe_a_trouver = str(mot_de_passe_a_trouver)
		while (self.compteur <= caracteres_max):
			self.puissances.append(int(((self.ascii_fin-self.ascii_debut)**(self.compteur+1))/3))
			self.compteur += 1
		self.compteur = int(1)

	def new(self):
		'''
		Creer un mot de passe possible
		Create a new random word
		'''
		self.dernier_mot_de_passe= str()
		for lettre in range(self.nombre_de_carateres):
			self.dernier_mot_de_passe = self.dernier_mot_de_passe + chr(randint(self.ascii_debut, self.ascii_fin))
		self.nombre_de_mots += 1
		return self.dernier_mot_de_passe
	
			
	def test(self):
		'''
		tester le dernier mot de passe qui doit deja etre hashe avec l option encode_...()
		test the last password which need to be already hashed before using encode_...()
		'''
		if (self.mot_de_passe_a_trouver == self.dernier_mot_de_passe_hashe):
			return bool(True)
		return bool(False)

	def encode(self, encryption):
		self.dernier_mot_de_passe_hashe = getattr(hashlib, encryption)(self.dernier_mot_de_passe).hexdigest()
		return self.dernier_mot_de_passe_hashe

def crack(hash_password, encryption):
	brute = brute_force(hash_password)
	try:
		while (True):
			if (brute.puissances[brute.nombre_de_carateres-1] == brute.nombre_de_mots):
					brute.nombre_de_carateres += 1
			brute.new()
			brute.encode(encryption)
			if (brute.test()):
				return brute.dernier_mot_de_passe
			stdout.write("\rTested: %d passwords searching now with %d chars" % (brute.nombre_de_mots, brute.nombre_de_carateres))
			stdout.flush()
	except KeyboardInterrupt:
		sleep(1)
		exit()

def quitter():
	print("\nExitted before found any correspondance")
	_exit(0)

def main():
	register(quitter)
	try:
		encryption = argv[1]
		password = argv[2]
	except IndexError:
		encryption = raw_input("Encryption\n(md5, sha1, sha224, sha256, sha384, sha512)\n: ")
		password = raw_input("Data to break: ")
	if (encryption in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
		print("\nFound: \n%s" % crack(password, encryption))
	else:
		print("\nEncryption not found")
	_exit(0)

if __name__ == "__main__":
	main()

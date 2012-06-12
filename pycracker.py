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

__doc__ = '''
PyCracker

This lib is for cracking encryptions like md5 sha...
Example:
[mou@mou libs]$ python brute_force.py sha1 c22b5f9178342609428d6f51b2c5af4c0bde6a42
Tested: 14055 passwords searching now with 2 chars
Found: 
hi
'''

__all__ = ('brute_force', 'crack', 'make_library')
encryptions = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

import hashlib
from random import randint
from os import _exit, mkdir
from sys import stdout, argv
from time import sleep
from pickle import dump, load
from atexit import register


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
			self.puissances.append(int(((self.ascii_fin-self.ascii_debut)**(self.compteur))*1.8))#you could change the 1.8 but you risk fail many words if you reduce it and if you increment it you will waste time
			self.compteur += 1
		self.compteur = int(1)
		
	def search(self, encryption):
		'''Generate one random password and returns true if found'''
		self.new()
		self.encode(encryption)
		return self.test()
	
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
		
	def generate(self, encryption, nombre_de_carateres=int()):
		'''
		could be used to make library of passwords with hash to avoid wasting time by rehashing at every crack
		example:
		>>> pycracker.brute_force().generate("md5", 5)#5 is the lenght of desired password "md5" is the encryption you want
		['D0!Zc', '807bacbbe4c2fea3723e9f1858fd484c']#return a list with generated pass and hashed generated pass
		'''
		if nombre_de_carateres:
			self.nombre_de_carateres = nombre_de_carateres
		return [self.new(), self.encode(encryption)]
	
			
	def test(self):
		'''
		tester le dernier mot de passe qui doit deja etre hashe avec l option encode_...()
		test the last password which need to be already hashed before using encode_...()
		'''
		if (self.mot_de_passe_a_trouver == self.dernier_mot_de_passe_hashe):
			return bool(True)
		return bool(False)

	def encode(self, encryption):
		'''md5, sha1, sha224, sha256, sha384, sha512'''
		self.dernier_mot_de_passe_hashe = getattr(hashlib, encryption)(self.dernier_mot_de_passe).hexdigest()
		return self.dernier_mot_de_passe_hashe
	


class brute_writer:
	def __init__(self, encryption, nombre_de_carateres_depart=int(1)):
		'''
		A tiny class to generate random passwords 
		and hash it to write it out in files using pickle
		'''
		self.brute = brute_force()
		self.encryption = encryption.lower()
		self.brute.nombre_de_caracteres = nombre_de_carateres_depart
		self.tout_mots = dict()
		self.compteur = int()
		self.last_gen = list()

	def __str__(self):
		return self.brute.nombre_de_mots

	def __del__(self):
		'''Save before any exit'''
		self.on_save()

	def on_save(self):
		'''Save the pass'''
		try:
			mkdir('library')
		except:
			print("[*] dir already created")
		file = open("library/%i%s%i.crack" % (randint(1, 10), self.encryption, self.brute.nombre_de_caracteres), "w+b")
		dump(self.tout_mots, file)
		file.close()
		self.tout_mots = dict()
		
	def make(self, encryption):
		''''''
		self.compteur += 1
		self.last_gen = self.brute.generate(encryption)
		self.tout_mots[self.last_gen[0]] = self.last_gen[1]


def make_dict(encryption, nombre_de_carateres_depart=int(1)):
	'''
	generate random passwords and hash it 
	to write it out in files using module
	'''
	m = brute_writer(encryption, nombre_de_carateres_depart)
	while (True):
		try:
			if (m.brute.puissances[m.brute.nombre_de_carateres-1] == m.brute.nombre_de_mots):
					m.brute.nombre_de_carateres += 1
			if (m.compteur >= 5000000):
				#do a backup every x times
				m.on_save()
				m.compteur = int()
				m.tout_mots = dict()
			m.make(encryption)
			stdout.write("\rGenerating: %i" % m.brute.nombre_de_mots)
			stdout.flush()
		except:
			print
			m.on_save()	

def crack(encryption, hash_password):
	'''
	>>> import pycracker
	>>> print "\n" + pycracker.crack("md5", "49f68a5c8493ec2c0bf489821c21fc3b")
	Tested: 5500 passwords searching now with 2 chars
	hi
	'''
	brute = brute_force(hash_password)
	try:
		while (True):
			if (brute.puissances[brute.nombre_de_carateres-1] == brute.nombre_de_mots):
					brute.nombre_de_carateres += 1
			if (brute.search(encryption)):
				print
				return brute.dernier_mot_de_passe
			stdout.write("\rTested: %d passwords searching now with %d chars" % (brute.nombre_de_mots, brute.nombre_de_carateres))
			stdout.flush()
	except KeyboardInterrupt:
		exit()

def quitter():
	print("\nExitted before found any correspondance")
	_exit(0)

def main():
	'''
	usage:
	[mou@mou pycracker]$ python pycracker.py sha1 c22b5f9178342609428d6f51b2c5af4c0bde6a42
	Tested: 1032 passwords searching now with 2 chars
	Found: 
	hi
	[mou@mou pycracker]$
	'''
	register(quitter)
	try:
		choix = int(argv[1].replace("-", ""))-1
		encryption = argv[2]
		password = argv[3]
	except IndexError:
		print("I also can run: python %s 'option' 'encryption' 'hashed password'\nexample: python pycracker.py %s c22b5f9178342609428d6f51b2c5af4c0bde6a42" % (argv[0], argv[0]))
		try:
			choix = input("1: Crack a password\n2: Make a dictionary of passwords\n: 1 or 2 ? ")-1
		except:
			choix = int()
		encryption = raw_input("Encryption\n(md5, sha1, sha224, sha256, sha384, sha512)\n: ")
		if not choix:
			password = raw_input("Data to break: ")
	if (encryption in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
		if choix:
			make_dict(encryption)
		else:
			print("\nFound: \n%s" % crack(encryption.lower(), password))
	else:
		print("\nEncryption not found")
	_exit(0)

if __name__ == "__main__":
	print("""
                                              ,MD5
                                            ,o
== THE CRAKEN ==                           :o
                   _....._                  `:o
                 .'       ``-.                \o
                /  _      _   \                \o
               :  /*\    /*\   )                ;o
               |  \_/    \_/   /        lulz     ;o
               (       U      /                 ;o
                \  (\_____/) /                  /o
                 \   \_m_/  (                  /o
                  \         (                ,o:
                  )          \,           .o;o'           ,o'o'o.
                ./          /\o;o,,,,,;o;o;''         _,-o,-'''-o:o.
 .sha384      ./o./)        \    'o'o'o''         _,-'o,o'         oSHA1
 o           ./o./ /       .o \.              __,-o o,o'
 \o.       ,/o /  /o/)     | o o'-..____,,-o'o o_o-'
 `o:o...-o,o-' ,o,/ |     \   'o.o_o_o_o,o--''
 .,  ``o-o'  ,.oo/   'o /\.o`.
 `o`o-....o'o,-'   /o /   \o \.                       ,o..         o
sha512`o-o.o--    /o /      \o.o--..          ,,,o-o'o.--o:o:o,,..:oSHA256
                 (oo(          `--o.o`o---o'o'o,o,-'''        o'o'o
                  \ o\              ``-o-o''''
   ,-o;osha224     \o \
  /o/               )o )
 (o(               /o / 
  \o\.       ...-o'o /
    \o`o`-o'o o,o,--'
      ```o--'''           
      """)
	main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Brute Force for encrypted passwords
#I could reduce the code 4x times but it will slow down the code much
# NEXT VERSION WITH MULTITREADING
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
CRAKEN

This lib is for cracking encryptions like md5 sha...
Example:
[mou@mou libs]$ python brute_force.py 1 sha1 c22b5f9178342609428d6f51b2c5af4c0bde6a42
Tested: 1055 passwords searching now with 2 chars
Found: 
hi
'''

__all__ = ('brute_force', 'crack', 'make_library')
encryptions = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

import hashlib
from random import randint
from os import _exit, mkdir
from sys import stdout, argv
from atexit import register
from time import sleep
from os import fsync, rename

class brute_force:
	def __init__(self, mot_de_passe_a_trouver='', nombre_de_carateres_depart = 1, caracteres_max=42):
		'''
		Librairie de recherche de mots de passes encrypte
		Library for decrypting encrypted passwords
		
		Encryptions:
		md5, sha1, sha224, sha256, sha384, sha512
		'''
		self.ascii_debut = 32
		self.ascii_fin = 126
		self.nombre_de_mots = 0
		self.compteur = 1
		self.puissances = []
		self.dernier_mot_de_passe_hashe = ''
		self.dernier_mot_de_passe = ''
		self.nombre_de_carateres = nombre_de_carateres_depart
		self.mot_de_passe_a_trouver = mot_de_passe_a_trouver

		while (self.compteur <= caracteres_max):
			self.puissances.append(int(((self.ascii_fin-self.ascii_debut)**(self.compteur))*2.5))#you could change the "2.5" but you risk fail many words if you reduce it and if you increment it you will waste time
			self.compteur += 1
		self.compteur = 1

	def __len__(self):
		return self.nombre_de_mots

	def set_char(self, nombre_de_caracteres=int()):
		'''a shortcut to change number of chars by generated words'''
		if not nombre_de_caracteres:
			self.nombre_de_carateres = nombre_de_caracteres
		return self.nombre_de_carateres

	def one_search(self, encryption):
		'''Generate one random password and returns true if found'''
		self.new()
		self.encode(encryption)
		if (self.mot_de_passe_a_trouver == self.dernier_mot_de_passe_hashe):
			return True
		return False

	def new(self):
		'''
		Creer un mot de passe possible
		Create a new random word
		'''
		self.dernier_mot_de_passe = ''
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
		self.tout_mots = []
		self.compteur = 0
	
	def __len__(self):
		return self.brute.nombre_de_mots

	def __str__(self):
		return self.brute.nombre_de_mots

	def __del__(self):
		'''Save before any exit'''
		self.on_save()

	def set_char(self, nombre_de_caracteres = 0):
		if not nombre_de_caracteres:
			self.brute.nombre_de_caracteres = nombre_de_caracteres

	def on_save(self):
		'''Save the pass'''
		try:
			mkdir('library')
		except OSError:
			print("\n[*] dir already created")
		file = open("library/dict%sc%i.crack" % (self.encryption, self.brute.nombre_de_caracteres), "a")
		file.write("\n".join(self.tout_mots))
		file.flush()
		fsync(file.fileno())
		file.close()
		self.tout_mots = []
		
	def make(self, encryption):
		''''''
		self.compteur += 1
		self.tout_mots.append("\t".join(self.brute.generate(encryption)))



def make_dict(encryption, nombre_de_carateres_depart=1, display=True):
	'''
	generate random passwords and hash it 
	to write it out in files using module
	'''
	m = brute_writer(encryption, nombre_de_carateres_depart)
	if encryption not in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
		print("Encryption not found")
		_exit(0)
	while (True):
		try:
			if (m.brute.puissances[m.brute.nombre_de_carateres-1] == m.brute.nombre_de_mots):
					m.brute.nombre_de_carateres += 1
			if (m.compteur >= 500000):
				#do a backup every x times
				m.on_save()
				m.compteur = 0
				m.tout_mots = []
			m.make(encryption)
			if display:
				stdout.write("\rGenerating: %i" % len(m))
				stdout.flush()
		except KeyboardInterrupt:
			print("\nKeyboard interrupt")
			m.on_save()
			sleep(5)

def crack(encryption, hash_password, display=True):
	'''
	return the password from a hash if found
	>>> import pycracker
	>>> print pycracker.crack("md5", "49f68a5c8493ec2c0bf489821c21fc3b")
	Tested: 3500 passwords searching now with 2 chars
	hi
	'''
	brute = brute_force(hash_password)
	if encryption not in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
		print("Encryption not found")
		_exit(0)
	try:
		while (True):
			if (brute.puissances[brute.nombre_de_carateres-1] == brute.nombre_de_mots):
					brute.nombre_de_carateres += 1
			if (brute.one_search(encryption)):
				print
				return brute.dernier_mot_de_passe
			if display:
				stdout.write("\rTested: %d passwords searching now with %d chars" % (len(brute), brute.nombre_de_carateres))
				stdout.flush()
	except KeyboardInterrupt:
		print("\nKeyboard Interrupt")
		exit()

def crack_with_dict(dict_name, to_crack):
	 try:
		  file = open(dict_name, "r")
	 except IOError:
		  print("File not found: %s" % dict_name)
		  exit()
	 for ligne in file:
		  if ligne[ligne.find("\t")+1:].replace("\n", "") == to_crack:
				return ligne[:ligne.find("\t")]
	 return ''

def crack_with_file(file_name, encryption, hash_pass):
	brute = brute_force()
	encryption = encryption.lower()
	if encryption not in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
		print("Encryption not found")
		_exit(0)
	try:
		_file = open(file_name, "r")
	except IOError:
		return ("File: %s not found" % file_name)
	_file.seek(0)
	print("Cracking...")
	for ligne in _file:
		brute.dernier_mot_de_passe = ligne.replace("\n", "")
		if brute.encode(encryption) == hash_pass:
			return ligne.replace("\n", "")
	print "Not found"

def quitter():
	print("Exitted before found any correspondance")
	_exit(0)

def main():
	'''
	usage:
	[mou@mou pycracker]$ python pycracker.py sha1 1 c22b5f9178342609428d6f51b2c5af4c0bde6a42
	Tested: 1032 passwords searching now with 2 chars
	Found: 
	hi
	[mou@mou pycracker]$
	'''
	register(quitter)
	__help__ = ('''
craken.py: basic help
Usage: python {0} [-c Crack a hash]
                  [-g generate a dict of passwords, encryption as 2nd arguement]
                  [-h display this help]
                  [-f crack a hash using plain text file
                       use -d if you used -g on the file]
                  [-d crack a hash using a dictionary file (use -g to make one)
                    no encryptions arguements needed]
Example:
	python {0} -c md5 "c268120ce3918b1264fe2c05143b5c4b"
                      or
	python {0} -f passwords.txt md5 "c268120ce3918b1264fe2c05143b5c4b"
                      or
	python {0} -d dictmd5c1.crack '61bad16b91c29a757f6b36c21a065197'
	'''.format(argv[0]))
	try:
		if (argv[1].lower() == '-c'):
			try:
				print("\nFound: %s" % crack(argv[2].lower(), argv[3]))
			except IndexError:
				print("More arguements needed\n%s" % __help__)
		elif (argv[1].lower() == '-g'):
			try:
				make_dict(argv[2].lower())
			except IndexError:
				print("More arguements needed\n%s" % __help__)
		elif (argv[1].lower() == '-f'):
			try:
				print("Found: %s" % crack_with_file(argv[2], argv[3].lower(), argv[4]))
			except IndexError:
				print(__help__)
		elif argv[1].lower() == '-d':
			 try:
				  print("Found: %s" % crack_with_dict(argv[2], argv[3]))
			 except IndexError:
				  print(__help__)
		elif (argv[1].lower() == '-h'):
			print(__help__)
		else:
			print("try: python %s -h" % argv[0])
	except IndexError:
		choix = input("1. Generate a dictionary\n2. Crack a password\n3. Crack a password using a file\n4. Crack a hash using a dictionary file\n: ")
		if (choix == 1):
			make_dict(raw_input("Encryption\nmd5, sha1, sha224, sha256, sha384, sha512\n: "))
		elif (choix == 2):
			print("Found: %s" % crack(raw_input("Encryption\nmd5, sha1, sha224, sha256, sha384, sha512\n: "), raw_input("Data to crack: ")))
		elif (choix == 3):
			print("Found: %s" % crack_with_file(raw_input("File name: "), raw_input("Encryption to crack: ").lower(), raw_input("Hash to crack: ")))
		else:
			print("Found: %s" % crack_with_dict(raw_input("File name: "), raw_input("Hash to crack: ")))
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
      ```o--''' """)
	main()
	_exit(0)

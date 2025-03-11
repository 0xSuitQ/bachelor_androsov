import tkinter as tk
from tkinter import ttk
from random import choice

window = tk.Tk()
window.geometry('600x400')
window.title('Treeview')

first_names = ['John', 'Jane', 'Alice', 'Bob', 'Charlie', 'Diana', 'Edward', 'Fiona', 'George', 'Hannah']
last_names = ['Smith', 'Doe', 'Johnson', 'Brown', 'Williams', 'Jones', 'Garcia', 'Miller', 'Davis', 'Martinez']

table = ttk.Treeview(window, columns=('first', 'last', 'email'), show='headings')
table.heading('first', text='First name')
table.heading('last', text='Surname')
table.heading('email', text='Email')
table.pack(fill='both', expand=True)

for i in range(100):
	first_name = choice(first_names)
	last_name = choice(last_names)
	email = (first_name + last_name + '@mail.com').lower()
	table.insert(parent='', index=i, values=(first_name, last_name, email))

table.insert(parent='', index=tk.END, values=('XXX', 'YYY', 'ZZZ'))

def item_select(_):
	print(table.selection())
	for i in table.selection():
		print(table.item(i)['values'])
	# table.item(table.selection())

def delete_items(_):
	for item in table.selection():
		print(f'Deleting {table.item(item)}')
		table.delete(item)

table.bind('<<TreeviewSelect>>', item_select)
table.bind('<BackSpace>', delete_items)

window.mainloop()
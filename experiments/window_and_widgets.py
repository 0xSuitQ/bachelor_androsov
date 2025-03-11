import tkinter as tk
from tkinter import ttk

def button_func():
	entry_data = entry.get()
	label['text'] = entry_data
	entry['state'] = 'disabled'

def reset_text():
	entry['state'] = 'enabled'
	label['text'] = 'Some text'


window = tk.Tk()
window.title('Window and Widgets')
window.geometry('800x500')

label = ttk.Label(window, text='This is a test')
label.pack()

text = tk.Text(window)
text.pack()

entry = ttk.Entry(window)
entry.pack()

button = ttk.Button(text='Press it', command=button_func)
button.pack()

button_2 = ttk.Button(text='Press it to enable again', command=reset_text)
button_2.pack()

window.mainloop()
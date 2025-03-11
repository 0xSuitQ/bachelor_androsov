import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

notebook = ttk.Notebook(window)

tab1 = ttk.Frame(notebook)
label1 = ttk.Label(tab1, text='Text in tab 1')
label1.pack()
button1 = ttk.Button(tab1, text='Button in tab 1')
button1.pack()

tab2 = ttk.Frame(notebook)
label2 = ttk.Label(tab2, text='Text in tab 2')
label2.pack()
button2 = ttk.Button(tab2, text='Button in tab 2')
button2.pack()

notebook.add(tab1, text='Tab 1')
notebook.add(tab2, text='Tab 2')
notebook.pack()



window.mainloop()
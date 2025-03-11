import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

label1 = tk.Label(window, text='Label 1', background='red')
label2 = tk.Label(window, text='Label 2', background='blue')
label3 = tk.Label(window, text='Last of the labels', background='green')
button = ttk.Button(window, text='Button')

label1.pack(fill='both', expand=True)
label2.pack(fill='both', expand=True, side='left')
label3.pack(fill='both', expand=True)
button.pack(fill='both', expand=True)

window.mainloop()
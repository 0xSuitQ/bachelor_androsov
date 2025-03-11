import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('600x400')

frame = ttk.Frame(window, width=200, height=200, borderwidth=10, relief=tk.GROOVE)
frame.pack_propagate(False) 
frame.pack(side='left')

label = ttk.Label(frame, text='Label in frame')
label.pack()

button = ttk.Button(frame, text='Button in frame')
button.pack()

label2 = ttk.Label(window, text='Label outside')
label2.pack(side='left')

frame2 = ttk.Frame(window)
frame2.pack(side='right')

button2 = ttk.Button(frame2, text='Button')
button2.pack()
entry = ttk.Entry(frame2)
entry.pack()

window.mainloop()
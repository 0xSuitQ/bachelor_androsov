from tkinter import *
# from tkinter import ttk
import ttkbootstrap as ttk

# root = Tk()
# root.title('Main')

# frm = ttk.Frame(root, padding=10)
# frm.grid()
# ttk.Label(frm, text="Hello World!").grid(column=0, row=0)
# ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=0)

# root.mainloop()

def convert():
	try:
		mile_input = entry_int.get()
		km_output = mile_input * 1.61
	except Exception as e:
		km_output = 0.0
	output_string.set(km_output)
	

root = ttk.Window(themename='journal')
root.title('Demo')
root.geometry('300x150')

title_lable = ttk.Label(root, text= 'Miles to kilometers', font='Calibri 24 bold')
title_lable.pack()

input_frame = ttk.Frame(root)
entry_int = IntVar()
entry = ttk.Entry(input_frame, textvariable=entry_int)
button = ttk.Button(input_frame, text='Convert', command=convert)
entry.pack(side='left', padx=10)
button.pack(side='left')
input_frame.pack(pady=10)

output_string = StringVar()
output_label = ttk.Label(root, text='Output', font='Calibri 24', textvariable=output_string)
output_label.pack(pady=10)

root.mainloop()
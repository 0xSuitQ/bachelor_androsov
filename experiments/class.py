import tkinter as tk
from tkinter import ttk

class App(tk.Tk):
	def __init__(self, title='Main', x=600, y=600):
		# Main configuration
		super().__init__()
		self.title(title)
		self.geometry(f'{x}x{y}')
		self.minsize(x, y)

		# Widgets
		self.menu = Menu(self)

		# Run
		self.mainloop()

class Menu(ttk.Frame):
	def __init__(self, parent):
		super().__init__(parent)

		# Widgets
		tk.Label(self, text='test', background='red').pack(expand=True, fill='both')

		self.place(x=0, y=0, relwidth=0.3, relheight=1)

		def create_widgets(self):
			menu_button1 = ttk.Button(self, text='Button 1')
			menu_button2 = ttk.Button(self, text='Button 2')
			menu_button3 = ttk.Button(self, text='Button 3')

			menu_slider1 = ttk.Scale(self, orient='vertical')
			menu_slider2 = ttk.Scale(self, orient='vertical')

			togle_frame = ttk.Frame(self)
			menu_toggle1 = ttk.Checkbutton(togle_frame, text='check 1')
			menu_toggle2 = ttk.Checkbutton(togle_frame, text='check 2')

			entry = ttk.Entry(self)

	def create_layout(self):
		# Create a grid
		self.columnconfigure((0, 1, 2), weight=1, uniform='a')
		self.rowconfigure((0, 1, 2, 3, 4), weight=1, uniform='a')

		# Place the widgets
		

App('New', 700, 700)


import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

window = tk.Tk()
window.geometry('600x400')

scale_float = tk.DoubleVar(value='15')
scale = ttk.Scale(window, 
				  command=lambda value: progress.stop(), 
				  from_=0, 
				  to=25, 
				  orient='horizontal', 
				  length=300, 
				  variable=scale_float)
scale.pack()


progress = ttk.Progressbar(window, 
						   variable=scale_float, 
						   maximum=25, 
						   orient='horizontal',
						   mode='determinate',
						   length=200)
progress.pack()

# progress.start(1000)

scrolled_text = scrolledtext.ScrolledText(window, width=100, height=5)
scrolled_text.pack()

progress_val = tk.IntVar()
progress_exercise = ttk.Progressbar(window, orient='vertical', maximum=100, variable=progress_val)
progress_exercise.pack()
progress_exercise.start()

label = ttk.Label(window, textvariable=progress_val)
label.pack()

slider_exercise = ttk.Scale(window, from_=0, to=100, variable=progress_val)
slider_exercise.pack()

window.mainloop()
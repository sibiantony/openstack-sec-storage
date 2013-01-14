# A gnuplot script for performance plots
# The data files are located in the directory 'files'
# 	suffixed by their respective mode of launching

set xlabel 'File size (mbytes)"
set ylabel 'Time (secs)"
set time
set grid
set terminal png font "/usr/share/fonts/truetype/msttcorefonts/arial.ttf" 9
 
set title "Swift read performance, with varying file sizes"
set output 'swift_read.png'
plot 'files/perf_data.noenc' using 2:3 title "No encryption" with lines lw 3, \
	'files/perf_data.basic' using 2:3 title "Basic encryption" with lines lw 3, \
	'files/perf_data.cdb' using 2:3 title "Encryption with DB" with lines lw 3 lc rgb "orange", \
	'files/perf_data.dist' using 2:3 title "Distributed encryption" with lines lw 3 lc rgb "purple"


set title "Swift write performance, with varying file sizes"
set output 'swift_write.png'
plot 'files/perf_data.noenc' using 2:4 title "No encryption" with lines lw 3, \
	'files/perf_data.basic' using 2:4 title "Basic encryption" with lines lw 3, \
	'files/perf_data.cdb' using 2:4 title "Encryption with DB" with lines lw 3 lc rgb "orange", \
	'files/perf_data.dist' using 2:4 title "Distributed encryption" with lines lw 3 lc rgb "purple"



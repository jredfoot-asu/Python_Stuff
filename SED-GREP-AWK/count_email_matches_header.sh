input="$1"
output="$2"

awk -F ',' '$2 == $3 { count ++ } { print $1, $2, $3 }' Visser\ -\ Header\ From\ EXISTS\ -\ $input | sort | uniq -c > file2.txt

sed 's/ /,/g' file2.txt | sed 's/,,,//g' | sed 's/,,//g' > $output


echo finished
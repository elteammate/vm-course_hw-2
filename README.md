# Собрать

```shell
cmake --build /home/elt/projects/vm-course/hw-02/cmake-build-debug --target vm_course_02
```

# Запустить

```shell
./cmake-build-debug/vm_course_02 00-smoke.bc
```

# Запустить тесты

```shell
python scripts/test.py
```

# Производительность

Сравнимо, полагаю что из-за сборщика мусора похуже проигрываем.

```shell
$ time lamac -i Lama/performance/Sort.lama
________________________________________________________
Executed in  313.76 secs    fish           external
   usr time  311.73 secs   48.00 micros  311.72 secs
   sys time    2.02 secs   62.00 micros    2.02 secs

$ echo "0" | time lamac -s Lama/performance/Sort.lama
________________________________________________________
Executed in   89.75 secs    fish           external
   usr time   88.11 secs    0.00 micros   88.11 secs
   sys time    1.63 secs  149.00 micros    1.63 secs

$ lamac -b Lama/performance/Sort.lama && time ./cmake-build-debug/vm_course_02 Sort.bc
________________________________________________________
Executed in   92.33 secs    fish           external
   usr time   88.43 secs  193.00 micros   88.43 secs
   sys time    3.90 secs   97.00 micros    3.90 secs

$ lamac Lama/performance/Sort.lama && time ./Sort
________________________________________________________
Executed in   60.57 secs    fish           external
   usr time   56.91 secs  232.00 micros   56.91 secs
   sys time    3.61 secs  116.00 micros    3.61 secs
```
